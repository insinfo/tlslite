// ignore_for_file: camel_case_types, non_constant_identifier_names
// ignore_for_file: constant_identifier_names, public_member_api_docs
// ignore_for_file: unused_field, lines_longer_than_80_chars

import 'dart:async';
import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

import '../../openssl/generated/ffi.dart';
import '../../openssl/openssl_loader.dart';
import 'secure_transport.dart';
import '../socket/native_buffer_utils.dart';
import '../socket/socket_native_ffi.dart';

const int _bioCtrlPending = 10; // BIO_CTRL_PENDING
const int _defaultCiphertextChunk = 16 * 1024;
const int _sslErrorWantRead = 2;
const int _sslErrorWantWrite = 3;
const int _sslErrorZeroReturn = 6;

class SecureSocketOpenSSL implements SecureTransport {
  final RawTransport _transport;
  late final OpenSsl _openSsl;
  ffi.Pointer<ssl_ctx_st>? _ctx; // typedef SSL_CTX = ssl_ctx_st
  ffi.Pointer<ssl_st>? _ssl; // typedef SSL = ssl_st
  ffi.Pointer<BIO>? _networkReadBio;
  ffi.Pointer<BIO>? _networkWriteBio;
  bool _sslInitialized = false;
  final bool _isServer;
  final bool _ownsDataPath;
  final String? _certFile;
  final String? _keyFile;

  SecureSocketOpenSSL._({
    required RawTransport transport,
    required bool isServer,
    required bool ownsDataPath,
    String? certFile,
    String? keyFile,
    bool eagerHandshake = false,
  })  : _transport = transport,
        _isServer = isServer,
        _ownsDataPath = ownsDataPath,
        _certFile = certFile,
        _keyFile = keyFile {
    _initOpenSsl();
    if (_ownsDataPath) {
      _initializeSSL(certFile: certFile, keyFile: keyFile);
      _attachSslObject();
      if (eagerHandshake || _isServer) {
        _ensureHandshakeCompleted();
      }
    } else if (_isServer && (certFile == null || keyFile == null)) {
      throw SocketException(
          'Certificate and private key are required for the TLS listener.');
    }
  }

  /// Client-mode constructor that owns its underlying socket.
  factory SecureSocketOpenSSL(int family, int type, int protocol) =>
      SecureSocketOpenSSL._(
        transport: SocketNative(family, type, protocol),
        isServer: false,
        ownsDataPath: true,
      );

  /// Creates a TLS listener in server mode; each accept() yields a TLS session.
  factory SecureSocketOpenSSL.server(
          int family, int type, int protocol, String certFile, String keyFile) =>
      SecureSocketOpenSSL._(
        transport: SocketNative(family, type, protocol),
        isServer: true,
        ownsDataPath: false,
        certFile: certFile,
        keyFile: keyFile,
      );

  /// Wraps an already-established transport in client mode.
  factory SecureSocketOpenSSL.fromTransport(RawTransport transport) =>
      SecureSocketOpenSSL._(
        transport: transport,
        isServer: false,
        ownsDataPath: true,
      );

  /// Wraps a transport accepted by the listener in server mode.
  factory SecureSocketOpenSSL.fromServerTransport(
          RawTransport transport, String certFile, String keyFile,
          {bool eagerHandshake = true}) =>
      SecureSocketOpenSSL._(
        transport: transport,
        isServer: true,
        ownsDataPath: true,
        certFile: certFile,
        keyFile: keyFile,
        eagerHandshake: eagerHandshake,
      );

  @override
  RawTransport get innerTransport => _transport;

  @override
  bool get isHandshakeComplete => _sslInitialized;

  void _initOpenSsl() {
    _openSsl = loadLibSsl(null);
  }

  void _initializeSSL({String? certFile, String? keyFile}) {
    ffi.Pointer<SSL_METHOD> method =
        _isServer ? _openSsl.TLS_server_method() : _openSsl.TLS_client_method();
    _ctx = _openSsl.SSL_CTX_new(method);
    if (_ctx == ffi.nullptr || _ctx == null) {
      throw SocketException('Failed to create the SSL context.');
    }
    if (_isServer) {
      if (certFile == null || keyFile == null) {
        throw SocketException(
            'Certificate and private key are required in server mode.');
      }
      final certFilePtr = certFile.toNativeUtf8();
      final keyFilePtr = keyFile.toNativeUtf8();
      final ctxPtr = _ctxPtr;
      final certResult = _openSsl.SSL_CTX_use_certificate_file(
          ctxPtr, certFilePtr.cast(), 1); // 1 = SSL_FILETYPE_PEM
      final keyResult =
          _openSsl.SSL_CTX_use_PrivateKey_file(ctxPtr, keyFilePtr.cast(), 1);
      calloc.free(certFilePtr);
      calloc.free(keyFilePtr);
      if (certResult != 1) {
        throw SocketException('Failed to load the certificate file.');
      }
      if (keyResult != 1) {
        throw SocketException('Failed to load the private key file.');
      }
    }
  }

  void _attachSslObject() {
    final ctxPtr = _ctxPtr;
    _ssl = _openSsl.SSL_new(ctxPtr);
    if (_ssl == ffi.nullptr || _ssl == null) {
      throw SocketException('Failed to create the SSL instance.');
    }
    _networkReadBio = _openSsl.BIO_new(_openSsl.BIO_s_mem());
    _networkWriteBio = _openSsl.BIO_new(_openSsl.BIO_s_mem());
    if (_networkReadBio == ffi.nullptr || _networkWriteBio == ffi.nullptr) {
      throw SocketException('Failed to create the TLS transport BIOs.');
    }
    _openSsl.SSL_set_bio(_sslPtr, _networkReadBioPtr, _networkWriteBioPtr);
    if (_isServer) {
      _openSsl.SSL_set_accept_state(_sslPtr);
    } else {
      _openSsl.SSL_set_connect_state(_sslPtr);
    }
  }

  void _ensureHandshakeCompleted() {
    _assertOwnsDataPath();
    if (_sslInitialized) {
      return;
    }
    while (true) {
      final result = _openSsl.SSL_do_handshake(_sslPtr);
      _drainWriteBioSync();
      if (result == 1) {
        _sslInitialized = true;
        return;
      }
      final error = _openSsl.SSL_get_error(_sslPtr, result);
      if (error == _sslErrorWantRead) {
        final filled = _fillReadBioFromTransport();
        if (!filled) {
          throw SocketException(
              'TLS handshake aborted: the underlying transport stopped providing data.');
        }
        continue;
      }
      if (error == _sslErrorWantWrite) {
        continue;
      }
      throw SocketException(
          'TLS handshake failed (OpenSSL code $error, mode ${_isServer ? 'server' : 'client'}).');
    }
  }

  void _assertOwnsDataPath() {
    if (!_ownsDataPath) {
      throw SocketException(
          'This instance only represents the TLS listener; call accept() to obtain connections.');
    }
  }

  ffi.Pointer<ssl_ctx_st> get _ctxPtr {
    final ctx = _ctx;
    if (ctx == null || ctx == ffi.nullptr) {
      throw SocketException('SSL context is unavailable.');
    }
    return ctx;
  }

  ffi.Pointer<ssl_st> get _sslPtr {
    final ssl = _ssl;
    if (ssl == null || ssl == ffi.nullptr) {
      throw SocketException('SSL object is unavailable.');
    }
    return ssl;
  }

  @override
  SocketBlockingMode get blockingMode => _transport.blockingMode;

  @override
  bool get isClosed => _transport.isClosed;

  @override
  (String, int) get address => _transport.address;

  @override
  int get port => _transport.port;

  @override
  Duration? get timeoutDuration => _transport.timeoutDuration;

  @override
  int? get nativeHandle => _transport.nativeHandle;

  @override
  void setBlockingMode(SocketBlockingMode mode) =>
      _transport.setBlockingMode(mode);

  @override
  void settimeout(double? timeout) => _transport.settimeout(timeout);

  @override
  void setTimeout(Duration? duration) => _transport.setTimeout(duration);

  @override
  void bind(String host, int port) => _transport.bind(host, port);

  @override
  void connect(String host, int port) {
    _transport.connect(host, port);
    if (_ownsDataPath && !_isServer) {
      _ensureHandshakeCompleted();
    }
  }

  @override
  void ensureHandshakeCompleted() => _ensureHandshakeCompleted();

  @override
  void listen(int backlog) => _transport.listen(backlog);

  @override
  RawTransport accept() {
    final child = _transport.accept();
    if (!_isServer || _certFile == null || _keyFile == null) {
      return child;
    }
    final certPath = _certFile;
    final keyPath = _keyFile;
    return SecureSocketOpenSSL.fromServerTransport(child, certPath, keyPath);
  }

  @override
  int send(Uint8List data) {
    _assertOwnsDataPath();
    _ensureHandshakeCompleted();
    if (data.isEmpty) {
      return 0;
    }
    final buffer = NativeUint8Buffer.fromBytes(
      data,
      pool: NativeUint8BufferPool.global,
    );
    var written = 0;
    try {
      while (written < data.length) {
        final remaining = data.length - written;
        final ptr = buffer.slice(written).cast<ffi.Void>();
        final result = _openSsl.SSL_write(_sslPtr, ptr, remaining);
        _drainWriteBioSync();
        if (result > 0) {
          written += result;
          continue;
        }
        final error = _openSsl.SSL_get_error(_sslPtr, result);
        if (error == _sslErrorWantRead) {
          final filled = _fillReadBioFromTransport();
          if (!filled) {
            throw SocketException('SSL write failed: transport closed unexpectedly.');
          }
          continue;
        }
        if (error == _sslErrorWantWrite) {
          continue;
        }
        throw SocketException('SSL write failed (OpenSSL code $error).');
      }
    } finally {
      buffer.release();
    }
    return data.length;
  }

  @override
  void sendall(Uint8List data) {
    final sent = send(data);
    if (sent != data.length) {
      throw SocketException(
          'Connection closed before all TLS bytes were transmitted.');
    }
  }

  @override
  Uint8List recv(int bufferSize) {
    _assertOwnsDataPath();
    _ensureHandshakeCompleted();
    final buffer = NativeUint8Buffer.pooled(bufferSize);
    try {
      while (true) {
        final received =
            _openSsl.SSL_read(_sslPtr, buffer.pointer.cast(), bufferSize);
        if (received > 0) {
          return buffer.copyToDart(received);
        }
        final error = _openSsl.SSL_get_error(_sslPtr, received);
        if (error == _sslErrorWantRead) {
          final filled = _fillReadBioFromTransport(bufferSize: bufferSize);
          if (!filled) {
            return Uint8List(0);
          }
          continue;
        }
        if (error == _sslErrorWantWrite) {
          _drainWriteBioSync();
          continue;
        }
        if (error == _sslErrorZeroReturn) {
          return Uint8List(0);
        }
        throw SocketException('SSL read failed (OpenSSL code $error).');
      }
    } finally {
      buffer.release();
    }
  }

  @override
  (Uint8List, String, int) recvfrom(int bufferSize) {
    throw SocketException('recvfrom is not supported over TLS.');
  }

  @override
  int sendto(Uint8List data, String host, int port) {
    throw SocketException('sendto is not supported over TLS.');
  }

  bool _fillReadBioFromTransport({int? bufferSize}) {
    final bio = _networkReadBio;
    if (bio == null || bio == ffi.nullptr) {
      throw SocketException('TLS read BIO is unavailable.');
    }
    final chunkSize =
        (bufferSize == null || bufferSize <= 0) ? _defaultCiphertextChunk : bufferSize;
    final ciphertext = _transport.recv(chunkSize);
    if (ciphertext.isEmpty) {
      return false;
    }
    final buffer = NativeUint8Buffer.fromBytes(
      ciphertext,
      pool: NativeUint8BufferPool.global,
    );
    try {
      final written =
          _openSsl.BIO_write(bio, buffer.pointer.cast(), ciphertext.length);
      if (written <= 0) {
        throw SocketException('Failed to feed the TLS read BIO.');
      }
    } finally {
      buffer.release();
    }
    return true;
  }

  void _drainWriteBioSync() {
    final bio = _networkWriteBio;
    if (bio == null || bio == ffi.nullptr) {
      return;
    }
    while (true) {
      final pending = _openSsl.BIO_ctrl(
        bio,
        _bioCtrlPending,
        0,
        ffi.nullptr.cast<ffi.Void>(),
      );
      if (pending <= 0) {
        return;
      }
      final chunkSize = pending < _defaultCiphertextChunk
          ? pending
          : _defaultCiphertextChunk;
      final buffer = NativeUint8Buffer.pooled(
        chunkSize,
        pool: NativeUint8BufferPool.global,
      );
      try {
        final read =
            _openSsl.BIO_read(bio, buffer.pointer.cast(), chunkSize);
        if (read <= 0) {
          return;
        }
        final ciphertext = buffer.copyToDart(read);
        _transport.sendall(ciphertext);
      } finally {
        buffer.release();
      }
    }
  }

  ffi.Pointer<BIO> get _networkReadBioPtr {
    final bio = _networkReadBio;
    if (bio == null || bio == ffi.nullptr) {
      throw SocketException('TLS read BIO is unavailable.');
    }
    return bio;
  }

  ffi.Pointer<BIO> get _networkWriteBioPtr {
    final bio = _networkWriteBio;
    if (bio == null || bio == ffi.nullptr) {
      throw SocketException('TLS write BIO is unavailable.');
    }
    return bio;
  }

  @override
  bool waitForRead({Duration? timeout}) =>
      _transport.waitForRead(timeout: timeout);

  @override
  bool waitForWrite({Duration? timeout}) =>
      _transport.waitForWrite(timeout: timeout);

  @override
  void setReuseAddress(bool enabled) =>
      _transport.setReuseAddress(enabled);

  @override
  void setReusePort(bool enabled) => _transport.setReusePort(enabled);

  @override
  void setNoDelay(bool enabled) => _transport.setNoDelay(enabled);

  @override
  void shutdown([SocketShutdown how = SocketShutdown.both]) {
    if (_ownsDataPath && _ssl != null && _ssl != ffi.nullptr && _sslInitialized) {
      final result = _openSsl.SSL_shutdown(_sslPtr);
      if (result == 0) {
        // Try to complete the bidirectional close_notify when required.
        _drainWriteBioSync();
        _fillReadBioFromTransport();
        _openSsl.SSL_shutdown(_sslPtr);
      }
      _drainWriteBioSync();
      _sslInitialized = false;
    }
    _transport.shutdown(how);
  }

  @override
  void close() {
    if (_ownsDataPath) {
      final ssl = _ssl;
      if (ssl != null && ssl != ffi.nullptr) {
        _openSsl.SSL_shutdown(ssl);
        _drainWriteBioSync();
        _openSsl.SSL_free(ssl);
        _ssl = null;
        _networkReadBio = null;
        _networkWriteBio = null;
      }
      final ctx = _ctx;
      if (ctx != null && ctx != ffi.nullptr) {
        _openSsl.SSL_CTX_free(ctx);
        _ctx = null;
      }
      _sslInitialized = false;
    }
    _transport.close();
  }
}

typedef CiphertextWriter = Future<void> Function(Uint8List chunk);
typedef CiphertextReader = Future<Uint8List?> Function(int preferredLength);

/// Exposes a BIO-backed TLS engine that can be wired into async protocols such
/// as SQL Server TDS, where TLS records must be encapsulated in custom frames.
class SecureSocketOpenSSLAsync {
  SecureSocketOpenSSLAsync._({
    required bool isServer,
    String? certFile,
    String? keyFile,
    required CiphertextWriter writer,
    required CiphertextReader reader,
  })  : _isServer = isServer,
        _certFile = certFile,
        _keyFile = keyFile,
        _writeCiphertext = writer,
        _readCiphertext = reader {
    _initOpenSsl();
    _initializeSSL(certFile: certFile, keyFile: keyFile);
    _attachSslObject();
  }

  factory SecureSocketOpenSSLAsync.client({
    required CiphertextWriter writer,
    required CiphertextReader reader,
  }) =>
      SecureSocketOpenSSLAsync._(
        isServer: false,
        writer: writer,
        reader: reader,
      );

  factory SecureSocketOpenSSLAsync.server({
    required CiphertextWriter writer,
    required CiphertextReader reader,
    required String certFile,
    required String keyFile,
  }) =>
      SecureSocketOpenSSLAsync._(
        isServer: true,
        certFile: certFile,
        keyFile: keyFile,
        writer: writer,
        reader: reader,
      );

  final bool _isServer;
  final CiphertextWriter _writeCiphertext;
  final CiphertextReader _readCiphertext;
  final String? _certFile;
  final String? _keyFile;
  late final OpenSsl _openSsl;
  ffi.Pointer<ssl_ctx_st>? _ctx;
  ffi.Pointer<ssl_st>? _ssl;
  ffi.Pointer<BIO>? _networkReadBio;
  ffi.Pointer<BIO>? _networkWriteBio;
  bool _sslInitialized = false;

  bool get isHandshakeComplete => _sslInitialized;

  Future<void> ensureHandshakeCompleted() async {
    if (_sslInitialized) {
      return;
    }
    while (true) {
      final result = _openSsl.SSL_do_handshake(_sslPtr);
      await _drainWriteBioAsync();
      if (result == 1) {
        _sslInitialized = true;
        return;
      }
      final error = _openSsl.SSL_get_error(_sslPtr, result);
      if (error == _sslErrorWantRead) {
        final filled = await _fillReadBioFromCallbacks();
        if (!filled) {
            throw SocketException(
              'TLS handshake aborted: encrypted channel yielded no bytes.');
        }
        continue;
      }
      if (error == _sslErrorWantWrite) {
        continue;
      }
        throw SocketException(
          'Asynchronous TLS handshake failed (OpenSSL code $error).');
    }
  }

  Future<int> send(Uint8List data) async {
    if (data.isEmpty) {
      return 0;
    }
    await ensureHandshakeCompleted();
    final buffer = NativeUint8Buffer.fromBytes(
      data,
      pool: NativeUint8BufferPool.global,
    );
    var written = 0;
    try {
      while (written < data.length) {
        final remaining = data.length - written;
        final ptr = buffer.slice(written).cast<ffi.Void>();
        final result = _openSsl.SSL_write(_sslPtr, ptr, remaining);
        await _drainWriteBioAsync();
        if (result > 0) {
          written += result;
          continue;
        }
        final error = _openSsl.SSL_get_error(_sslPtr, result);
        if (error == _sslErrorWantRead) {
          final filled = await _fillReadBioFromCallbacks();
          if (!filled) {
            throw SocketException(
              'Encrypted channel closed while SSL_write was in progress.');
          }
          continue;
        }
        if (error == _sslErrorWantWrite) {
          continue;
        }
        throw SocketException(
          'Asynchronous SSL write failed (OpenSSL code $error).');
      }
    } finally {
      buffer.release();
    }
    return data.length;
  }

  Future<Uint8List> recv(int bufferSize) async {
    await ensureHandshakeCompleted();
    final buffer = NativeUint8Buffer.pooled(bufferSize);
    try {
      while (true) {
        final received =
            _openSsl.SSL_read(_sslPtr, buffer.pointer.cast(), bufferSize);
        if (received > 0) {
          return buffer.copyToDart(received);
        }
        final error = _openSsl.SSL_get_error(_sslPtr, received);
        if (error == _sslErrorWantRead) {
          final filled = await _fillReadBioFromCallbacks(
            preferredSize: bufferSize,
          );
          if (!filled) {
            return Uint8List(0);
          }
          continue;
        }
        if (error == _sslErrorWantWrite) {
          await _drainWriteBioAsync();
          continue;
        }
        if (error == _sslErrorZeroReturn) {
          return Uint8List(0);
        }
        throw SocketException(
            'Asynchronous SSL read failed (OpenSSL code $error).');
      }
    } finally {
      buffer.release();
    }
  }

  Future<void> shutdown() async {
    if (_ssl == null || _ssl == ffi.nullptr || !_sslInitialized) {
      return;
    }
    final result = _openSsl.SSL_shutdown(_sslPtr);
    if (result == 0) {
      await _drainWriteBioAsync();
      await _fillReadBioFromCallbacks();
      _openSsl.SSL_shutdown(_sslPtr);
    }
    await _drainWriteBioAsync();
    _sslInitialized = false;
  }

  Future<void> close() async {
    await shutdown();
    final ssl = _ssl;
    if (ssl != null && ssl != ffi.nullptr) {
      _openSsl.SSL_free(ssl);
      _ssl = null;
      _networkReadBio = null;
      _networkWriteBio = null;
    }
    final ctx = _ctx;
    if (ctx != null && ctx != ffi.nullptr) {
      _openSsl.SSL_CTX_free(ctx);
      _ctx = null;
    }
  }

  Future<bool> _fillReadBioFromCallbacks({int? preferredSize}) async {
    final bio = _networkReadBio;
    if (bio == null || bio == ffi.nullptr) {
      throw SocketException('TLS read BIO is unavailable.');
    }
    final chunkSize =
        (preferredSize == null || preferredSize <= 0)
            ? _defaultCiphertextChunk
            : preferredSize;
    final ciphertext = await _readCiphertext(chunkSize);
    if (ciphertext == null || ciphertext.isEmpty) {
      return false;
    }
    final buffer = NativeUint8Buffer.fromBytes(
      ciphertext,
      pool: NativeUint8BufferPool.global,
    );
    try {
      final written =
          _openSsl.BIO_write(bio, buffer.pointer.cast(), ciphertext.length);
      if (written <= 0) {
        throw SocketException('Failed to feed the asynchronous TLS read BIO.');
      }
    } finally {
      buffer.release();
    }
    return true;
  }

  Future<void> _drainWriteBioAsync() async {
    final bio = _networkWriteBio;
    if (bio == null || bio == ffi.nullptr) {
      return;
    }
    while (true) {
      final pending = _openSsl.BIO_ctrl(
        bio,
        _bioCtrlPending,
        0,
        ffi.nullptr.cast<ffi.Void>(),
      );
      if (pending <= 0) {
        return;
      }
      final chunkSize = pending < _defaultCiphertextChunk
          ? pending
          : _defaultCiphertextChunk;
      final buffer = NativeUint8Buffer.pooled(
        chunkSize,
        pool: NativeUint8BufferPool.global,
      );
      try {
        final read =
            _openSsl.BIO_read(bio, buffer.pointer.cast(), chunkSize);
        if (read <= 0) {
          return;
        }
        final ciphertext = buffer.copyToDart(read);
        await _writeCiphertext(ciphertext);
      } finally {
        buffer.release();
      }
    }
  }

  void _initOpenSsl() {
    _openSsl = loadLibSsl(null);
  }

  void _initializeSSL({String? certFile, String? keyFile}) {
    ffi.Pointer<SSL_METHOD> method =
        _isServer ? _openSsl.TLS_server_method() : _openSsl.TLS_client_method();
    _ctx = _openSsl.SSL_CTX_new(method);
    if (_ctx == ffi.nullptr || _ctx == null) {
      throw SocketException('Failed to create the SSL context.');
    }
    if (_isServer) {
      if (certFile == null || keyFile == null) {
        throw SocketException(
            'Certificate and private key are required in server mode.');
      }
      final certFilePtr = certFile.toNativeUtf8();
      final keyFilePtr = keyFile.toNativeUtf8();
      final ctxPtr = _ctxPtr;
      final certResult = _openSsl.SSL_CTX_use_certificate_file(
          ctxPtr, certFilePtr.cast(), 1);
      final keyResult =
          _openSsl.SSL_CTX_use_PrivateKey_file(ctxPtr, keyFilePtr.cast(), 1);
      calloc.free(certFilePtr);
      calloc.free(keyFilePtr);
      if (certResult != 1) {
        throw SocketException('Failed to load the certificate file.');
      }
      if (keyResult != 1) {
        throw SocketException('Failed to load the private key file.');
      }
    }
  }

  void _attachSslObject() {
    final ctxPtr = _ctxPtr;
    _ssl = _openSsl.SSL_new(ctxPtr);
    if (_ssl == ffi.nullptr || _ssl == null) {
      throw SocketException('Failed to create the SSL instance.');
    }
    _networkReadBio = _openSsl.BIO_new(_openSsl.BIO_s_mem());
    _networkWriteBio = _openSsl.BIO_new(_openSsl.BIO_s_mem());
    if (_networkReadBio == ffi.nullptr || _networkWriteBio == ffi.nullptr) {
      throw SocketException('Failed to create the TLS transport BIOs.');
    }
    _openSsl.SSL_set_bio(_sslPtr, _networkReadBioPtr, _networkWriteBioPtr);
    if (_isServer) {
      _openSsl.SSL_set_accept_state(_sslPtr);
    } else {
      _openSsl.SSL_set_connect_state(_sslPtr);
    }
  }

  ffi.Pointer<ssl_ctx_st> get _ctxPtr {
    final ctx = _ctx;
    if (ctx == null || ctx == ffi.nullptr) {
      throw SocketException('SSL context is unavailable.');
    }
    return ctx;
  }

  ffi.Pointer<ssl_st> get _sslPtr {
    final ssl = _ssl;
    if (ssl == null || ssl == ffi.nullptr) {
      throw SocketException('SSL object is unavailable.');
    }
    return ssl;
  }

  ffi.Pointer<BIO> get _networkReadBioPtr {
    final bio = _networkReadBio;
    if (bio == null || bio == ffi.nullptr) {
      throw SocketException('TLS read BIO is unavailable.');
    }
    return bio;
  }

  ffi.Pointer<BIO> get _networkWriteBioPtr {
    final bio = _networkWriteBio;
    if (bio == null || bio == ffi.nullptr) {
      throw SocketException('TLS write BIO is unavailable.');
    }
    return bio;
  }
}
