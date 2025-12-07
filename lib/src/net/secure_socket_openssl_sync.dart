// ignore_for_file: lines_longer_than_80_chars

import 'dart:ffi' as ffi;
import 'dart:io' as io;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

import '../net_ffi/native_buffer_utils.dart';
import '../openssl/generated/ffi.dart';
import '../openssl/openssl_loader.dart';

const int _bioCtrlPending = 10; // BIO_CTRL_PENDING
const int _defaultCiphertextChunk = 16 * 1024;
const int _sslErrorWantRead = 2;
const int _sslErrorWantWrite = 3;
const int _sslErrorZeroReturn = 6;

/// A synchronous TLS socket that reuses the OpenSSL BIO engine.
class SecureSocketOpenSSLSync {
  SecureSocketOpenSSLSync._({
    required io.RawSynchronousSocket socket,
    required bool isServer,
    String? certFile,
    String? keyFile,
    bool eagerHandshake = false,
  })  : _socket = socket,
        _isServer = isServer {
    _initOpenSsl();
    _initializeSSL(certFile: certFile, keyFile: keyFile);
    _attachSslObject();
    if (eagerHandshake || isServer) {
      ensureHandshakeCompleted();
    }
  }

  static SecureSocketOpenSSLSync connect(
    String host,
    int port, {
    bool eagerHandshake = true,
  }) {
    final socket = io.RawSynchronousSocket.connectSync(host, port);
    return SecureSocketOpenSSLSync._(
      socket: socket,
      isServer: false,
      eagerHandshake: eagerHandshake,
    );
  }

  factory SecureSocketOpenSSLSync.clientFromSocket(
    io.RawSynchronousSocket socket, {
    bool eagerHandshake = true,
  }) =>
      SecureSocketOpenSSLSync._(
        socket: socket,
        isServer: false,
        eagerHandshake: eagerHandshake,
      );

  factory SecureSocketOpenSSLSync.serverFromSocket(
    io.RawSynchronousSocket socket, {
    required String certFile,
    required String keyFile,
    bool eagerHandshake = true,
  }) =>
      SecureSocketOpenSSLSync._(
        socket: socket,
        isServer: true,
        certFile: certFile,
        keyFile: keyFile,
        eagerHandshake: eagerHandshake,
      );

  final io.RawSynchronousSocket _socket;
  final bool _isServer;
  late final OpenSsl _openSsl;
  late final OpenSsl _openSslCrypto;
  ffi.Pointer<ssl_ctx_st>? _ctx;
  ffi.Pointer<ssl_st>? _ssl;
  ffi.Pointer<BIO>? _networkReadBio;
  ffi.Pointer<BIO>? _networkWriteBio;
  bool _sslInitialized = false;
  bool _socketClosed = false;

  io.RawSynchronousSocket get socket => _socket;

  bool get isHandshakeComplete => _sslInitialized;

  void ensureHandshakeCompleted() {
    if (_sslInitialized) {
      return;
    }
    _performHandshake();
  }

  void _performHandshake() {
    while (true) {
      final result = _openSsl.SSL_do_handshake(_sslPtr);
      _drainWriteBioToSocket();
      if (result == 1) {
        _sslInitialized = true;
        return;
      }
      final error = _openSsl.SSL_get_error(_sslPtr, result);
      if (error == _sslErrorWantRead) {
        final filled = _fillReadBioFromSocket();
        if (!filled) {
          throw io.SocketException(
            'TLS handshake aborted: socket closed before completion.',
          );
        }
        continue;
      }
      if (error == _sslErrorWantWrite) {
        continue;
      }
      throw io.SocketException(
        'TLS handshake failed (OpenSSL code $error, mode ${_isServer ? 'server' : 'client'}).',
      );
    }
  }

  int send(Uint8List data) {
    if (data.isEmpty) {
      return 0;
    }
    ensureHandshakeCompleted();
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
        _drainWriteBioToSocket();
        if (result > 0) {
          written += result;
          continue;
        }
        final error = _openSsl.SSL_get_error(_sslPtr, result);
        if (error == _sslErrorWantRead) {
          final filled = _fillReadBioFromSocket();
          if (!filled) {
            throw io.SocketException(
              'Socket closed while SSL_write was waiting for data.',
            );
          }
          continue;
        }
        if (error == _sslErrorWantWrite) {
          continue;
        }
        throw io.SocketException('SSL write failed (OpenSSL code $error).');
      }
    } finally {
      buffer.release();
    }
    return data.length;
  }

  Uint8List recv(int bufferSize) {
    if (bufferSize <= 0) {
      throw ArgumentError.value(bufferSize, 'bufferSize', 'must be positive');
    }
    ensureHandshakeCompleted();
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
          final filled = _fillReadBioFromSocket(
            preferredSize: bufferSize,
          );
          if (!filled) {
            return Uint8List(0);
          }
          continue;
        }
        if (error == _sslErrorWantWrite) {
          _drainWriteBioToSocket();
          continue;
        }
        if (error == _sslErrorZeroReturn) {
          return Uint8List(0);
        }
        throw io.SocketException('SSL read failed (OpenSSL code $error).');
      }
    } finally {
      buffer.release();
    }
  }

  void shutdown() {
    if (_ssl == null || _ssl == ffi.nullptr || !_sslInitialized) {
      return;
    }
    final result = _openSsl.SSL_shutdown(_sslPtr);
    if (result == 0) {
      _drainWriteBioToSocket();
      _fillReadBioFromSocket();
      _openSsl.SSL_shutdown(_sslPtr);
    }
    _drainWriteBioToSocket();
    _sslInitialized = false;
  }

  void close() {
    shutdown();
    if (!_socketClosed) {
      _socket.closeSync();
      _socketClosed = true;
    }
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

  bool _fillReadBioFromSocket({int? preferredSize}) {
    final bio = _networkReadBio;
    if (bio == null || bio == ffi.nullptr) {
      throw io.SocketException('TLS read BIO is unavailable.');
    }
    final chunkSize = (preferredSize == null || preferredSize <= 0)
        ? _defaultCiphertextChunk
        : preferredSize;
    List<int>? ciphertext;
    try {
      ciphertext = _socket.readSync(chunkSize);
    } on io.SocketException catch (_) {
      _socketClosed = true;
      rethrow;
    }
    if (ciphertext == null || ciphertext.isEmpty) {
      _socketClosed = true;
      return false;
    }
    final bytes = ciphertext is Uint8List
        ? ciphertext
        : Uint8List.fromList(ciphertext);
    final buffer = NativeUint8Buffer.fromBytes(
      bytes,
      pool: NativeUint8BufferPool.global,
    );
    try {
      final written = _openSslCrypto.BIO_write(
        bio,
        buffer.pointer.cast(),
        bytes.length,
      );
      if (written <= 0) {
        throw io.SocketException('Failed to feed the TLS read BIO.');
      }
    } finally {
      buffer.release();
    }
    return true;
  }

  void _drainWriteBioToSocket() {
    final bio = _networkWriteBio;
    if (bio == null || bio == ffi.nullptr) {
      return;
    }
    while (true) {
      final pending = _openSslCrypto.BIO_ctrl(
        bio,
        _bioCtrlPending,
        0,
        ffi.nullptr.cast<ffi.Void>(),
      );
      if (pending <= 0) {
        break;
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
            _openSslCrypto.BIO_read(bio, buffer.pointer.cast(), chunkSize);
        if (read <= 0) {
          break;
        }
        final ciphertext = buffer.copyToDart(read);
        _socket.writeFromSync(ciphertext);
      } finally {
        buffer.release();
      }
    }
  }

  void _initOpenSsl() {
    final bindings = OpenSslBindings.load();
    _openSsl = bindings.ssl;
    _openSslCrypto = bindings.crypto;
  }

  void _initializeSSL({String? certFile, String? keyFile}) {
    ffi.Pointer<SSL_METHOD> method =
        _isServer ? _openSsl.TLS_server_method() : _openSsl.TLS_client_method();
    _ctx = _openSsl.SSL_CTX_new(method);
    if (_ctx == ffi.nullptr || _ctx == null) {
      throw io.SocketException('Failed to create the SSL context.');
    }
    if (_isServer) {
      if (certFile == null || keyFile == null) {
        throw io.SocketException(
          'Certificate and private key are required in server mode.',
        );
      }
      final certFilePtr = certFile.toNativeUtf8();
      final keyFilePtr = keyFile.toNativeUtf8();
      final ctxPtr = _ctxPtr;
      final certResult = _openSsl.SSL_CTX_use_certificate_file(
        ctxPtr,
        certFilePtr.cast(),
        1,
      );
      final keyResult = _openSsl.SSL_CTX_use_PrivateKey_file(
        ctxPtr,
        keyFilePtr.cast(),
        1,
      );
      calloc.free(certFilePtr);
      calloc.free(keyFilePtr);
      if (certResult != 1) {
        throw io.SocketException('Failed to load the certificate file.');
      }
      if (keyResult != 1) {
        throw io.SocketException('Failed to load the private key file.');
      }
    }
  }

  void _attachSslObject() {
    final ctxPtr = _ctxPtr;
    _ssl = _openSsl.SSL_new(ctxPtr);
    if (_ssl == ffi.nullptr || _ssl == null) {
      throw io.SocketException('Failed to create the SSL instance.');
    }
    _networkReadBio = _openSslCrypto.BIO_new(_openSslCrypto.BIO_s_mem());
    _networkWriteBio = _openSslCrypto.BIO_new(_openSslCrypto.BIO_s_mem());
    if (_networkReadBio == ffi.nullptr || _networkWriteBio == ffi.nullptr) {
      throw io.SocketException('Failed to create the TLS transport BIOs.');
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
      throw io.SocketException('SSL context is unavailable.');
    }
    return ctx;
  }

  ffi.Pointer<ssl_st> get _sslPtr {
    final ssl = _ssl;
    if (ssl == null || ssl == ffi.nullptr) {
      throw io.SocketException('SSL object is unavailable.');
    }
    return ssl;
  }

  ffi.Pointer<BIO> get _networkReadBioPtr {
    final bio = _networkReadBio;
    if (bio == null || bio == ffi.nullptr) {
      throw io.SocketException('TLS read BIO is unavailable.');
    }
    return bio;
  }

  ffi.Pointer<BIO> get _networkWriteBioPtr {
    final bio = _networkWriteBio;
    if (bio == null || bio == ffi.nullptr) {
      throw io.SocketException('TLS write BIO is unavailable.');
    }
    return bio;
  }
}
