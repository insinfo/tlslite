// ignore_for_file: lines_longer_than_80_chars

import 'dart:async';
import 'dart:collection';
import 'dart:ffi' as ffi;
import 'dart:io' as io;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:logging/logging.dart';

import '../net_ffi/native_buffer_utils.dart';
import '../openssl/generated/ffi.dart';
import '../openssl/openssl_loader.dart';
import 'ciphertext_callback.dart';

const int _bioCtrlPending = 10; // BIO_CTRL_PENDING
const int _defaultCiphertextChunk = 16 * 1024;
const int _sslErrorWantRead = 2;
const int _sslErrorWantWrite = 3;
const int _sslErrorZeroReturn = 6;

/// A dart SecureSocket with dart io.Socket and OpenSSL FFI
class SecureSocketOpenSSLAsync {
  SecureSocketOpenSSLAsync._({
    io.Socket? socket,
    CiphertextWriterAsync? writer,
    CiphertextReaderAsync? reader,
    required bool isServer,
    String? certFile,
    String? keyFile,
    bool eagerHandshake = false,
    Logger? logger,
  })  : _socket = socket,
        _ciphertextWriter = writer,
        _ciphertextReader = reader,
        _useCallbacks = writer != null && reader != null,
        _isServer = isServer,
        _logger = logger ?? Logger('SecureSocketOpenSSLAsync') {
    final socket = _socket;
    if (socket != null) {
      _subscription = socket.listen(
        _handleCiphertext,
        onError: _handleSocketError,
        onDone: _handleSocketDone,
        cancelOnError: true,
      );
    }
    _initOpenSsl();
    _initializeSSL(certFile: certFile, keyFile: keyFile);
    _attachSslObject();
    if (eagerHandshake || isServer) {
      _handshakeFuture = ensureHandshakeCompleted();
    }
  }

  static Future<SecureSocketOpenSSLAsync> connect(
    String host,
    int port, {
    Duration? timeout,
    bool eagerHandshake = true,
    Logger? logger,
  }) async {
    final socket = await io.Socket.connect(host, port, timeout: timeout);
    return SecureSocketOpenSSLAsync._(
      socket: socket,
      isServer: false,
      eagerHandshake: eagerHandshake,
      logger: logger,
    );
  }

  factory SecureSocketOpenSSLAsync.clientFromSocket(
    io.Socket socket, {
    bool eagerHandshake = true,
    Logger? logger,
  }) =>
      SecureSocketOpenSSLAsync._(
        socket: socket,
        isServer: false,
        eagerHandshake: eagerHandshake,
        logger: logger,
      );

  factory SecureSocketOpenSSLAsync.clientWithCallbacks({
    required CiphertextWriterAsync writer,
    required CiphertextReaderAsync reader,
    bool eagerHandshake = true,
    Logger? logger,
  }) =>
      SecureSocketOpenSSLAsync._(
        socket: null,
        writer: writer,
        reader: reader,
        isServer: false,
        eagerHandshake: eagerHandshake,
        logger: logger,
      );

  factory SecureSocketOpenSSLAsync.serverFromSocket(
    io.Socket socket, {
    required String certFile,
    required String keyFile,
    bool eagerHandshake = true,
    Logger? logger,
  }) =>
      SecureSocketOpenSSLAsync._(
        socket: socket,
        isServer: true,
        certFile: certFile,
        keyFile: keyFile,
        eagerHandshake: eagerHandshake,
        logger: logger,
      );

  final io.Socket? _socket;
  final CiphertextWriterAsync? _ciphertextWriter;
  final CiphertextReaderAsync? _ciphertextReader;
  final bool _useCallbacks;
  final bool _isServer;
  final Logger _logger;
  late final OpenSsl _openSsl;
  late final OpenSsl _openSslCrypto;
  ffi.Pointer<ssl_ctx_st>? _ctx;
  ffi.Pointer<ssl_st>? _ssl;
  ffi.Pointer<BIO>? _networkReadBio;
  ffi.Pointer<BIO>? _networkWriteBio;
  bool _sslInitialized = false;
  Future<void>? _handshakeFuture;
  StreamSubscription<Uint8List>? _subscription;
  final Queue<Uint8List> _ciphertextQueue = Queue();
  Completer<void>? _ciphertextSignal;
  Object? _socketError;
  bool _socketClosed = false;

  io.Socket? get socket => _socket;

  bool get isHandshakeComplete => _sslInitialized;

  Future<void> ensureHandshakeCompleted() {
    _handshakeFuture ??= _performHandshake();
    return _handshakeFuture!;
  }

  Future<void> _performHandshake() async {
    if (_sslInitialized) {
      _debug('Handshake already completed, skipping.');
      return;
    }
    _debug('Starting TLS handshake (mode=${_isServer ? 'server' : 'client'}).');
    while (true) {
      _debug('Calling SSL_do_handshake');
      final result = _openSsl.SSL_do_handshake(_sslPtr);
      await _drainWriteBio();
      if (result == 1) {
        _sslInitialized = true;
        _debug('TLS handshake completed successfully.');
        return;
      }
      final error = _openSsl.SSL_get_error(_sslPtr, result);
      _debug('SSL_do_handshake result=$result error=$error');
      if (error == _sslErrorWantRead) {
        _debug('Handshake wants read; filling BIO...');
        final filled = await _fillReadBio();
        if (!filled) {
          _debug('Handshake aborting because no data arrived.');
          throw io.SocketException(
            'TLS handshake aborted: socket closed before completion.',
          );
        }
        continue;
      }
      if (error == _sslErrorWantWrite) {
        _debug('Handshake wants write; continuing.');
        continue;
      }
      _debug('Handshake failed with OpenSSL error $error.');
      throw io.SocketException(
        'TLS handshake failed (OpenSSL code $error, mode ${_isServer ? 'server' : 'client'}).',
      );
    }
  }

  Future<int> send(Uint8List data) async {
    if (data.isEmpty) {
      return 0;
    }
    await ensureHandshakeCompleted();
    final buffer = NativeUint8Buffer.fromBytes(data);
    var written = 0;
    try {
      while (written < data.length) {
        final remaining = data.length - written;
        final ptr = buffer.slice(written).cast<ffi.Void>();
        final result = _openSsl.SSL_write(_sslPtr, ptr, remaining);
        await _drainWriteBio();
        if (result > 0) {
          written += result;
          continue;
        }
        final error = _openSsl.SSL_get_error(_sslPtr, result);
        if (error == _sslErrorWantRead) {
          final filled = await _fillReadBio();
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

  Future<Uint8List> recv(int bufferSize) async {
    if (bufferSize <= 0) {
      throw ArgumentError.value(bufferSize, 'bufferSize', 'must be positive');
    }
    await ensureHandshakeCompleted();

    final builder = BytesBuilder(copy: false);
    final tempBuffer = NativeUint8Buffer.allocate(_defaultCiphertextChunk);

    try {
      while (builder.length < bufferSize) {
        final remaining = bufferSize - builder.length;
        final toRead = remaining < tempBuffer.length ? remaining : tempBuffer.length;
        _debug('SSL_read attempt bufferSize=$toRead');
        final received = _openSsl.SSL_read(
          _sslPtr,
          tempBuffer.pointer.cast(),
          toRead,
        );

        if (received > 0) {
          _debug('SSL_read produced $received bytes');
          final data = tempBuffer.copyToDart(received);
          builder.add(data);

          if (builder.length >= bufferSize) {
            break;
          }
          continue;
        }

        final error = _openSsl.SSL_get_error(_sslPtr, received);
        _debug('SSL_read result=$received error=$error');

        if (error == _sslErrorWantRead) {
          if (builder.length > 0) {
            break;
          }

          final filled =
              await _fillReadBio(preferredSize: _defaultCiphertextChunk);
          if (!filled) {
            if (builder.length == 0) {
              return Uint8List(0);
            }
            break;
          }
          continue;
        }

        if (error == _sslErrorWantWrite) {
          await _drainWriteBio();
          continue;
        }

        if (error == _sslErrorZeroReturn) {
          if (builder.length == 0) {
            return Uint8List(0);
          }
          break;
        }

        throw io.SocketException('SSL read failed (OpenSSL code $error).');
      }
    } finally {
      tempBuffer.release();
    }

    return builder.takeBytes();
  }

  Future<void> shutdown() async {
    if (_ssl == null || _ssl == ffi.nullptr || !_sslInitialized) {
      return;
    }
    final result = _openSsl.SSL_shutdown(_sslPtr);
    if (result == 0) {
      await _drainWriteBio();
      await _fillReadBio();
      _openSsl.SSL_shutdown(_sslPtr);
    }
    await _drainWriteBio();
    _sslInitialized = false;
  }

  Future<void> close() async {
    await shutdown();
    final subscription = _subscription;
    _subscription = null;
    await subscription?.cancel();
    final socket = _socket;
    if (socket != null && !_socketClosed) {
      await socket.flush();
      await socket.close();
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
    _ciphertextQueue.clear();
    final signal = _ciphertextSignal;
    if (signal != null && !signal.isCompleted) {
      signal.complete();
    }
    _ciphertextSignal = null;
  }

  Future<bool> _fillReadBio({int? preferredSize}) async {
    _debug('Filling read BIO (preferredSize=${preferredSize ?? -1}).');
    final bio = _networkReadBio;
    if (bio == null || bio == ffi.nullptr) {
      throw io.SocketException('TLS read BIO is unavailable.');
    }
    final ciphertext = await _dequeueCiphertextChunk(preferredSize);
    if (ciphertext == null || ciphertext.isEmpty) {
      _debug('No ciphertext available for read BIO.');
      return false;
    }
    final buffer = NativeUint8Buffer.fromBytes(ciphertext);
    try {
      final written = _openSslCrypto.BIO_write(
        bio,
        buffer.pointer.cast(),
        ciphertext.length,
      );
      if (written <= 0) {
        throw io.SocketException('Failed to feed the TLS read BIO.');
      }
    } finally {
      buffer.release();
    }
    _debug('Fed ${ciphertext.length} bytes into read BIO.');
    return true;
  }

  Future<void> _drainWriteBio() async {
    final bio = _networkWriteBio;
    if (bio == null || bio == ffi.nullptr) {
      return;
    }
    var wroteAny = false;
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
      final chunkSize =
          pending < _defaultCiphertextChunk ? pending : _defaultCiphertextChunk;
      final buffer = NativeUint8Buffer.allocate(chunkSize);
      try {
        final read =
            _openSslCrypto.BIO_read(bio, buffer.pointer.cast(), chunkSize);
        if (read <= 0) {
          break;
        }
        final ciphertext = buffer.copyToDart(read);
        if (ciphertext.isEmpty) {
          break;
        }
        _debug('Draining write BIO chunk of ${ciphertext.length} bytes.');
        if (_useCallbacks) {
          _debug('Sending ciphertext via callback.');
          await _ciphertextWriter!(ciphertext);
        } else {
          _debug('Sending ciphertext via socket.add (len=${ciphertext.length}).');
          _socket!.add(ciphertext);
          wroteAny = true;
        }
      } finally {
        buffer.release();
      }
    }
    final socket = _socket;
    if (wroteAny && socket != null) {
      _debug('Flushing underlying socket after BIO drain.');
      await socket.flush();
    }
  }

  Future<Uint8List?> _dequeueCiphertextChunk(int? preferredSize) async {
    if (_useCallbacks) {
      final size = preferredSize ?? _defaultCiphertextChunk;
      _debug('Requesting ciphertext via callback (size=$size).');
      return await _ciphertextReader!(size);
    }
    while (true) {
      if (_ciphertextQueue.isNotEmpty) {
        final chunk = _ciphertextQueue.removeFirst();
        _debug('Dequeued ${chunk.length} bytes from ciphertext queue.');
        return chunk;
      }
      if (_socketError != null) {
        _debug('Dequeue aborting due to socket error: $_socketError');
        final error = _socketError!;
        if (error is io.SocketException) {
          throw error;
        }
        throw io.SocketException(error.toString());
      }
      if (_socketClosed) {
        _debug('Dequeue saw closed socket; returning null.');
        return null;
      }
      _ciphertextSignal ??= Completer<void>();
      _debug('Waiting for ciphertext signal...');
      await _ciphertextSignal!.future;
    }
  }

  void _handleCiphertext(Uint8List data) {
    if (data.isEmpty) {
      return;
    }
    _ciphertextQueue.addLast(Uint8List.fromList(data));
    _debug('Received ${data.length} bytes from socket.');
    final signal = _ciphertextSignal;
    if (signal != null && !signal.isCompleted) {
      _ciphertextSignal = null;
      signal.complete();
    }
  }

  void _handleSocketError(Object error, StackTrace stackTrace) {
    _debug('Socket error: $error');
    _socketError = error;
    _socketClosed = true;
    final signal = _ciphertextSignal;
    if (signal != null && !signal.isCompleted) {
      _ciphertextSignal = null;
      signal.completeError(error, stackTrace);
    }
  }

  void _handleSocketDone() {
    _debug('Socket done/closed notification received.');
    _socketClosed = true;
    final signal = _ciphertextSignal;
    if (signal != null && !signal.isCompleted) {
      _ciphertextSignal = null;
      signal.complete();
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

  void _debug(String message) {
    _logger.fine('[#${identityHashCode(this)}] $message');
  }

}
