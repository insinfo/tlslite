// ignore_for_file: camel_case_types, non_constant_identifier_names
// ignore_for_file: constant_identifier_names, public_member_api_docs
// ignore_for_file: unused_field, lines_longer_than_80_chars

import 'dart:async';
import 'dart:ffi' as ffi;
import 'dart:isolate';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:tlslite/src/net/ciphertext_callback.dart';
import 'package:tlslite/src/net_ffi/socket_exceptions.dart';
import 'package:tlslite/src/net_ffi/native_buffer_utils.dart';
import 'package:tlslite/src/net_ffi/sync/socket_native_ffi.dart';

import '../../openssl/generated/ffi.dart';
import '../../openssl/openssl_loader.dart';
import '../secure_socket_constants.dart';




/// High-level helper that combines the isolate-backed transport with the
/// async OpenSSL engine so callers can await TLS handshakes without blocking
/// the main isolate.
class SecureSocketOpenSSLIsolateClient {
  SecureSocketOpenSSLIsolateClient._(this._transport, this._tls);

  final _IsolatedSocketTransport _transport;
  final SecureFFISocketOpenSSLAsync _tls;

  bool get isHandshakeComplete => _tls.isHandshakeComplete;

  static Future<SecureSocketOpenSSLIsolateClient> connect({
    required String host,
    required int port,
    int family = AF_INET,
    int type = SOCK_STREAM,
    int protocol = IPPROTO_TCP,
  }) async {
    final transport = await _IsolatedSocketTransport.connect(
      host: host,
      port: port,
      family: family,
      type: type,
      protocol: protocol,
    );
    final tls = SecureFFISocketOpenSSLAsync.client(
      writer: transport.writeCiphertext,
      reader: transport.readCiphertext,
    );
    final client = SecureSocketOpenSSLIsolateClient._(transport, tls);
    await client.ensureHandshakeCompleted();
    return client;
  }

  Future<void> ensureHandshakeCompleted() => _tls.ensureHandshakeCompleted();

  Future<int> send(Uint8List data) => _tls.send(data);

  Future<Uint8List> recv(int bufferSize) => _tls.recv(bufferSize);

  Future<void> close() async {
    await _tls.close();
    await _transport.close();
  }
}

/// Exposes a BIO-backed TLS engine that can be wired into async protocols such
/// as SQL Server TDS, where TLS records must be encapsulated in custom frames.
class SecureFFISocketOpenSSLAsync {
  SecureFFISocketOpenSSLAsync._({
    required bool isServer,
    String? certFile,
    String? keyFile,
    required CiphertextWriterAsync writer,
    required CiphertextReaderAsync reader,
  })  : _isServer = isServer,
        _certFile = certFile,
        _keyFile = keyFile,
        _writeCiphertext = writer,
        _readCiphertext = reader {
    _initOpenSsl();
    _initializeSSL(certFile: certFile, keyFile: keyFile);
    _attachSslObject();
  }

  factory SecureFFISocketOpenSSLAsync.client({
    required CiphertextWriterAsync writer,
    required CiphertextReaderAsync reader,
  }) =>
      SecureFFISocketOpenSSLAsync._(
        isServer: false,
        writer: writer,
        reader: reader,
      );

  factory SecureFFISocketOpenSSLAsync.server({
    required CiphertextWriterAsync writer,
    required CiphertextReaderAsync reader,
    required String certFile,
    required String keyFile,
  }) =>
      SecureFFISocketOpenSSLAsync._(
        isServer: true,
        certFile: certFile,
        keyFile: keyFile,
        writer: writer,
        reader: reader,
      );

  final bool _isServer;
  final CiphertextWriterAsync _writeCiphertext;
  final CiphertextReaderAsync _readCiphertext;
  final String? _certFile;
  final String? _keyFile;
  late final OpenSsl _openSsl;
  late final OpenSsl _openSslCrypto;
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
      if (error == kSslErrorWantRead) {
        final filled = await _fillReadBioFromCallbacks();
        if (!filled) {
            throw SocketException(
              'TLS handshake aborted: encrypted channel yielded no bytes.');
        }
        continue;
      }
      if (error == kSslErrorWantWrite) {
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
        if (error == kSslErrorWantRead) {
          final filled = await _fillReadBioFromCallbacks();
          if (!filled) {
            throw SocketException(
              'Encrypted channel closed while SSL_write was in progress.');
          }
          continue;
        }
        if (error == kSslErrorWantWrite) {
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
        if (error == kSslErrorWantRead) {
          final filled = await _fillReadBioFromCallbacks(
            preferredSize: bufferSize,
          );
          if (!filled) {
            return Uint8List(0);
          }
          continue;
        }
        if (error == kSslErrorWantWrite) {
          await _drainWriteBioAsync();
          continue;
        }
        if (error == kSslErrorZeroReturn) {
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
            ? kDefaultCiphertextChunk
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
      final written = _openSslCrypto.BIO_write(
        bio,
        buffer.pointer.cast(),
        ciphertext.length,
      );
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
      final pending = _openSslCrypto.BIO_ctrl(
        bio,
        kBioCtrlPending,
        0,
        ffi.nullptr.cast<ffi.Void>(),
      );
      if (pending <= 0) {
        return;
      }
      final chunkSize = pending < kDefaultCiphertextChunk
          ? pending
          : kDefaultCiphertextChunk;
      final buffer = NativeUint8Buffer.pooled(
        chunkSize,
        pool: NativeUint8BufferPool.global,
      );
      try {
        final read =
          _openSslCrypto.BIO_read(bio, buffer.pointer.cast(), chunkSize);
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
    final bindings = OpenSslBindings.load();
    _openSsl = bindings.ssl;
    _openSslCrypto = bindings.crypto;
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
    _networkReadBio = _openSslCrypto.BIO_new(_openSslCrypto.BIO_s_mem());
    _networkWriteBio = _openSslCrypto.BIO_new(_openSslCrypto.BIO_s_mem());
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

class _IsolatedSocketTransport {
  _IsolatedSocketTransport._({
    required Isolate isolate,
    required SendPort commandPort,
    required ReceivePort responsePort,
    required ReceivePort exitPort,
    required ReceivePort errorPort,
  })  : _isolate = isolate,
        _commandPort = commandPort,
        _responsePort = responsePort,
        _exitPort = exitPort,
        _errorPort = errorPort {
    _responseSubscription = _responsePort.listen(_handleResponse);
    _exitSubscription = _exitPort.listen((_) {
      _failAll(SocketException('Socket isolate exited unexpectedly'));
    });
    _errorSubscription = _errorPort.listen((dynamic message) {
      final description = message is List && message.isNotEmpty
          ? message.first.toString()
          : 'Socket isolate error';
      _failAll(SocketException(description));
    });
  }

  final Isolate _isolate;
  final SendPort _commandPort;
  final ReceivePort _responsePort;
  final ReceivePort _exitPort;
  final ReceivePort _errorPort;
  late final StreamSubscription<dynamic> _responseSubscription;
  late final StreamSubscription<dynamic> _exitSubscription;
  late final StreamSubscription<dynamic> _errorSubscription;
  final Map<int, Completer<Object?>> _pending = <int, Completer<Object?>>{};
  int _nextRequestId = 0;
  bool _closed = false;

  static Future<_IsolatedSocketTransport> connect({
    required String host,
    required int port,
    required int family,
    required int type,
    required int protocol,
  }) async {
    final readyPort = ReceivePort();
    final responsePort = ReceivePort();
    final exitPort = ReceivePort();
    final errorPort = ReceivePort();

    final isolate = await Isolate.spawn<Map<String, Object?>>(
      _socketWorkerEntry,
      <String, Object?>{
        'readyPort': readyPort.sendPort,
        'responsePort': responsePort.sendPort,
      },
      errorsAreFatal: true,
      onExit: exitPort.sendPort,
      onError: errorPort.sendPort,
      debugName: 'tlslite_socket_worker',
    );

    final commandPort = await readyPort.first as SendPort;
    readyPort.close();

    final transport = _IsolatedSocketTransport._(
      isolate: isolate,
      commandPort: commandPort,
      responsePort: responsePort,
      exitPort: exitPort,
      errorPort: errorPort,
    );

    await transport._request<void>('connect', <String, Object?>{
      'host': host,
      'port': port,
      'family': family,
      'type': type,
      'protocol': protocol,
    });

    return transport;
  }

  Future<void> writeCiphertext(Uint8List chunk) async {
    if (chunk.isEmpty) {
      return;
    }
    await _request<int>('write', <String, Object?>{'bytes': chunk});
  }

  Future<Uint8List?> readCiphertext(int preferredLength) async {
    final size = preferredLength <= 0 ? 1 : preferredLength;
    final data =
        await _request<Uint8List>('read', <String, Object?>{'length': size});
    return data;
  }

  Future<void> close() async {
    if (_closed) {
      return;
    }
    try {
      await _request<void>('close', const <String, Object?>{});
    } catch (_) {
      // Ignore failures during shutdown; the isolate is going away anyway.
    } finally {
      _closed = true;
      await _responseSubscription.cancel();
      await _exitSubscription.cancel();
      await _errorSubscription.cancel();
      _responsePort.close();
      _exitPort.close();
      _errorPort.close();
      _isolate.kill(priority: Isolate.immediate);
      _failAll(SocketException('Socket isolate closed'));
    }
  }

  Future<T> _request<T>(String op, Map<String, Object?> payload) {
    if (_closed) {
      throw SocketException('Socket isolate is already closed');
    }
    final id = _nextRequestId++;
    final completer = Completer<Object?>();
    _pending[id] = completer;
    final message = Map<String, Object?>.from(payload);
    message['id'] = id;
    message['op'] = op;
    _commandPort.send(message);
    return completer.future.then((value) => value as T);
  }

  void _handleResponse(dynamic message) {
    if (message is! Map) {
      return;
    }
    final id = message['id'] as int?;
    if (id == null) {
      return;
    }
    final completer = _pending.remove(id);
    if (completer == null) {
      return;
    }
    final ok = message['ok'] as bool? ?? false;
    if (ok) {
      completer.complete(message['data']);
    } else {
      final errorMessage =
          message['message'] as String? ?? 'Unknown socket isolate error';
      completer.completeError(SocketException(errorMessage));
    }
  }

  void _failAll(SocketException error) {
    if (_pending.isEmpty) {
      return;
    }
    final pending = _pending.values.toList();
    _pending.clear();
    for (final completer in pending) {
      if (!completer.isCompleted) {
        completer.completeError(error);
      }
    }
  }
}

@pragma('vm:entry-point')
void _socketWorkerEntry(Map<String, Object?> init) {
  final readyPort = init['readyPort'] as SendPort;
  final responsePort = init['responsePort'] as SendPort;
  final commandPort = ReceivePort();
  readyPort.send(commandPort.sendPort);

  SocketNative? socket;

  void sendOk(int id, [Object? data]) {
    responsePort.send(<String, Object?>{'id': id, 'ok': true, 'data': data});
  }

  void sendError(int id, Object error) {
    final description =
        error is SocketException ? error.message : error.toString();
    responsePort.send(<String, Object?>{
      'id': id,
      'ok': false,
      'message': description,
    });
  }

  commandPort.listen((dynamic rawMessage) {
    if (rawMessage is! Map) {
      return;
    }
    final id = rawMessage['id'] as int? ?? -1;
    final op = rawMessage['op'] as String? ?? '';
    try {
      switch (op) {
        case 'connect':
          final host = rawMessage['host'] as String;
          final port = rawMessage['port'] as int;
          final family = rawMessage['family'] as int;
          final type = rawMessage['type'] as int;
          final protocol = rawMessage['protocol'] as int;
          socket?.close();
          socket = SocketNative.blocking(family, type, protocol);
          socket!.connect(host, port);
          sendOk(id);
          break;
        case 'write':
          final bytes = rawMessage['bytes'] as Uint8List? ?? Uint8List(0);
          if (socket == null) {
            throw SocketException('Socket not connected');
          }
          if (bytes.isNotEmpty) {
            socket!.sendall(bytes);
          }
          sendOk(id, bytes.length);
          break;
        case 'read':
          final requested = rawMessage['length'] as int? ?? 1;
          if (socket == null) {
            throw SocketException('Socket not connected');
          }
          final size = requested <= 0 ? 1 : requested;
          final data = socket!.recv(size);
          sendOk(id, data);
          break;
        case 'close':
          socket?.close();
          socket = null;
          sendOk(id);
          commandPort.close();
          break;
        default:
          throw SocketException('Unsupported socket op: $op');
      }
    } catch (error) {
      sendError(id, error);
      if (op == 'close') {
        commandPort.close();
      }
    }
  });
}
