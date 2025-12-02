// ignore_for_file: camel_case_types, non_constant_identifier_names
// ignore_for_file: constant_identifier_names, public_member_api_docs
// ignore_for_file: unused_field, lines_longer_than_80_chars

import 'dart:ffi' as ffi;
import 'dart:io' show Platform;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import '../../openssl/openssl_ffi.dart';
import '../../openssl/openssl_ssl_extension.dart';
import 'secure_transport.dart';
import '../socket/native_buffer_utils.dart';
import '../socket/socket_native_ffi.dart';

class SecureSocketOpenSSL implements SecureTransport {
  final RawTransport _transport;
  late final OpenSSL _openSsl;
  ffi.Pointer<ssl_ctx_st>? _ctx; // typedef SSL_CTX = ssl_ctx_st
  ffi.Pointer<ssl_st>? _ssl; // typedef SSL = ssl_st
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
          'Certificado e chave são necessários para o listener TLS');
    }
  }

  /// Construtor para modo cliente com um socket próprio.
  factory SecureSocketOpenSSL(int family, int type, int protocol) =>
      SecureSocketOpenSSL._(
        transport: SocketNative(family, type, protocol),
        isServer: false,
        ownsDataPath: true,
      );

  /// Cria um listener TLS em modo servidor; cada accept() gera uma conexão TLS.
  factory SecureSocketOpenSSL.server(
          int family, int type, int protocol, String certFile, String keyFile) =>
      SecureSocketOpenSSL._(
        transport: SocketNative(family, type, protocol),
        isServer: true,
        ownsDataPath: false,
        certFile: certFile,
        keyFile: keyFile,
      );

  /// Envolve um transporte já existente em modo cliente.
  factory SecureSocketOpenSSL.fromTransport(RawTransport transport) =>
      SecureSocketOpenSSL._(
        transport: transport,
        isServer: false,
        ownsDataPath: true,
      );

  /// Envolve um transporte aceito pelo listener em modo servidor.
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
    final dynamicLibrary = Platform.isWindows
        ? ffi.DynamicLibrary.open('libssl-3-x64.dll')
        : Platform.isMacOS
            ? ffi.DynamicLibrary.open('libssl.dylib')
            : ffi.DynamicLibrary.open('libssl.so');
    _openSsl = OpenSSL(dynamicLibrary);
  }

  void _initializeSSL({String? certFile, String? keyFile}) {
    ffi.Pointer<SSL_METHOD> method =
        _isServer ? _openSsl.TLS_server_method() : _openSsl.TLS_client_method();
    _ctx = _openSsl.SSL_CTX_new(method);
    if (_ctx == ffi.nullptr || _ctx == null) {
      throw SocketException('Falha ao criar o contexto SSL');
    }
    if (_isServer) {
      if (certFile == null || keyFile == null) {
        throw SocketException(
            'Certificado e chave são necessários para o modo servidor');
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
        throw SocketException('Falha ao carregar o certificado');
      }
      if (keyResult != 1) {
        throw SocketException('Falha ao carregar a chave privada');
      }
    }
  }

  void _attachSslObject() {
    final ctxPtr = _ctxPtr;
    _ssl = _openSsl.SSL_new(ctxPtr);
    if (_ssl == ffi.nullptr || _ssl == null) {
      throw SocketException('Falha ao criar o objeto SSL');
    }
    final socketHandle = _transport.nativeHandle;
    if (socketHandle == null) {
      throw SocketException('Socket nativo indisponível para o SSL');
    }
    final result = _openSsl.SSL_set_fd(_sslPtr, socketHandle);
    if (result != 1) {
      throw SocketException('Falha ao associar o descritor ao SSL');
    }
  }

  void _ensureHandshakeCompleted() {
    _assertOwnsDataPath();
    if (_sslInitialized) {
      return;
    }
    final ssl = _sslPtr;
    final result =
        _isServer ? _openSsl.SSL_accept(ssl) : _openSsl.SSL_connect(ssl);
    if (result != 1) {
      throw SocketException(_isServer
          ? 'Handshake SSL (servidor) falhou'
          : 'Handshake SSL (cliente) falhou');
    }
    _sslInitialized = true;
  }

  void _assertOwnsDataPath() {
    if (!_ownsDataPath) {
      throw SocketException(
          'Esta instância representa apenas o listener TLS; utilize accept() para obter conexões.');
    }
  }

  ffi.Pointer<ssl_ctx_st> get _ctxPtr {
    final ctx = _ctx;
    if (ctx == null || ctx == ffi.nullptr) {
      throw SocketException('Contexto SSL indisponível');
    }
    return ctx;
  }

  ffi.Pointer<ssl_st> get _sslPtr {
    final ssl = _ssl;
    if (ssl == null || ssl == ffi.nullptr) {
      throw SocketException('Objeto SSL indisponível');
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
    final buffer = NativeUint8Buffer.fromBytes(
      data,
      pool: NativeUint8BufferPool.global,
    );
    try {
      final sent =
          _openSsl.SSL_write(_sslPtr, buffer.pointer.cast(), data.length);
      if (sent <= 0) {
        throw SocketException('Falha na escrita SSL');
      }
      return sent;
    } finally {
      buffer.release();
    }
  }

  @override
  void sendall(Uint8List data) {
    final sent = send(data);
    if (sent != data.length) {
      throw SocketException(
          'Conexão fechada antes de enviar todos os bytes sobre TLS');
    }
  }

  @override
  Uint8List recv(int bufferSize) {
    _assertOwnsDataPath();
    _ensureHandshakeCompleted();
    final buffer = NativeUint8Buffer.pooled(bufferSize);
    try {
      final received =
          _openSsl.SSL_read(_sslPtr, buffer.pointer.cast(), bufferSize);
      if (received <= 0) {
        throw SocketException('Falha na leitura SSL');
      }
      return buffer.copyToDart(received);
    } finally {
      buffer.release();
    }
  }

  @override
  (Uint8List, String, int) recvfrom(int bufferSize) {
    throw SocketException('recvfrom não é suportado sobre TLS');
  }

  @override
  int sendto(Uint8List data, String host, int port) {
    throw SocketException('sendto não é suportado sobre TLS');
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
      _openSsl.SSL_shutdown(_sslPtr);
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
        _openSsl.SSL_free(ssl);
        _ssl = null;
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
