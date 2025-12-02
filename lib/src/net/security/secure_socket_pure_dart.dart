import 'dart:typed_data';

import '../socket/socket_native_ffi.dart';
import 'pure_dart_with_ffi_socket/dart_tls_engine.dart';
import 'pure_dart_with_ffi_socket/dart_tls_types.dart';
import 'secure_transport.dart';

/// Implementação inicial de um provider TLS totalmente em Dart.
///
/// // TODO(tlslite-ng): conectar esta classe às camadas portadas de
/// `tlslite-ng` (record layer, mensagens e verificação de certificados).
class SecureSocketPureDart
    with SecureTransportDelegates
    implements SecureTransport {
  SecureSocketPureDart._({
    required RawTransport transport,
    required PureDartTlsMode mode,
    required bool ownsDataPath,
    PureDartTlsConfig? config,
  })  : _transport = transport,
        _mode = mode,
        _ownsDataPath = ownsDataPath,
        _config = config,
        _engine = PureDartTlsEngine(mode: mode, config: config);

  final RawTransport _transport;
  final PureDartTlsMode _mode;
  final bool _ownsDataPath;
  final PureDartTlsConfig? _config;
  final PureDartTlsEngine _engine;

  factory SecureSocketPureDart.client(int family, int type, int protocol) =>
      SecureSocketPureDart._(
        transport: SocketNative(family, type, protocol),
        mode: PureDartTlsMode.client,
        ownsDataPath: true,
      );

  factory SecureSocketPureDart.server(
    int family,
    int type,
    int protocol,
    PureDartTlsConfig config,
  ) =>
      SecureSocketPureDart._(
        transport: SocketNative(family, type, protocol),
        mode: PureDartTlsMode.server,
        ownsDataPath: false,
        config: config,
      );

  factory SecureSocketPureDart.fromTransport(
    RawTransport transport, {
    PureDartTlsMode mode = PureDartTlsMode.client,
    PureDartTlsConfig? config,
  }) =>
      SecureSocketPureDart._(
        transport: transport,
        mode: mode,
        ownsDataPath: true,
        config: config,
      );

  @override
  RawTransport get innerTransport => _transport;

  @override
  bool get isHandshakeComplete => _engine.isHandshakeComplete;

  PureDartTlsMode get mode => _mode;

  bool get _isServer => _mode == PureDartTlsMode.server;

  @override
  void ensureHandshakeCompleted() =>
      _engine.ensureHandshakeCompleted(_transport);

  @override
  void connect(String host, int port) {
    innerTransport.connect(host, port);
    if (!_isServer) {
      ensureHandshakeCompleted();
    }
  }

  @override
  RawTransport accept() {
    final child = innerTransport.accept();
    if (!_isServer || _config == null) {
      return child;
    }
    return SecureSocketPureDart._(
      transport: child,
      mode: PureDartTlsMode.server,
      ownsDataPath: true,
      config: _config,
    );
  }

  @override
  int send(Uint8List data) {
    _ensureDataPath();
    return _engine.sendApplicationData(_transport, data);
  }

  @override
  void sendall(Uint8List data) {
    final sent = send(data);
    if (sent != data.length) {
      throw SocketException(
        'Fluxo TLS puro Dart não concluiu o envio de todos os bytes',
      );
    }
  }

  @override
  Uint8List recv(int bufferSize) {
    _ensureDataPath();
    return _engine.receiveApplicationData(_transport, bufferSize);
  }

  @override
  (Uint8List, String, int) recvfrom(int bufferSize) {
    throw SocketException('recvfrom não é suportado no TLS puro Dart');
  }

  @override
  int sendto(Uint8List data, String host, int port) {
    throw SocketException('sendto não é suportado no TLS puro Dart');
  }

  @override
  void shutdown([SocketShutdown how = SocketShutdown.both]) {
    if (_ownsDataPath) {
      _engine.dispose();
    }
    innerTransport.shutdown(how);
  }

  @override
  void close() {
    if (_ownsDataPath) {
      _engine.dispose();
    }
    innerTransport.close();
  }

  void _ensureDataPath() {
    if (!_ownsDataPath) {
      throw SocketException(
        'Esta instância representa apenas um listener TLS puro Dart; '
        'utilize accept() para obter conexões dedicadas.',
      );
    }
  }
}
