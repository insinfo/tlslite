import 'dart:typed_data';

import '../../socket/socket_native_ffi.dart';
import 'pure_dart_tls_types.dart';
import 'tls_connection.dart';

/// Engine inicial responsável por concentrar o porte do TLS puro Dart.
///
/// // TODO(tlslite-ng): portar `tlslite-ng/tlslite/tlsconnection.py`,
/// `recordlayer.py`, `messages.py` e dependências para dar suporte real
/// ao handshake, negociação de ciphersuites e fluxo de registros.
class PureDartTlsEngine {
  PureDartTlsEngine({
    required this.mode,
    PureDartTlsConfig? config,
  }) : _config = config ?? PureDartTlsConfig() {
    _connection = PureDartTlsConnection(mode: mode, config: _config);
  }

  final PureDartTlsMode mode;
  final PureDartTlsConfig _config;
  late final PureDartTlsConnection _connection;

  bool get isHandshakeComplete => _connection.isHandshakeComplete;

  void ensureHandshakeCompleted(RawTransport transport) {
    _connection.ensureHandshake(transport);
  }

  int sendApplicationData(RawTransport transport, Uint8List data) {
    ensureHandshakeCompleted(transport);
    return _connection.sendApplicationData(transport, data);
  }

  Uint8List receiveApplicationData(
    RawTransport transport,
    int bufferSize,
  ) {
    ensureHandshakeCompleted(transport);
    return _connection.receiveApplicationData(transport, bufferSize);
  }

  void dispose() => _connection.dispose();
}
