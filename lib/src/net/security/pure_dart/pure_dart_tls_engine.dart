import 'dart:typed_data';

import '../../socket/socket_native_ffi.dart';

/// Define o modo de operação esperado para o engine TLS puro Dart.
enum PureDartTlsMode { client, server }

/// Configurações provisórias utilizadas enquanto o porte de tlslite-ng progride.
///
/// // TODO(tlslite-ng): alinhar este objeto com `tlslite/tlsconnection.py`
/// e as estruturas de `handshakesettings.py` assim que forem portadas.
class PureDartTlsConfig {
  const PureDartTlsConfig({
    this.certificateChainPem,
    this.privateKeyPem,
  });

  final String? certificateChainPem;
  final String? privateKeyPem;
}

/// Engine inicial responsável por concentrar o porte do TLS puro Dart.
///
/// // TODO(tlslite-ng): portar `tlslite-ng/tlslite/tlsconnection.py`,
/// `recordlayer.py`, `messages.py` e dependências para dar suporte real
/// ao handshake, negociação de ciphersuites e fluxo de registros.
class PureDartTlsEngine {
  PureDartTlsEngine({
    required this.mode,
    PureDartTlsConfig? config,
  }) : _config = config;

  final PureDartTlsMode mode;
  final PureDartTlsConfig? _config;
  bool _handshakeComplete = false;

  bool get isHandshakeComplete => _handshakeComplete;

  void ensureHandshakeCompleted(RawTransport transport) {
    if (_handshakeComplete) {
      return;
    }
    if (mode == PureDartTlsMode.server && _config == null) {
      throw UnimplementedError(
        'TODO(tlslite-ng): carregar credenciais do servidor '
        'a partir de tlslite/tlsconnection.py.',
      );
    }
    throw UnimplementedError(
      'TODO(tlslite-ng): portar handshake TLS puro Dart '
      'com base em tlslite/tlsconnection.py (mode=$mode).',
    );
  }

  int sendApplicationData(RawTransport transport, Uint8List data) {
    ensureHandshakeCompleted(transport);
    throw UnimplementedError(
      'TODO(tlslite-ng): implementar escrita de registros TLS '
      'pelo recordlayer Dart (mode=$mode).',
    );
  }

  Uint8List receiveApplicationData(
    RawTransport transport,
    int bufferSize,
  ) {
    ensureHandshakeCompleted(transport);
    throw UnimplementedError(
      'TODO(tlslite-ng): implementar leitura/decodificação de registros '
      'TLS pelo recordlayer Dart (mode=$mode).',
    );
  }

  void dispose() {
    // TODO(tlslite-ng): liberar estados de sessão, secrets e caches.
    _handshakeComplete = false;
  }
}
