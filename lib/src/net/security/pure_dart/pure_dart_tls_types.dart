import 'dart:typed_data';

import '../../../utils/keyfactory.dart';
import '../../../utils/pem.dart';
import '../../../tls_messages.dart';

/// Define o modo de operação esperado para o engine TLS puro Dart.
enum PureDartTlsMode { client, server }

/// Configurações provisórias utilizadas enquanto o porte de tlslite-ng progride.
///
/// // TODO(tlslite-ng): alinhar este objeto com `tlslite/tlsconnection.py`
/// e as estruturas de `handshakesettings.py` assim que forem portadas.
class PureDartTlsConfig {
  PureDartTlsConfig({
    this.certificateChainPem,
    this.privateKeyPem,
  });

  final String? certificateChainPem;
  final String? privateKeyPem;

  /// Lista normalizada de blocos PEM individuais para o certificado.
    late final List<String> certificateChain =
      _extractCertificateBlocks(certificateChainPem);

  /// DERs correspondentes a cada certificado PEM.
  ///
  /// // TODO(tlslite-ng): substituir por um parser X.509 completo.
  late final List<Uint8List> certificateChainDer =
      certificateChain.map((pem) => dePem(pem, 'CERTIFICATE')).toList();

  /// Chave privada parseada usando o keyfactory puro Dart.
  late final Object? privateKey =
      privateKeyPem == null ? null : parsePrivateKey(privateKeyPem!);

  bool get hasServerCredentials =>
      certificateChain.isNotEmpty && privateKey != null;

  void ensureServerCredentials() {
    if (!hasServerCredentials) {
      throw StateError(
          'PureDartTlsConfig sem certificado e chave privada válidos');
    }
  }

  TlsCertificate buildServerCertificateMessage({
    TlsProtocolVersion version = TlsProtocolVersion.tls12,
  }) {
    ensureServerCredentials();
    return TlsCertificate.tls12(
      version: version,
      certificateChain: certificateChainDer,
    );
  }
}

List<String> _extractCertificateBlocks(String? pemBundle) {
  if (pemBundle == null || pemBundle.trim().isEmpty) {
    return const <String>[];
  }
  final matches = _certificateRegex.allMatches(pemBundle);
  return matches.map((match) => match.group(0)!.trim()).toList();
}

final RegExp _certificateRegex = RegExp(
  r'-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----',
  multiLine: true,
);
