import 'dart:typed_data';

import 'package:tlslite/src/tls_protocol.dart';

import 'utils/keyfactory.dart';
import 'utils/pem.dart';
import 'messages.dart';

/// Define o modo de operação esperado para o engine TLS puro Dart.
enum PureDartTlsMode { client, server }

/// Configurações provisórias utilizadas
///
/// NOTE: Aligns with HandshakeSettings from handshake_settings.dart.
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
  /// NOTE: Uses X509 class from x509.dart for certificate parsing.
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
