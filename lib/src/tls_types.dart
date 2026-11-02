import 'dart:typed_data';

import 'package:tlslite/src/tls_protocol.dart';

import 'utils/keyfactory.dart';
import 'utils/pem.dart';
import 'messages.dart';

/// Operating mode expected by the pure Dart TLS engine.
enum PureDartTlsMode { client, server }

/// Provisional configuration (certificate chain and private key).
///
/// NOTE: Aligns with HandshakeSettings from handshake_settings.dart.
class PureDartTlsConfig {
  PureDartTlsConfig({
    this.certificateChainPem,
    this.privateKeyPem,
  });

  final String? certificateChainPem;
  final String? privateKeyPem;

  /// Normalized list of the individual PEM blocks of the certificate chain.
    late final List<String> certificateChain =
      _extractCertificateBlocks(certificateChainPem);

  /// DER encoding of each PEM certificate.
  ///
  /// NOTE: Uses X509 class from x509.dart for certificate parsing.
  late final List<Uint8List> certificateChainDer =
      certificateChain.map((pem) => dePem(pem, 'CERTIFICATE')).toList();

  /// Private key parsed with the pure Dart keyfactory.
  late final Object? privateKey =
      privateKeyPem == null ? null : parsePrivateKey(privateKeyPem!);

  bool get hasServerCredentials =>
      certificateChain.isNotEmpty && privateKey != null;

  void ensureServerCredentials() {
    if (!hasServerCredentials) {
      throw StateError(
          'PureDartTlsConfig has no valid certificate and private key');
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
