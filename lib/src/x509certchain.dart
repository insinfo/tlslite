import 'utils/pem.dart';
import 'x509.dart';

/// Representation of a chain of X.509 certificates.
class X509CertChain {
  X509CertChain([List<X509>? certificates])
      : x509List = List<X509>.from(certificates ?? const []);

  /// Certificates ordered from end-entity to trust anchor.
  List<X509> x509List;

  /// Parse a blob containing one or more PEM certificates.
  void parsePemList(String pemData) {
    final derList = dePemList(pemData, 'CERTIFICATE');
    final parsed = <X509>[];
    for (final der in derList) {
      parsed.add(X509()..parseBinary(der));
    }
    x509List = parsed;
  }

  /// Number of certificates in the chain.
  int getNumCerts() => x509List.length;

  /// Return the end-entity public key.
  Object getEndEntityPublicKey() {
    if (x509List.isEmpty) {
      throw StateError('Certificate chain is empty');
    }
    final key = x509List.first.publicKey;
    if (key == null) {
      throw StateError('End-entity certificate is missing a public key');
    }
    return key;
  }

  /// Hex fingerprint of the end-entity certificate.
  String getFingerprint() {
    if (x509List.isEmpty) {
      throw StateError('Certificate chain is empty');
    }
    return x509List.first.getFingerprint();
  }

  /// TACK validation is not yet ported; conservatively return false.
  bool checkTack(Object tack) {
    // TODO(port): Implement once utils/tackwrapper.dart is available.
    // Requires porting tlslite-ng/tlslite/utils/tackwrapper.py
    return false;
  }

  /// Extract the TACK extension if present (not yet implemented).
  Object? getTackExt() {
    // TODO(port): Implement once utils/tackwrapper.dart is available.
    // Requires porting tlslite-ng/tlslite/utils/tackwrapper.py
    return null;
  }

  @override
  int get hashCode => Object.hashAll(x509List);

  @override
  bool operator ==(Object other) {
    if (other is! X509CertChain) {
      return false;
    }
    if (x509List.length != other.x509List.length) {
      return false;
    }
    for (var i = 0; i < x509List.length; i++) {
      if (x509List[i] != other.x509List[i]) {
        return false;
      }
    }
    return true;
  }
}
