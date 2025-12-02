import 'dart:typed_data';

import 'utils/cryptomath.dart';
import 'utils/rsakey.dart';

const List<String> RSA_SIGNATURE_HASHES = [
  'sha512',
  'sha384',
  'sha256',
  'sha224',
  'sha1',
];

const List<String> ALL_RSA_SIGNATURE_HASHES = [
  ...RSA_SIGNATURE_HASHES,
  'md5',
];

const List<String> RSA_SCHEMES = [
  'pss',
  'pkcs1',
];

// TODO(port): Missing functionality from Python signed.py:
// - ECDSA signature verification (currently only RSA is implemented)
// - EdDSA signature verification (Ed25519/Ed448)
// - DSA signature verification
// - Integration with TLS 1.3 signature schemes

/// Key-related constraints applied when verifying signatures.
class SignatureSettings {
  SignatureSettings({
    int? minKeySize,
    int? maxKeySize,
    List<String>? rsaSigHashes,
    List<String>? rsaSchemes,
  })  : minKeySize = minKeySize ?? 1023,
        maxKeySize = maxKeySize ?? 8193,
        rsaSigHashes = List.unmodifiable(
          (rsaSigHashes ?? RSA_SIGNATURE_HASHES)
              .map((alg) => alg.toLowerCase()),
        ),
        rsaSchemes = List.unmodifiable(
          (rsaSchemes ?? RSA_SCHEMES).map((scheme) => scheme.toLowerCase()),
        );

  final int minKeySize;
  final int maxKeySize;
  final List<String> rsaSigHashes;
  final List<String> rsaSchemes;

  SignatureSettings _copy() => SignatureSettings(
        minKeySize: minKeySize,
        maxKeySize: maxKeySize,
        rsaSigHashes: List<String>.from(rsaSigHashes),
        rsaSchemes: List<String>.from(rsaSchemes),
      );

  static void _sanityCheckKeySizes(SignatureSettings other) {
    if (other.minKeySize < 512) {
      throw ArgumentError('min_key_size too small');
    }
    if (other.minKeySize > 16384) {
      throw ArgumentError('min_key_size too large');
    }
    if (other.maxKeySize < 512) {
      throw ArgumentError('max_key_size too small');
    }
    if (other.maxKeySize > 16384) {
      throw ArgumentError('max_key_size too large');
    }
    if (other.maxKeySize < other.minKeySize) {
      throw ArgumentError('max_key_size smaller than min_key_size');
    }
  }

  static void _sanityCheckSignatureAlgs(SignatureSettings other) {
    final invalid = other.rsaSigHashes
        .where((alg) => !ALL_RSA_SIGNATURE_HASHES.contains(alg))
        .toList();
    if (invalid.isNotEmpty) {
      throw ArgumentError(
        'Following signature algorithms are not allowed: ${invalid.join(', ')}',
      );
    }
  }

  /// Returns a sanitized copy of the settings.
  SignatureSettings validate() {
    final checked = _copy();
    _sanityCheckKeySizes(checked);
    _sanityCheckSignatureAlgs(checked);
    return checked;
  }
}

/// Generic holder for signed structures that need verification.
class SignedObject {
  Uint8List? tbsData;
  Uint8List? signature;
  Uint8List? signatureAlgorithm;

  static final Map<String, String> _hashAlgsOids = {
    _oidKey([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04]): 'md5',
    _oidKey([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]): 'sha1',
    _oidKey([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e]): 'sha224',
    _oidKey([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c]): 'sha384',
    _oidKey([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]): 'sha256',
    _oidKey([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d]): 'sha512',
  };

  bool verifySignature(
    RSAKey publicKey, {
    SignatureSettings? settings,
  }) {
    final sig = signature;
    final alg = signatureAlgorithm;
    final data = tbsData;
    if (sig == null || sig.isEmpty) {
      throw StateError('Signature not set');
    }
    if (alg == null || alg.isEmpty) {
      throw StateError('Signature algorithm OID not set');
    }
    if (data == null) {
      throw StateError('Signed payload not set');
    }

    final resolvedSettings = (settings ?? SignatureSettings()).validate();

    var offset = 0;
    if (sig[0] == 0 && numBytes(publicKey.n) + 1 == sig.length) {
      offset = 1;
    }

    final algName = _hashAlgsOids[_oidKey(alg)];
    if (algName == null) {
      throw ArgumentError(
        'Unknown signature algorithm OID: ${_formatOid(alg)}',
      );
    }
    if (!resolvedSettings.rsaSigHashes.contains(algName)) {
      throw ArgumentError('Invalid signature algorithm: $algName');
    }

    final verified = publicKey.hashAndVerify(
      sig.sublist(offset),
      data,
      hAlg: algName,
    );
    if (!verified) {
      throw StateError('Signature could not be verified for $algName');
    }
    return true;
  }

  static String _oidKey(List<int> oidBytes) =>
      oidBytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

  static String _formatOid(List<int> oidBytes) =>
      oidBytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(':');
}
