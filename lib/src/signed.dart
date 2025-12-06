import 'dart:typed_data';

import 'utils/cryptomath.dart';
import 'utils/dsakey.dart';
import 'utils/ecdsakey.dart';
import 'utils/eddsakey.dart';
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
// - Integration with TLS 1.3 signature schemes (RSA-PSS parameters)

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

  static final Map<String, _SignatureAlgorithm> _signatureAlgorithms = {
  // PKCS#1 v1.5 RSA
  _oidKey([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x04]):
    _SignatureAlgorithm.rsa('md5'),
  _oidKey([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]):
    _SignatureAlgorithm.rsa('sha1'),
  _oidKey([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0e]):
    _SignatureAlgorithm.rsa('sha224'),
  _oidKey([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]):
    _SignatureAlgorithm.rsa('sha256'),
  _oidKey([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c]):
    _SignatureAlgorithm.rsa('sha384'),
  _oidKey([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d]):
    _SignatureAlgorithm.rsa('sha512'),
  // ECDSA (RFC 5758)
  _oidKey([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01]):
    _SignatureAlgorithm.ecdsa('sha1'),
  _oidKey([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x01]):
    _SignatureAlgorithm.ecdsa('sha224'),
  _oidKey([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]):
    _SignatureAlgorithm.ecdsa('sha256'),
  _oidKey([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]):
    _SignatureAlgorithm.ecdsa('sha384'),
  _oidKey([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04]):
    _SignatureAlgorithm.ecdsa('sha512'),
  // DSA (FIPS 186-4)
  _oidKey([0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x03]):
    _SignatureAlgorithm.dsa('sha1'),
  _oidKey([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x01]):
    _SignatureAlgorithm.dsa('sha224'),
  _oidKey([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x02]):
    _SignatureAlgorithm.dsa('sha256'),
  _oidKey([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x03]):
    _SignatureAlgorithm.dsa('sha384'),
  _oidKey([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x04]):
    _SignatureAlgorithm.dsa('sha512'),
  // EdDSA (RFC 8410)
  _oidKey([0x2b, 0x65, 0x70]): _SignatureAlgorithm.eddsa('ed25519'),
  _oidKey([0x2b, 0x65, 0x71]): _SignatureAlgorithm.eddsa('ed448'),
  };

  bool verifySignature(
  Object publicKey, {
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

    final descriptor = _signatureAlgorithms[_oidKey(alg)];
    if (descriptor == null) {
      throw ArgumentError(
        'Unknown signature algorithm OID: ${_formatOid(alg)}',
      );
    }

    switch (descriptor.keyType) {
      case _SignatureKeyType.rsa:
        if (publicKey is! RSAKey) {
          throw ArgumentError('RSA signature requires an RSAKey');
        }
        final resolvedSettings = (settings ?? SignatureSettings()).validate();
        final hashName = descriptor.hashName;
        if (hashName == null) {
          throw ArgumentError('RSA signature missing hash algorithm');
        }
        if (!resolvedSettings.rsaSigHashes.contains(hashName)) {
          throw ArgumentError('Invalid signature algorithm: $hashName');
        }
        final scheme = descriptor.scheme;
        if (scheme != null &&
            !resolvedSettings.rsaSchemes.contains(scheme.toLowerCase())) {
          throw ArgumentError('RSA scheme $scheme not allowed');
        }
        final normalized = _normalizeRsaSignature(sig, publicKey);
        final verified = publicKey.hashAndVerify(
          normalized,
          data,
          rsaScheme: (scheme ?? 'pkcs1').toUpperCase(),
          hAlg: hashName,
        );
        if (!verified) {
          throw StateError('Signature could not be verified for $hashName');
        }
        return true;
      case _SignatureKeyType.ecdsa:
        if (publicKey is! ECDSAKey) {
          throw ArgumentError('ECDSA signature requires an ECDSAKey');
        }
        final hashName = descriptor.hashName ?? 'sha256';
        final verified = publicKey.hashAndVerify(sig, data, hAlg: hashName);
        if (!verified) {
          throw StateError('Signature could not be verified for $hashName');
        }
        return true;
      case _SignatureKeyType.dsa:
        if (publicKey is! DSAKey) {
          throw ArgumentError('DSA signature requires a DSAKey');
        }
        final hashName = descriptor.hashName ?? 'sha1';
        final verified = publicKey.hashAndVerify(sig, data, hashName);
        if (!verified) {
          throw StateError('Signature could not be verified for $hashName');
        }
        return true;
      case _SignatureKeyType.eddsa:
        if (publicKey is! EdDSAKey) {
          throw ArgumentError('EdDSA signature requires an EdDSAKey');
        }
        final curve = descriptor.hashName ?? 'ed25519';
        final verified = publicKey.hashAndVerify(sig, data);
        if (!verified) {
          throw StateError('Signature could not be verified for $curve');
        }
        return true;
    }
  }

  static String _oidKey(List<int> oidBytes) =>
      oidBytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

  static String _formatOid(List<int> oidBytes) =>
      oidBytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join(':');
}

enum _SignatureKeyType { rsa, ecdsa, dsa, eddsa }

class _SignatureAlgorithm {
  const _SignatureAlgorithm._(this.keyType, this.hashName, this.scheme);

  factory _SignatureAlgorithm.rsa(String hashName) =>
      _SignatureAlgorithm._(_SignatureKeyType.rsa, hashName, 'pkcs1');

  factory _SignatureAlgorithm.ecdsa(String hashName) =>
      _SignatureAlgorithm._(_SignatureKeyType.ecdsa, hashName, null);

  factory _SignatureAlgorithm.dsa(String hashName) =>
      _SignatureAlgorithm._(_SignatureKeyType.dsa, hashName, null);

  factory _SignatureAlgorithm.eddsa(String curveName) =>
      _SignatureAlgorithm._(_SignatureKeyType.eddsa, curveName, null);

  final _SignatureKeyType keyType;
  final String? hashName;
  final String? scheme;
}

Uint8List _normalizeRsaSignature(Uint8List signature, RSAKey key) {
  if (signature.isEmpty) {
    return signature;
  }
  final modulusBytes = numBytes(key.n);
  if (signature.length == modulusBytes) {
    return signature;
  }
  if (signature.length == modulusBytes + 1 && signature[0] == 0) {
    return Uint8List.fromList(signature.sublist(1));
  }
  return signature;
}
