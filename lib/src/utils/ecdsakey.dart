import 'dart:typed_data';

import 'cryptomath.dart';

/// Abstract base class for ECDSA keys, mirroring tlslite-ng's API.
abstract class ECDSAKey {
  /// Size of the curve order, in bits.
  int get bitLength;

  /// True if the key instance carries a private component.
  bool hasPrivateKey();

  Uint8List signDigest(Uint8List hash, String hashAlg);

  bool verifyDigest(Uint8List signature, Uint8List hashBytes);

  Uint8List hashAndSign(List<int> data,
      {String? rsaScheme, String hAlg = 'sha1', int? saltLen}) {
    final hashBytes = secureHash(Uint8List.fromList(data), hAlg);
    return sign(hashBytes, padding: rsaScheme, hashAlg: hAlg, saltLen: saltLen);
  }

  bool hashAndVerify(List<int> signature, List<int> data,
      {String? rsaScheme, String hAlg = 'sha1', int? saltLen}) {
    final hashBytes = secureHash(Uint8List.fromList(data), hAlg);
    return verify(Uint8List.fromList(signature), hashBytes,
        padding: rsaScheme, hashAlg: hAlg, saltLen: saltLen);
  }

  Uint8List sign(Uint8List hashBytes,
      {String? padding, String hashAlg = 'sha1', int? saltLen}) {
    if (!hasPrivateKey()) {
      throw StateError('Private key required for signing');
    }
    return signDigest(hashBytes, hashAlg.toLowerCase());
  }

  bool verify(Uint8List signature, Uint8List hashBytes,
      {String? padding, String? hashAlg, int? saltLen}) {
    return verifyDigest(signature, hashBytes);
  }

  bool acceptsPassword();

  String write({String? password});

  static ECDSAKey generate(String curveName) {
    throw UnimplementedError('Implemented by concrete backends');
  }
}