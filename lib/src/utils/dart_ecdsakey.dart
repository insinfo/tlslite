// Ported to Dart from tlslite-ng tlslite/utils/python_ecdsakey.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:typed_data';

import 'cryptomath.dart';
import 'curve_oids.dart';
import 'der.dart';
import 'ec/ecdsa.dart';
import 'ecdsakey.dart';
import 'ecc.dart';
import 'pem.dart';
import 'pkcs8.dart';

class DartECDSAKey extends ECDSAKey {
  DartECDSAKey({
    BigInt? pointX,
    BigInt? pointY,
    required String curveName,
    BigInt? secretMultiplier,
  }) : curveName = curveName {
    final curve = getCurveByName(curveName);
    _curve = curve;
    EcPoint? publicPoint;
    if (secretMultiplier == null && (pointX == null || pointY == null)) {
      throw ArgumentError(
          'Provide either a private multiplier or public point');
    }
    if (secretMultiplier != null) {
      if (secretMultiplier <= BigInt.zero || secretMultiplier >= curve.n) {
        throw ArgumentError('EC private key out of range for $curveName');
      }
      _secret = secretMultiplier;
      publicPoint = curve.mulBaseSecret(secretMultiplier);
    }
    if (pointX != null && pointY != null) {
      // Validates that the point lies on the curve.
      publicPoint = curve.createPoint(pointX, pointY);
    }
    if (publicPoint == null || publicPoint.isInfinity) {
      throw StateError('Unable to determine public point');
    }
    _publicPoint = publicPoint;
  }

  final String curveName;
  late final EcCurve _curve;
  late final EcPoint _publicPoint;
  BigInt? _secret;

  @override
  int get bitLength => _curve.n.bitLength;

  @override
  bool hasPrivateKey() => _secret != null;

  @override
  Uint8List signDigest(Uint8List hash, String hashAlg) {
    final secret = _secret;
    if (secret == null) {
      throw StateError('Private key required for signing');
    }
    _checkHashAlg(hashAlg);
    // Deterministic nonce (RFC 6979) with HMAC over the same hash algorithm.
    final sig = ecdsaSign(_curve, secret, hash, hashAlg);
    return derEncodeSequence([
      derEncodeInteger(sig.r),
      derEncodeInteger(sig.s),
    ]);
  }

  @override
  bool verifyDigest(Uint8List signature, Uint8List hashBytes) {
    final (r: r, s: s) = derDecodeSignature(signature);
    return ecdsaVerify(_publicPoint, hashBytes, r, s);
  }

  @override
  bool acceptsPassword() => hasPrivateKey();

  @override
  String write({String? password}) {
    if (password != null) {
      if (!hasPrivateKey()) {
        throw StateError('Cannot encrypt public-only ECDSA key');
      }
      final curveOid = curveOidFromName(curveName);
      if (curveOid == null) {
        throw UnsupportedError('Unknown curve OID for $curveName');
      }
      final pkcs8 = encodePkcs8PrivateKey(
        algorithmOid: _ecPublicKeyOid,
        algorithmParams: derEncodeObjectIdentifier(curveOid),
        privateKeyDer: _encodeEcPrivateKey(),
      );
      return encodeEncryptedPrivateKeyPem(pkcs8, password);
    }
    final derBytes = hasPrivateKey() ? _encodeEcPrivateKey() : _encodeSpki();
    final label = hasPrivateKey() ? 'EC PRIVATE KEY' : 'PUBLIC KEY';
    return pem(derBytes, label);
  }

  BigInt get publicPointX => _publicPoint.x!;

  BigInt get publicPointY => _publicPoint.y!;

  BigInt? get secretMultiplier => _secret;

  static void _checkHashAlg(String hashAlg) {
    switch (hashAlg) {
      case 'md5':
      case 'sha1':
      case 'sha224':
      case 'sha256':
      case 'sha384':
      case 'sha512':
        return;
      default:
        throw ArgumentError('Unsupported hash algorithm: $hashAlg');
    }
  }

  Uint8List _encodeEcPrivateKey() {
    final secret = _secret;
    if (secret == null) {
      throw StateError('Private key is required for serialization');
    }
    final curveOid = curveOidFromName(curveName);
    if (curveOid == null) {
      throw UnsupportedError('Unknown curve OID for $curveName');
    }
    // RFC 5915: privateKey is ceiling(log2(n)/8) octets long.
    final privateScalar =
        numberToByteArray(secret, howManyBytes: _curve.orderBytes);
    final pointBytes = _encodeEcPoint();
    final sequence = <Uint8List>[
      derEncodeInteger(BigInt.one),
      derEncodeOctetString(privateScalar),
      derEncodeContextSpecific(0, derEncodeObjectIdentifier(curveOid)),
      derEncodeContextSpecific(1, derEncodeBitString(pointBytes)),
    ];
    return derEncodeSequence(sequence);
  }

  Uint8List _encodeSpki() {
    final curveOid = curveOidFromName(curveName);
    if (curveOid == null) {
      throw UnsupportedError('Unknown curve OID for $curveName');
    }
    final algorithmIdentifier = derEncodeSequence([
      derEncodeObjectIdentifier(_ecPublicKeyOid),
      derEncodeObjectIdentifier(curveOid),
    ]);
    final subjectPublicKey = derEncodeBitString(_encodeEcPoint());
    return derEncodeSequence([algorithmIdentifier, subjectPublicKey]);
  }

  Uint8List _encodeEcPoint() => _publicPoint.encode();
}

const List<int> _ecPublicKeyOid = [1, 2, 840, 10045, 2, 1];
