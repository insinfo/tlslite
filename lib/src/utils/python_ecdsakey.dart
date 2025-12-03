import 'dart:typed_data';

import 'package:pointycastle/api.dart' as pc
    show Digest, PrivateKeyParameter, PublicKeyParameter;
import 'package:pointycastle/digests/md5.dart';
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha224.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/ecc/api.dart' as ecc;
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';

import 'cryptomath.dart';
import 'curve_oids.dart';
import 'der.dart';
import 'ecdsakey.dart';
import 'ecc.dart';
import 'pem.dart';
import 'pkcs8.dart';

class PythonECDSAKey extends ECDSAKey {
  PythonECDSAKey({
    BigInt? pointX,
    BigInt? pointY,
    required String curveName,
    BigInt? secretMultiplier,
  }) : curveName = curveName {
    final domain = getCurveByName(curveName);
    _domain = domain;
    ecc.ECPoint? publicPoint;
    if (secretMultiplier == null && (pointX == null || pointY == null)) {
      throw ArgumentError(
          'Provide either a private multiplier or public point');
    }
    if (secretMultiplier != null) {
      _privateKey = ecc.ECPrivateKey(secretMultiplier, domain);
      publicPoint = (domain.G * secretMultiplier)!;
    }
    if (pointX != null && pointY != null) {
      publicPoint = domain.curve.createPoint(pointX, pointY);
    }
    if (publicPoint == null) {
      throw StateError('Unable to determine public point');
    }
    _publicPoint = publicPoint;
    _publicKey = ecc.ECPublicKey(_publicPoint, domain);
  }

  final String curveName;
  late final ecc.ECDomainParameters _domain;
  late final ecc.ECPoint _publicPoint;
  late final ecc.ECPublicKey _publicKey;
  ecc.ECPrivateKey? _privateKey;

  @override
  int get bitLength => _domain.n.bitLength;

  @override
  bool hasPrivateKey() => _privateKey != null;

  @override
  Uint8List signDigest(Uint8List hash, String hashAlg) {
    final privateKey = _privateKey;
    if (privateKey == null) {
      throw StateError('Private key required for signing');
    }
    final digest = _digestFor(hashAlg);
    final signer = ECDSASigner(null, HMac(digest, _blockLength(hashAlg)));
    signer.init(true, pc.PrivateKeyParameter(privateKey));
    final sig = signer.generateSignature(hash) as ecc.ECSignature;
    return derEncodeSequence([
      derEncodeInteger(sig.r),
      derEncodeInteger(sig.s),
    ]);
  }

  @override
  bool verifyDigest(Uint8List signature, Uint8List hashBytes) {
    final (r: r, s: s) = derDecodeSignature(signature);
    final signer = ECDSASigner();
    signer.init(false, pc.PublicKeyParameter(_publicKey));
    return signer.verifySignature(hashBytes, ecc.ECSignature(r, s));
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

  BigInt get publicPointX {
    final xCoord = _publicPoint.x;
    if (xCoord == null) {
      throw StateError('Public point is at infinity');
    }
    final value = xCoord.toBigInteger();
    if (value == null) {
      throw StateError('Point X coordinate missing');
    }
    return value;
  }

  BigInt get publicPointY {
    final yCoord = _publicPoint.y;
    if (yCoord == null) {
      throw StateError('Public point is at infinity');
    }
    final value = yCoord.toBigInteger();
    if (value == null) {
      throw StateError('Point Y coordinate missing');
    }
    return value;
  }

  BigInt? get secretMultiplier => _privateKey?.d;

  pc.Digest _digestFor(String hashAlg) {
    switch (hashAlg) {
      case 'md5':
        return MD5Digest();
      case 'sha1':
        return SHA1Digest();
      case 'sha224':
        return SHA224Digest();
      case 'sha256':
        return SHA256Digest();
      case 'sha384':
        return SHA384Digest();
      case 'sha512':
        return SHA512Digest();
      default:
        throw ArgumentError('Unsupported hash algorithm: $hashAlg');
    }
  }

  int _blockLength(String hashAlg) {
    switch (hashAlg) {
      case 'md5':
      case 'sha1':
      case 'sha224':
      case 'sha256':
        return 64;
      case 'sha384':
      case 'sha512':
        return 128;
      default:
        throw ArgumentError('Unsupported hash algorithm: $hashAlg');
    }
  }

  Uint8List _encodeEcPrivateKey() {
    final privateKey = _privateKey;
    if (privateKey == null) {
      throw StateError('Private key is required for serialization');
    }
    final curveOid = curveOidFromName(curveName);
    if (curveOid == null) {
      throw UnsupportedError('Unknown curve OID for $curveName');
    }
    final coordLength = getPointByteSize(_domain);
    final privateScalar =
        numberToByteArray(privateKey.d!, howManyBytes: coordLength);
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

  Uint8List _encodeEcPoint() {
    final coordLength = getPointByteSize(_domain);
    final xBytes = numberToByteArray(publicPointX, howManyBytes: coordLength);
    final yBytes = numberToByteArray(publicPointY, howManyBytes: coordLength);
    final encoded = Uint8List(1 + xBytes.length + yBytes.length);
    encoded[0] = 0x04;
    encoded.setRange(1, 1 + xBytes.length, xBytes);
    encoded.setRange(1 + xBytes.length, encoded.length, yBytes);
    return encoded;
  }
}

const List<int> _ecPublicKeyOid = [1, 2, 840, 10045, 2, 1];
