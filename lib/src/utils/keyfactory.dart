import 'dart:typed_data';

import 'asn1parser.dart';
import 'cryptomath.dart';
import 'dsakey.dart';
import 'ecdsakey.dart';
import 'eddsakey.dart';
import 'pem.dart';
import 'python_ecdsakey.dart';
import 'rsakey.dart';

typedef PasswordCallback = String Function();

/// Generates an RSA key using the requested implementation list.
RSAKey generateRSAKey(
  int bits, {
  List<String> implementations = const ['python'],
}) {
  for (final impl in implementations) {
    if (impl.toLowerCase() == 'python') {
      return PythonRSAKey.generate(bits);
    }
  }
  throw ArgumentError('No acceptable implementations: $implementations');
}

/// Parse a PEM-formatted key and return an asymmetric key object.
Object parsePEMKey(
  String pemData, {
  bool private = false,
  bool public = false,
  PasswordCallback? passwordCallback,
  List<String> implementations = const ['python'],
}) {
  final accepted = implementations.any((impl) => impl.toLowerCase() == 'python');
  if (!accepted) {
    throw ArgumentError('No acceptable implementations: $implementations');
  }
  if (passwordCallback != null) {
    throw UnsupportedError('Encrypted PEM files are not supported yet');
  }
  final key = _parsePemWithPurePython(pemData);
  return _parseKeyHelper(key, private: private, public: public);
}

/// Parse a PEM public key.
Object parseAsPublicKey(String pemData) => parsePEMKey(
      pemData,
      public: true,
    );

/// Parse a PEM private key.
Object parsePrivateKey(String pemData) => parsePEMKey(
      pemData,
      private: true,
    );

ECDSAKey createPublicECDSAKey(
  BigInt pointX,
  BigInt pointY,
  String curveName, {
  List<String> implementations = const ['python'],
}) {
  for (final impl in implementations) {
    if (impl.toLowerCase() == 'python') {
      return PythonECDSAKey(pointX: pointX, pointY: pointY, curveName: curveName);
    }
  }
  throw ArgumentError('No acceptable implementations: $implementations');
}

DSAKey createPublicDSAKey({
  required BigInt p,
  required BigInt q,
  required BigInt g,
  required BigInt y,
  List<String> implementations = const ['python'],
}) {
  for (final impl in implementations) {
    if (impl.toLowerCase() == 'python') {
      return PythonDSAKey(p: p, q: q, g: g, y: y);
    }
  }
  throw ArgumentError('No acceptable implementations: $implementations');
}

EdDSAKey createPublicEdDSAKey(
  Uint8List publicKey, {
  String curve = 'Ed25519',
  List<String> implementations = const ['python'],
}) {
  for (final impl in implementations) {
    if (impl.toLowerCase() == 'python') {
      if (curve == 'Ed25519') {
        return PythonEdDSAKey.ed25519(publicKey: publicKey);
      }
      throw UnsupportedError('Unsupported EdDSA curve: $curve');
    }
  }
  throw ArgumentError('No acceptable implementations: $implementations');
}

Object _parseKeyHelper(
  Object key, {
  required bool private,
  required bool public,
}) {
  if (private && !_hasPrivateComponent(key)) {
    throw const FormatException('Not a private key');
  }
  if (public) {
    return _stripToPublicKey(key);
  }
  return key;
}

bool _hasPrivateComponent(Object key) {
  if (key is RSAKey) {
    return key.hasPrivateKey();
  }
  if (key is ECDSAKey) {
    return key.hasPrivateKey();
  }
  if (key is DSAKey) {
    return key.hasPrivateKey();
  }
  if (key is EdDSAKey) {
    return key.hasPrivateKey();
  }
  return false;
}

Object _stripToPublicKey(Object key) {
  if (key is RSAKey) {
    return PythonRSAKey(
      n: key.n,
      e: key.e,
      keyType: key.keyType,
    );
  }
  if (key is PythonECDSAKey) {
    return PythonECDSAKey(
      pointX: key.publicPointX,
      pointY: key.publicPointY,
      curveName: key.curveName,
    );
  }
  if (key is PythonDSAKey) {
    return PythonDSAKey(p: key.p, q: key.q, g: key.g, y: key.y);
  }
  if (key is PythonEdDSAKey) {
    return PythonEdDSAKey.ed25519(publicKey: key.publicKeyBytes);
  }
  return key;
}

Object _parsePemWithPurePython(String pemData) {
  if (pemSniff(pemData, 'PRIVATE KEY')) {
    final der = dePem(pemData, 'PRIVATE KEY');
    return _parsePkcs8PrivateKey(der);
  }
  if (pemSniff(pemData, 'RSA PRIVATE KEY')) {
    final der = dePem(pemData, 'RSA PRIVATE KEY');
    return _parsePkcs1PrivateKey(der, keyType: 'rsa');
  }
  if (pemSniff(pemData, 'EC PRIVATE KEY')) {
    final der = dePem(pemData, 'EC PRIVATE KEY');
    final parser = ASN1Parser(der);
    return _parseEcPrivateKey(parser);
  }
  if (pemSniff(pemData, 'DSA PRIVATE KEY')) {
    final der = dePem(pemData, 'DSA PRIVATE KEY');
    return _parseDsaSsLeayKey(der);
  }
  if (pemSniff(pemData, 'PUBLIC KEY')) {
    final der = dePem(pemData, 'PUBLIC KEY');
    return _parseSubjectPublicKeyInfo(der);
  }
  throw const FormatException('Not a PEM private key file');
}

Object _parseSubjectPublicKeyInfo(Uint8List derBytes) {
  final spki = ASN1Parser(derBytes);
  final algId = spki.getChild(0);
  final oid = algId.getChild(0).value.toList();
  if (!_isRsaOid(oid)) {
    if (_listsEqual(oid, _oidDsa)) {
      return _parseDsaPublicKey(spki, algId);
    }
    if (_listsEqual(oid, _oidEcdsa)) {
      return _parseEcdsaPublicKey(spki, algId);
    }
    if (_listsEqual(oid, _oidEd25519) || _listsEqual(oid, _oidEd448)) {
      return _parseEdDsaPublicKey(spki, oid);
    }
    throw const FormatException('Unsupported public key algorithm');
  }
  final keyType = _listsEqual(oid, _oidRsaPss) ? 'rsa-pss' : 'rsa';
  final bitString = ASN1Parser(spki.getChildBytes(1));
  if (bitString.value.isEmpty || bitString.value.first != 0) {
    throw const FormatException('Invalid subjectPublicKey encoding');
  }
  final publicSequence = ASN1Parser(bitString.value.sublist(1));
  final modulus = bytesToNumber(publicSequence.getChild(0).value);
  final exponent = bytesToNumber(publicSequence.getChild(1).value);
  return PythonRSAKey(n: modulus, e: exponent, keyType: keyType);
}

Object _parsePkcs8PrivateKey(Uint8List derBytes) {
  final parser = ASN1Parser(derBytes);
  final version = bytesToNumber(parser.getChild(0).value);
  if (version != BigInt.zero) {
    throw const FormatException('Unrecognized PKCS#8 version');
  }
  final algIdent = parser.getChild(1);
  final oid = algIdent.getChild(0).value.toList();
  final keyType = _keyTypeFromOid(oid);
  if (keyType == null) {
    throw FormatException('Unrecognized AlgorithmIdentifier OID: $oid');
  }
  final childCount = algIdent.getChildCount();
  final privateKeyOctet = parser.getChild(2);
  if (childCount > 2) {
    throw const FormatException('Invalid AlgorithmIdentifier encoding');
  }
  switch (keyType) {
    case 'rsa':
      if (childCount == 2 && algIdent.getChild(1).value.isNotEmpty) {
        throw const FormatException('RSA parameters must be NULL');
      }
      return _parsePkcs1PrivateKey(privateKeyOctet.value, keyType: 'rsa');
    case 'rsa-pss':
      return _parsePkcs1PrivateKey(privateKeyOctet.value, keyType: 'rsa-pss');
    case 'dsa':
      if (childCount != 2) {
        throw const FormatException('Invalid DSA AlgorithmIdentifier');
      }
      return _parseDsaPkcs8PrivateKey(privateKeyOctet.value, algIdent.getChild(1));
    case 'ecdsa':
      if (childCount != 2) {
        throw const FormatException('Invalid ECDSA AlgorithmIdentifier');
      }
      final curveName = _curveNameFromOid(algIdent.getChild(1).value.toList());
      if (curveName == null) {
        throw const FormatException('Unknown EC curve');
      }
      return _parseEcPrivateKey(ASN1Parser(privateKeyOctet.value), curveName: curveName);
    case 'Ed25519':
      return _parseEd25519PrivateKey(privateKeyOctet.value);
    case 'Ed448':
      throw UnsupportedError('Ed448 keys are not supported yet');
    default:
      throw UnsupportedError('Unsupported PKCS#8 algorithm: $keyType');
  }
}

RSAKey _parsePkcs1PrivateKey(Uint8List derBytes, {String keyType = 'rsa'}) {
  final parser = ASN1Parser(derBytes);
  final version = bytesToNumber(parser.getChild(0).value);
  if (version != BigInt.zero) {
    throw const FormatException('Unrecognized RSAPrivateKey version');
  }
  final n = bytesToNumber(parser.getChild(1).value);
  final e = bytesToNumber(parser.getChild(2).value);
  final d = bytesToNumber(parser.getChild(3).value);
  final p = bytesToNumber(parser.getChild(4).value);
  final q = bytesToNumber(parser.getChild(5).value);
  final dP = bytesToNumber(parser.getChild(6).value);
  final dQ = bytesToNumber(parser.getChild(7).value);
  final qInv = bytesToNumber(parser.getChild(8).value);
  return PythonRSAKey(
    n: n,
    e: e,
    d: d,
    p: p,
    q: q,
    dP: dP,
    dQ: dQ,
    qInv: qInv,
    keyType: keyType,
  );
}

String? _keyTypeFromOid(List<int> oid) {
  if (_listsEqual(oid, _oidRsaEncryption)) {
    return 'rsa';
  }
  if (_listsEqual(oid, _oidRsaPss)) {
    return 'rsa-pss';
  }
  if (_listsEqual(oid, _oidDsa)) {
    return 'dsa';
  }
  if (_listsEqual(oid, _oidEcdsa)) {
    return 'ecdsa';
  }
  if (_listsEqual(oid, _oidEd25519)) {
    return 'Ed25519';
  }
  if (_listsEqual(oid, _oidEd448)) {
    return 'Ed448';
  }
  return null;
}

bool _isRsaOid(List<int> oid) {
  return _listsEqual(oid, _oidRsaEncryption) || _listsEqual(oid, _oidRsaPss);
}

bool _listsEqual(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

PythonDSAKey _parseDsaPublicKey(ASN1Parser spki, ASN1Parser algId) {
  if (algId.getChildCount() < 2) {
    throw const FormatException('DSA parameters missing');
  }
  final params = algId.getChild(1);
  final p = bytesToNumber(params.getChild(0).value);
  final q = bytesToNumber(params.getChild(1).value);
  final g = bytesToNumber(params.getChild(2).value);
  final bitString = ASN1Parser(spki.getChildBytes(1));
  if (bitString.value.isEmpty || bitString.value.first != 0) {
    throw const FormatException('Invalid DSA public key encoding');
  }
  final yParser = ASN1Parser(bitString.value.sublist(1));
  final y = bytesToNumber(yParser.value);
  return PythonDSAKey(p: p, q: q, g: g, y: y);
}

PythonECDSAKey _parseEcdsaPublicKey(ASN1Parser spki, ASN1Parser algId) {
  if (algId.getChildCount() != 2) {
    throw const FormatException('EC parameters missing');
  }
  final curveName = _curveNameFromOid(algId.getChild(1).value.toList());
  if (curveName == null) {
    throw const FormatException('Unknown EC curve OID');
  }
  final bitString = ASN1Parser(spki.getChildBytes(1));
  if (bitString.value.isEmpty || bitString.value.first != 0) {
    throw const FormatException('Invalid EC public key encoding');
  }
  final encoded = bitString.value.sublist(1);
  if (encoded.isEmpty || encoded.first != 4) {
    throw const FormatException('Unsupported EC point encoding');
  }
  final coords = encoded.sublist(1);
  if (coords.length.isOdd) {
    throw const FormatException('Malformed EC point');
  }
  final coordLen = coords.length ~/ 2;
  final x = bytesToNumber(coords.sublist(0, coordLen));
  final y = bytesToNumber(coords.sublist(coordLen));
  return PythonECDSAKey(pointX: x, pointY: y, curveName: curveName);
}

PythonEdDSAKey _parseEdDsaPublicKey(ASN1Parser spki, List<int> oid) {
  final bitString = ASN1Parser(spki.getChildBytes(1));
  if (bitString.value.isEmpty || bitString.value.first != 0) {
    throw const FormatException('Invalid EdDSA public key encoding');
  }
  final keyBytes = bitString.value.sublist(1);
  if (_listsEqual(oid, _oidEd25519)) {
    if (keyBytes.length != 32) {
      throw const FormatException('Ed25519 public keys must be 32 bytes');
    }
    return PythonEdDSAKey.ed25519(publicKey: Uint8List.fromList(keyBytes));
  }
  throw UnsupportedError('Ed448 keys are not supported yet');
}

PythonDSAKey _parseDsaPkcs8PrivateKey(Uint8List data, ASN1Parser params) {
  final p = bytesToNumber(params.getChild(0).value);
  final q = bytesToNumber(params.getChild(1).value);
  final g = bytesToNumber(params.getChild(2).value);
  final x = _extractInteger(data);
  final y = powMod(g, x, p);
  return PythonDSAKey(p: p, q: q, g: g, x: x, y: y);
}

PythonDSAKey _parseDsaSsLeayKey(Uint8List derBytes) {
  final parser = ASN1Parser(derBytes);
  final version = bytesToNumber(parser.getChild(0).value);
  if (version != BigInt.zero) {
    throw const FormatException('Unexpected DSA key version');
  }
  final p = bytesToNumber(parser.getChild(1).value);
  final q = bytesToNumber(parser.getChild(2).value);
  final g = bytesToNumber(parser.getChild(3).value);
  final y = bytesToNumber(parser.getChild(4).value);
  final x = bytesToNumber(parser.getChild(5).value);
  return PythonDSAKey(p: p, q: q, g: g, x: x, y: y);
}

PythonECDSAKey _parseEcPrivateKey(ASN1Parser parser, {String? curveName}) {
  final version = bytesToNumber(parser.getChild(0).value);
  if (version != BigInt.one) {
    throw const FormatException('Unexpected EC key version');
  }
  final privateKeyBytes = parser.getChild(1).value;
  var curve = curveName;
  Uint8List? publicField;
  final childCount = parser.getChildCount();
  for (var i = 2; i < childCount; i++) {
    final child = parser.getChild(i);
    final type = child.type;
    if (type.tagClass == 2 && type.tagId == 0) {
      final paramsParser = ASN1Parser(child.value);
      curve ??= _curveNameFromOid(paramsParser.value.toList());
    } else if (type.tagClass == 2 && type.tagId == 1) {
      publicField = child.value;
    }
  }
  if (curve == null) {
    throw const FormatException('EC parameters missing');
  }
  final secret = bytesToNumber(privateKeyBytes);
  BigInt? pointX;
  BigInt? pointY;
  if (publicField != null) {
    final coords = _decodeEcPoint(publicField);
    pointX = coords.x;
    pointY = coords.y;
  }
  return PythonECDSAKey(
    pointX: pointX,
    pointY: pointY,
    curveName: curve,
    secretMultiplier: secret,
  );
}

({BigInt x, BigInt y}) _decodeEcPoint(Uint8List bitStringBytes) {
  final bitString = ASN1Parser(bitStringBytes);
  if (bitString.type.tagId != 3) {
    throw const FormatException('Expected BIT STRING');
  }
  final bytes = bitString.value;
  if (bytes.isEmpty || bytes.first != 0) {
    throw const FormatException('Invalid EC public key encoding');
  }
  final encoded = bytes.sublist(1);
  if (encoded.isEmpty || encoded.first != 4) {
    throw const FormatException('Unsupported EC point encoding');
  }
  final coords = encoded.sublist(1);
  if (coords.length.isOdd) {
    throw const FormatException('Malformed EC point');
  }
  final coordLen = coords.length ~/ 2;
  final x = bytesToNumber(coords.sublist(0, coordLen));
  final y = bytesToNumber(coords.sublist(coordLen));
  return (x: x, y: y);
}

PythonEdDSAKey _parseEd25519PrivateKey(Uint8List data) {
  Uint8List seed = data;
  if (seed.isNotEmpty && seed.first == 0x04) {
    try {
      final parser = ASN1Parser(seed);
      if (parser.type.tagId == 0x04) {
        seed = parser.value;
      }
    } catch (_) {
      // Fallback to treating data as raw seed
    }
  }
  if (seed.length != 32) {
    throw const FormatException('Ed25519 private keys must be 32 bytes');
  }
  return PythonEdDSAKey.ed25519(privateKey: seed);
}

String? _curveNameFromOid(List<int> oid) {
  return _curveOidToName[_oidToString(oid)];
}

String _oidToString(List<int> oid) => oid.join('.');

BigInt _extractInteger(Uint8List data) {
  if (data.isEmpty) {
    return BigInt.zero;
  }
  final tag = data.first;
  if (tag == 0x02 || tag == 0x04 || tag == 0x30) {
    try {
      final parser = ASN1Parser(data);
      return bytesToNumber(parser.value);
    } catch (_) {
      // Fall back to raw interpretation
    }
  }
  return bytesToNumber(data);
}

const _oidRsaEncryption = [42, 134, 72, 134, 247, 13, 1, 1, 1];
const _oidRsaPss = [42, 134, 72, 134, 247, 13, 1, 1, 10];
const _oidDsa = [42, 134, 72, 206, 56, 4, 1];
const _oidEcdsa = [42, 134, 72, 206, 61, 2, 1];
const _oidEd25519 = [43, 101, 112];
const _oidEd448 = [43, 101, 113];

const Map<String, String> _curveOidToName = {
  '1.2.840.10045.3.1.7': 'secp256r1',
  '1.3.132.0.34': 'secp384r1',
  '1.3.132.0.35': 'secp521r1',
  '1.3.36.3.3.2.8.1.1.7': 'brainpoolp256r1',
  '1.3.36.3.3.2.8.1.1.11': 'brainpoolp384r1',
  '1.3.36.3.3.2.8.1.1.13': 'brainpoolp512r1',
  '1.3.36.3.3.2.8.1.1.11.1': 'brainpoolp384r1tls13',
  '1.3.36.3.3.2.8.1.1.13.1': 'brainpoolp512r1tls13',
  '1.3.36.3.3.2.8.1.1.7.1': 'brainpoolp256r1tls13',
};
