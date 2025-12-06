import 'dart:convert';
import 'dart:typed_data';

import 'asn1parser.dart';
import 'cryptomath.dart';
import 'curve_oids.dart' show decodeOid;
import 'der.dart';
import 'pem.dart';
import 'package:pointycastle/api.dart' show BlockCipher, KeyParameter, ParametersWithIV;
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/modes/cbc.dart';

const _oidPbes2 = [1, 2, 840, 113549, 1, 5, 13];
const _oidPbkdf2 = [1, 2, 840, 113549, 1, 5, 12];
const _oidHmacWithSha256 = [1, 2, 840, 113549, 2, 9];
const _oidAes256Cbc = [2, 16, 840, 1, 101, 3, 4, 1, 42];

const int _defaultIterations = 100000;
const int _saltLength = 16;
const int _ivLength = 16;
const int _aesBlockSize = 16;
const int _aes256KeySize = 32;

Uint8List encodePkcs8PrivateKey({
  required List<int> algorithmOid,
  Uint8List? algorithmParams,
  required Uint8List privateKeyDer,
  int version = 0,
  Uint8List? publicKeyBytes,
}) {
  final algorithmChildren = <Uint8List>[derEncodeObjectIdentifier(algorithmOid)];
  if (algorithmParams != null) {
    algorithmChildren.add(algorithmParams);
  }
  final algorithmIdentifier = derEncodeSequence(algorithmChildren);
  final privateKeyOctet = derEncodeOctetString(privateKeyDer);
  final children = <Uint8List>[
    derEncodeInteger(BigInt.from(version)),
    algorithmIdentifier,
    privateKeyOctet,
  ];
  if (publicKeyBytes != null) {
    final bitString = derEncodeBitString(publicKeyBytes);
    children.add(derEncodeContextSpecific(1, bitString));
  }
  return derEncodeSequence(children);
}

String encodeEncryptedPrivateKeyPem(Uint8List privateKeyInfo, String password) {
  final encrypted = encodeEncryptedPrivateKey(privateKeyInfo, password);
  return pem(encrypted, 'ENCRYPTED PRIVATE KEY');
}

Uint8List encodeEncryptedPrivateKey(Uint8List privateKeyInfo, String password) {
  final passwordBytes = Uint8List.fromList(utf8.encode(password));
  final salt = getRandomBytes(_saltLength);
  final iv = getRandomBytes(_ivLength);
  final key = pbkdf2(passwordBytes, salt, _defaultIterations, _aes256KeySize, 'sha256');
  final padded = _pkcs7Pad(privateKeyInfo, _aesBlockSize);
  final ciphertext = _aesCbcEncrypt(key, iv, padded);

  final prfParameters = derEncodeSequence([
    derEncodeObjectIdentifier(_oidHmacWithSha256),
    derEncodeNull(),
  ]);
  final pbkdf2Params = derEncodeSequence([
    derEncodeOctetString(salt),
    derEncodeInteger(BigInt.from(_defaultIterations)),
    derEncodeInteger(BigInt.from(_aes256KeySize)),
    prfParameters,
  ]);
  final keyDerivationFunc = derEncodeSequence([
    derEncodeObjectIdentifier(_oidPbkdf2),
    pbkdf2Params,
  ]);
  final encryptionScheme = derEncodeSequence([
    derEncodeObjectIdentifier(_oidAes256Cbc),
    derEncodeOctetString(iv),
  ]);
  final pbes2Params = derEncodeSequence([
    keyDerivationFunc,
    encryptionScheme,
  ]);
  final encryptionAlgorithm = derEncodeSequence([
    derEncodeObjectIdentifier(_oidPbes2),
    pbes2Params,
  ]);
  return derEncodeSequence([
    encryptionAlgorithm,
    derEncodeOctetString(ciphertext),
  ]);
}

Uint8List decodeEncryptedPrivateKey(Uint8List encryptedInfo, String password) {
  final parser = ASN1Parser(encryptedInfo);
  final algId = parser.getChild(0);
  final encryptedData = parser.getChild(1).value;
  final algorithmOid = algId.getChild(0).value;
  if (!_encodedOidEquals(algorithmOid, _oidPbes2)) {
    throw UnsupportedError('Only PBES2 encrypted keys are supported');
  }
  final params = ASN1Parser(algId.getChildBytes(1));
  final keyDerivationFunc = ASN1Parser(params.getChildBytes(0));
  final encryptionScheme = ASN1Parser(params.getChildBytes(1));
  _validateKdf(keyDerivationFunc);
  final (salt: salt, iterations: iterations, keyLength: keyLength, prfOid: prfOid) =
      _parsePbkdf2Params(keyDerivationFunc.getChild(1));
  if (!_listEquals(prfOid, _oidHmacWithSha256)) {
    throw UnsupportedError('Only HMAC-SHA256 PBKDF2 PRF is supported');
  }
  final encSchemeOid = encryptionScheme.getChild(0).value;
  if (!_encodedOidEquals(encSchemeOid, _oidAes256Cbc)) {
    throw UnsupportedError('Only AES-256-CBC encrypted keys are supported');
  }
  final iv = encryptionScheme.getChild(1).value;
  final passwordBytes = Uint8List.fromList(utf8.encode(password));
  final key = pbkdf2(passwordBytes, salt, iterations, keyLength, 'sha256');
  final plaintext = _aesCbcDecrypt(key, iv, encryptedData);
  return _pkcs7Unpad(plaintext, _aesBlockSize);
}

void _validateKdf(ASN1Parser keyDerivationFunc) {
  final oid = keyDerivationFunc.getChild(0).value;
  if (!_encodedOidEquals(oid, _oidPbkdf2)) {
    throw UnsupportedError('Only PBKDF2 key derivation is supported');
  }
}

({Uint8List salt, int iterations, int keyLength, List<int> prfOid}) _parsePbkdf2Params(
    ASN1Parser params) {
  final salt = params.getChild(0).value;
  final iterations = bytesToNumber(params.getChild(1).value).toInt();
  var index = 2;
  var keyLength = _aes256KeySize;
  if (params.getChildCount() > index && params.getChild(index).type.tagId == 2) {
    keyLength = bytesToNumber(params.getChild(index).value).toInt();
    index += 1;
  }
  List<int> prfOid = _oidHmacWithSha256;
  if (params.getChildCount() > index) {
    final prf = ASN1Parser(params.getChildBytes(index));
    prfOid = decodeOid(prf.getChild(0).value.toList());
  }
  return (salt: salt, iterations: iterations, keyLength: keyLength, prfOid: prfOid);
}

Uint8List _pkcs7Pad(Uint8List data, int blockSize) {
  final paddingLength = blockSize - (data.length % blockSize);
  final paddingByte = paddingLength;
  final padding = Uint8List(paddingLength)..fillRange(0, paddingLength, paddingByte);
  final result = Uint8List(data.length + paddingLength)
    ..setRange(0, data.length, data)
    ..setRange(data.length, data.length + paddingLength, padding);
  return result;
}

Uint8List _pkcs7Unpad(Uint8List data, int blockSize) {
  if (data.isEmpty || data.length % blockSize != 0) {
    throw FormatException('Invalid PKCS#7 padding length');
  }
  final paddingLength = data.last;
  if (paddingLength <= 0 || paddingLength > blockSize || paddingLength > data.length) {
    throw FormatException('Invalid PKCS#7 padding value');
  }
  for (var i = data.length - paddingLength; i < data.length; i++) {
    if (data[i] != paddingLength) {
      throw FormatException('Corrupted PKCS#7 padding');
    }
  }
  return Uint8List.fromList(data.sublist(0, data.length - paddingLength));
}

bool _encodedOidEquals(Uint8List encoded, List<int> oid) {
  final decoded = decodeOid(encoded.toList());
  if (decoded.length != oid.length) {
    return false;
  }
  for (var i = 0; i < decoded.length; i++) {
    if (decoded[i] != oid[i]) {
      return false;
    }
  }
  return true;
}

Uint8List _aesCbcEncrypt(Uint8List key, Uint8List iv, Uint8List plaintext) {
  if (plaintext.length % _aesBlockSize != 0) {
    throw ArgumentError('Plaintext must be block aligned');
  }
  final cipher = CBCBlockCipher(AESEngine())
    ..init(true, ParametersWithIV(KeyParameter(key), iv));
  return _processBlocks(cipher, plaintext);
}

Uint8List _aesCbcDecrypt(Uint8List key, Uint8List iv, Uint8List ciphertext) {
  if (ciphertext.length % _aesBlockSize != 0) {
    throw ArgumentError('Ciphertext must be block aligned');
  }
  final cipher = CBCBlockCipher(AESEngine())
    ..init(false, ParametersWithIV(KeyParameter(key), iv));
  return _processBlocks(cipher, ciphertext);
}

Uint8List _processBlocks(BlockCipher cipher, Uint8List input) {
  final out = Uint8List(input.length);
  final blockSize = cipher.blockSize;
  for (var offset = 0; offset < input.length; offset += blockSize) {
    cipher.processBlock(input, offset, out, offset);
  }
  return out;
}

bool _listEquals(List<int> a, List<int> b) {
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
