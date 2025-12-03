import 'dart:typed_data';

import '../errors.dart';
import 'constanttime.dart' as ct;
import 'cryptomath.dart';
import 'der.dart';
import 'pem.dart';
import 'pkcs8.dart';
import 'tlshashlib.dart' as tlshash;

part 'python_rsakey.dart';

typedef RandomBytesGenerator = Uint8List Function(int length);

RandomBytesGenerator _rsaRandomBytes = getRandomBytes;

/// Overrides the randomness source used by RSA helpers. Intended for tests.
void overrideRsaRandomBytes(RandomBytesGenerator generator) {
  _rsaRandomBytes = generator;
}

/// Restores the default randomness generator used by RSA helpers.
void resetRsaRandomBytes() {
  _rsaRandomBytes = getRandomBytes;
}

Uint8List _toUint8List(List<int> data) =>
    data is Uint8List ? data : Uint8List.fromList(data);

int _digestSize(String algorithm) => tlshash.newHash(algorithm).digestSize;

/// Base class for RSA keys. Mirrors tlslite-ng's RSAKey API.
abstract class RSAKey {
  RSAKey({BigInt? modulus, BigInt? exponent, String keyTypeValue = 'rsa'})
      : n = modulus ?? BigInt.zero,
        e = exponent ?? BigInt.zero,
        keyType = keyTypeValue.toLowerCase();

  /// RSA modulus.
  BigInt n;

  /// RSA public exponent.
  BigInt e;

  /// Indicates supported operations ("rsa" or "rsa-pss").
  String keyType;

  Uint8List? _keyHash;

  /// Bit length of the modulus.
  int get bitLength => numBits(n);

  /// Private exponent if available. Subclasses should override.
  BigInt? get privateExponent => null;

  /// Returns whether the key includes private components.
  bool hasPrivateKey();

  Uint8List hashAndSign(
    List<int> bytes, {
    String rsaScheme = 'PKCS1',
    String hAlg = 'sha1',
    int saltLen = 0,
  }) {
    final hashBytes = secureHash(_toUint8List(bytes), hAlg);
    return sign(
      hashBytes,
      padding: rsaScheme,
      hashAlg: hAlg,
      saltLen: saltLen,
    );
  }

  bool hashAndVerify(
    List<int> sigBytes,
    List<int> bytes, {
    String rsaScheme = 'PKCS1',
    String hAlg = 'sha1',
    int saltLen = 0,
  }) {
    final hashBytes = secureHash(_toUint8List(bytes), hAlg);
    return verify(
      _toUint8List(sigBytes),
      hashBytes,
      padding: rsaScheme,
      hashAlg: hAlg,
      saltLen: saltLen,
    );
  }

  Uint8List MGF1(Uint8List mgfSeed, int maskLen, String hAlg) {
    final hashLen = _digestSize(hAlg);
    final maxMaskLen = (BigInt.one << 32) * BigInt.from(hashLen);
    if (BigInt.from(maskLen) > maxMaskLen) {
      throw MaskTooLongError('Incorrect parameter maskLen');
    }
    final builder = BytesBuilder();
    final iterations = divceil(BigInt.from(maskLen), BigInt.from(hashLen));
    for (var counter = 0; counter < iterations.toInt(); counter++) {
      final cBytes = numberToByteArray(
        BigInt.from(counter),
        howManyBytes: 4,
      );
      final input = BytesBuilder()
        ..add(mgfSeed)
        ..add(cBytes);
      builder.add(secureHash(input.toBytes(), hAlg));
    }
    final mask = builder.toBytes();
    return Uint8List.fromList(mask.sublist(0, maskLen));
  }

  Uint8List EMSA_PSS_encode(
    Uint8List mHash,
    int emBits,
    String hAlg, {
    int saltLen = 0,
  }) {
    final hashLen = _digestSize(hAlg);
    final emLen = divceil(BigInt.from(emBits), BigInt.from(8)).toInt();
    if (emLen < hashLen + saltLen + 2) {
      throw EncodingError('Encoded message length too short');
    }
    final salt = saltLen == 0 ? Uint8List(0) : _rsaRandomBytes(saltLen);
    final m2 = BytesBuilder()
      ..add(Uint8List(8))
      ..add(mHash)
      ..add(salt);
    final h = secureHash(m2.toBytes(), hAlg);
    final ps = Uint8List(emLen - saltLen - hashLen - 2);
    final db = BytesBuilder()
      ..add(ps)
      ..addByte(0x01)
      ..add(salt);
    final dbMask = MGF1(h, emLen - hashLen - 1, hAlg);
    final maskedDb = Uint8List(db.length);
    final dbBytes = db.toBytes();
    for (var i = 0; i < maskedDb.length; i++) {
      maskedDb[i] = dbBytes[i] ^ dbMask[i];
    }
    final mLen = emLen * 8 - emBits;
    final mask = (1 << (8 - mLen)) - 1;
    maskedDb[0] &= mask;
    final builder = BytesBuilder()
      ..add(maskedDb)
      ..add(h)
      ..addByte(0xbc);
    return builder.toBytes();
  }

  Uint8List RSASSA_PSS_sign(
    Uint8List mHash,
    String hAlg, {
    int saltLen = 0,
  }) {
    final em = EMSA_PSS_encode(
      mHash,
      numBits(n) - 1,
      hAlg,
      saltLen: saltLen,
    );
    try {
      return _raw_private_key_op_bytes(em);
    } on ArgumentError {
      throw MessageTooLongError('Encode output too long');
    }
  }

  bool EMSA_PSS_verify(
    Uint8List mHash,
    Uint8List EM,
    int emBits,
    String hAlg, {
    int saltLen = 0,
  }) {
    final hashLen = _digestSize(hAlg);
    final emLen = divceil(BigInt.from(emBits), BigInt.from(8)).toInt();
    if (emLen < hashLen + saltLen + 2) {
      throw InvalidSignature('Invalid signature');
    }
    if (EM.isEmpty || EM.last != 0xbc) {
      throw InvalidSignature('Invalid signature');
    }
    final maskedDB = EM.sublist(0, emLen - hashLen - 1);
    final h = EM.sublist(emLen - hashLen - 1, emLen - 1);
    var dbHelpMask = 1 << (8 - ((8 * emLen) - emBits));
    dbHelpMask = (~(dbHelpMask - 1)) & 0xff;
    if ((maskedDB[0] & dbHelpMask) != 0) {
      throw InvalidSignature('Invalid signature');
    }
    final dbMask = MGF1(h, emLen - hashLen - 1, hAlg);
    final db = Uint8List(maskedDB.length);
    for (var i = 0; i < maskedDB.length; i++) {
      db[i] = maskedDB[i] ^ dbMask[i];
    }
    final mLen = emLen * 8 - emBits;
    final mask = (1 << (8 - mLen)) - 1;
    db[0] &= mask;
    final zeroCount = emLen - hashLen - saltLen - 2;
    for (var i = 0; i < zeroCount; i++) {
      if (db[i] != 0) {
        throw InvalidSignature('Invalid signature');
      }
    }
    if (db[zeroCount] != 0x01) {
      throw InvalidSignature('Invalid signature');
    }
    final salt = saltLen == 0 ? Uint8List(0) : db.sublist(db.length - saltLen);
    final newM = BytesBuilder()
      ..add(Uint8List(8))
      ..add(mHash)
      ..add(salt);
    final newH = secureHash(newM.toBytes(), hAlg);
    if (!_listsEqual(h, newH)) {
      throw InvalidSignature('Invalid signature');
    }
    return true;
  }

  bool RSASSA_PSS_verify(
    Uint8List mHash,
    Uint8List signature,
    String hAlg, {
    int saltLen = 0,
  }) {
    late Uint8List em;
    try {
      em = _raw_public_key_op_bytes(signature);
    } on ArgumentError {
      throw InvalidSignature('Invalid signature');
    }
    final result = EMSA_PSS_verify(
      mHash,
      em,
      numBits(n) - 1,
      hAlg,
      saltLen: saltLen,
    );
    if (result) {
      return true;
    }
    throw InvalidSignature('Invalid signature');
  }

  Uint8List _raw_pkcs1_sign(Uint8List bytes) {
    if (!hasPrivateKey()) {
      throw AssertionError('Private key required');
    }
    final padded = _addPKCS1Padding(bytes, 1);
    return _raw_private_key_op_bytes(padded);
  }

  Uint8List sign(
    Uint8List bytes, {
    String padding = 'pkcs1',
    String? hashAlg,
    int saltLen = 0,
  }) {
    final mode = padding.toLowerCase();
    if (mode == 'pkcs1') {
      final payload = hashAlg != null ? addPKCS1Prefix(bytes, hashAlg) : bytes;
      return _raw_pkcs1_sign(payload);
    } else if (mode == 'pss') {
      if (hashAlg == null) {
        throw ArgumentError('hashAlg is required for PSS signatures');
      }
      return RSASSA_PSS_sign(bytes, hashAlg, saltLen: saltLen);
    } else {
      throw UnknownRSAType('Unknown RSA algorithm type: $padding');
    }
  }

  bool _raw_pkcs1_verify(Uint8List sigBytes, Uint8List bytes) {
    try {
      final check = _raw_public_key_op_bytes(sigBytes);
      final padded = _addPKCS1Padding(bytes, 1);
      return _listsEqual(check, padded);
    } on ArgumentError {
      return false;
    }
  }

  bool verify(
    Uint8List sigBytes,
    Uint8List bytes, {
    String padding = 'pkcs1',
    String? hashAlg,
    int saltLen = 0,
  }) {
    final mode = padding.toLowerCase();
    if (mode == 'pkcs1' && keyType == 'rsa-pss') {
      return false;
    }
    if (mode == 'pkcs1' && (hashAlg?.toLowerCase() == 'sha1')) {
      final prefixed1 = addPKCS1SHA1Prefix(bytes, withNull: false);
      final prefixed2 = addPKCS1SHA1Prefix(bytes, withNull: true);
      return _raw_pkcs1_verify(sigBytes, prefixed1) ||
          _raw_pkcs1_verify(sigBytes, prefixed2);
    } else if (mode == 'pkcs1') {
      final payload = hashAlg != null ? addPKCS1Prefix(bytes, hashAlg) : bytes;
      return _raw_pkcs1_verify(sigBytes, payload);
    } else if (mode == 'pss') {
      if (hashAlg == null) {
        throw ArgumentError('hashAlg is required for PSS verification');
      }
      try {
        return RSASSA_PSS_verify(bytes, sigBytes, hashAlg, saltLen: saltLen);
      } on InvalidSignature {
        return false;
      }
    }
    throw UnknownRSAType('Unknown RSA algorithm type: $padding');
  }

  Uint8List encrypt(Uint8List bytes) {
    final padded = _addPKCS1Padding(bytes, 2);
    return _raw_public_key_op_bytes(padded);
  }

  Uint8List _decPrf(Uint8List key, Uint8List label, int outLenBits) {
    if (outLenBits % 8 != 0) {
      throw ArgumentError('only multiples of 8 supported as output size');
    }
    final out = BytesBuilder();
    var iterator = 0;
    final targetLen = outLenBits ~/ 8;
    while (out.length < targetLen) {
      final data = BytesBuilder()
        ..add(numberToByteArray(BigInt.from(iterator), howManyBytes: 2))
        ..add(label)
        ..add(numberToByteArray(BigInt.from(outLenBits), howManyBytes: 2));
      out.add(secureHMAC(key, data.toBytes(), 'sha256'));
      iterator += 1;
    }
    final outBytes = out.toBytes();
    return Uint8List.fromList(outBytes.sublist(0, targetLen));
  }

  Uint8List? decrypt(Uint8List encBytes) {
    if (!hasPrivateKey()) {
      throw AssertionError('Private key required');
    }
    if (keyType != 'rsa') {
      throw ArgumentError('Decryption requires RSA key, "$keyType" present');
    }
    Uint8List decBytes;
    try {
      decBytes = _raw_private_key_op_bytes(encBytes);
    } on ArgumentError {
      return null;
    }
    final maxSepOffset = numBytes(n) - 10;
    final priv = privateExponent;
    if (priv == null) {
      throw StateError('Private exponent missing');
    }
    _keyHash ??= secureHash(
        numberToByteArray(priv, howManyBytes: numBytes(n)), 'sha256');
    final kdk = secureHMAC(_keyHash!, encBytes, 'sha256');
    final lengthRandoms =
        _decPrf(kdk, Uint8List.fromList('length'.codeUnits), 128 * 2 * 8);
    final messageRandom =
        _decPrf(kdk, Uint8List.fromList('message'.codeUnits), numBytes(n) * 8);

    var synthLength = 0;
    final lengthMask = (1 << numBits(BigInt.from(maxSepOffset))) - 1;
    for (var i = 0; i < lengthRandoms.length; i += 2) {
      if (i + 1 >= lengthRandoms.length) break;
      var candidate =
          ((lengthRandoms[i] << 8) + lengthRandoms[i + 1]) & lengthMask;
      final mask =
          ct.ctLsbPropU16(ct.ctLtU32(candidate, maxSepOffset)) & 0xffff;
      synthLength = (synthLength & (0xffff ^ mask)) | (candidate & mask);
    }
    final synthMsgStart = numBytes(n) - synthLength;

    var errorDetected = 0;
    final length = decBytes.length;
    if (length < 2) {
      return null;
    }
    errorDetected |= ct.ctIsNonZeroU32(decBytes[0]);
    errorDetected |= ct.ctNeqU32(decBytes[1], 0x02);
    var msgStart = 0;
    for (var pos = 2; pos < length; pos++) {
      final val = decBytes[pos];
      errorDetected |= ct.ctLtU32(pos, 10) & (1 ^ ct.ctIsNonZeroU32(val));
      var mask = (1 ^ ct.ctLtU32(pos, 10)) &
          (1 ^ ct.ctIsNonZeroU32(val)) &
          (1 ^ ct.ctIsNonZeroU32(msgStart));
      mask = ct.ctLsbPropU16(mask);
      msgStart = (msgStart & (0xffff ^ mask)) | ((pos + 1) & mask);
    }
    errorDetected |= 1 ^ ct.ctIsNonZeroU32(msgStart);
    final mask = ct.ctLsbPropU16(errorDetected);
    final retMsgStart = (msgStart & (0xffff ^ mask)) | (synthMsgStart & mask);

    final mask8 = ct.ctLsbPropU8(errorDetected);
    final notMask = 0xff ^ mask8;
    final result = List<int>.generate(
      length - retMsgStart,
      (index) {
        final real = decBytes[retMsgStart + index];
        final synth = messageRandom[retMsgStart + index];
        return (real & notMask) | (synth & mask8);
      },
    );
    return Uint8List.fromList(result);
  }

  BigInt _rawPrivateKeyOp(BigInt message);

  BigInt _rawPublicKeyOp(BigInt ciphertext);

  Uint8List _raw_private_key_op_bytes(Uint8List message) {
    final expectedLen = numBytes(n);
    if (message.length != expectedLen) {
      throw ArgumentError('Message has incorrect length for the key size');
    }
    final mInt = bytesToNumber(message);
    if (mInt >= n) {
      throw ArgumentError('Provided message value exceeds modulus');
    }
    final decInt = _rawPrivateKeyOp(mInt);
    return numberToByteArray(decInt, howManyBytes: expectedLen);
  }

  Uint8List _raw_public_key_op_bytes(Uint8List ciphertext) {
    final expectedLen = numBytes(n);
    if (ciphertext.length != expectedLen) {
      throw ArgumentError('Message has incorrect length for the key size');
    }
    final cInt = bytesToNumber(ciphertext);
    if (cInt >= n) {
      throw ArgumentError('Provided message value exceeds modulus');
    }
    final encInt = _rawPublicKeyOp(cInt);
    return numberToByteArray(encInt, howManyBytes: expectedLen);
  }

  bool acceptsPassword();

  String write({String? password});

  static RSAKey generate(int bits, {String keyType = 'rsa'}) {
    if (bits < 512) {
      throw ArgumentError('RSA keys smaller than 512 bits are insecure');
    }
    return PythonRSAKey.generate(bits, keyType: keyType);
  }

  Uint8List _addPKCS1Padding(Uint8List bytes, int blockType) {
    final padLength = numBytes(n) - (bytes.length + 3);
    if (padLength < 0) {
      throw MessageTooLongError('Data too large for key size');
    }
    Uint8List pad;
    if (blockType == 1) {
      pad = Uint8List.fromList(List<int>.filled(padLength, 0xff));
    } else if (blockType == 2) {
      final tmp = <int>[];
      while (tmp.length < padLength) {
        final chunk = _rsaRandomBytes(padLength * 2);
        for (final b in chunk) {
          if (b != 0) {
            tmp.add(b);
            if (tmp.length == padLength) {
              break;
            }
          }
        }
      }
      pad = Uint8List.fromList(tmp);
    } else {
      throw AssertionError('Unsupported block type $blockType');
    }
    final builder = BytesBuilder()
      ..addByte(0x00)
      ..addByte(blockType)
      ..add(pad)
      ..addByte(0x00)
      ..add(bytes);
    return builder.toBytes();
  }

  static Uint8List addPKCS1SHA1Prefix(Uint8List hashBytes,
      {bool withNull = true}) {
    if (!withNull) {
      return Uint8List.fromList([
        0x30,
        0x1f,
        0x30,
        0x07,
        0x06,
        0x05,
        0x2b,
        0x0e,
        0x03,
        0x02,
        0x1a,
        0x04,
        0x14,
        ...hashBytes,
      ]);
    }
    final prefix = _pkcs1Prefixes['sha1']!;
    return Uint8List.fromList([...prefix, ...hashBytes]);
  }

  static Uint8List addPKCS1Prefix(Uint8List data, String hashName) {
    final prefix = _pkcs1Prefixes[hashName.toLowerCase()];
    if (prefix == null) {
      throw ArgumentError('Unsupported hash: $hashName');
    }
    return Uint8List.fromList([...prefix, ...data]);
  }

  static final Map<String, List<int>> _pkcs1Prefixes = {
    'md5': [
      0x30,
      0x20,
      0x30,
      0x0c,
      0x06,
      0x08,
      0x2a,
      0x86,
      0x48,
      0x86,
      0xf7,
      0x0d,
      0x02,
      0x05,
      0x05,
      0x00,
      0x04,
      0x10,
    ],
    'sha1': [
      0x30,
      0x21,
      0x30,
      0x09,
      0x06,
      0x05,
      0x2b,
      0x0e,
      0x03,
      0x02,
      0x1a,
      0x05,
      0x00,
      0x04,
      0x14,
    ],
    'sha224': [
      0x30,
      0x2d,
      0x30,
      0x0d,
      0x06,
      0x09,
      0x60,
      0x86,
      0x48,
      0x01,
      0x65,
      0x03,
      0x04,
      0x02,
      0x04,
      0x05,
      0x00,
      0x04,
      0x1c,
    ],
    'sha256': [
      0x30,
      0x31,
      0x30,
      0x0d,
      0x06,
      0x09,
      0x60,
      0x86,
      0x48,
      0x01,
      0x65,
      0x03,
      0x04,
      0x02,
      0x01,
      0x05,
      0x00,
      0x04,
      0x20,
    ],
    'sha384': [
      0x30,
      0x41,
      0x30,
      0x0d,
      0x06,
      0x09,
      0x60,
      0x86,
      0x48,
      0x01,
      0x65,
      0x03,
      0x04,
      0x02,
      0x02,
      0x05,
      0x00,
      0x04,
      0x30,
    ],
    'sha512': [
      0x30,
      0x51,
      0x30,
      0x0d,
      0x06,
      0x09,
      0x60,
      0x86,
      0x48,
      0x01,
      0x65,
      0x03,
      0x04,
      0x02,
      0x03,
      0x05,
      0x00,
      0x04,
      0x40,
    ],
  };
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
