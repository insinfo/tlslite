/// Ed448-Goldilocks implementation for Dart.
///
/// This layer provides a high level signing/verifying API while delegating all
/// curve/field arithmetic to the optimized fp448/scalar448 primitives.
library ed448;

import 'dart:typed_data';

import '../../crypto/shake256.dart' as shake;
import 'ed448_point.dart' as curve;
import 'fp448.dart' as fp;
import 'scalar448.dart';

/// Selects which base point to use for Ed448 operations.
enum Ed448Generator { rfc8032, legacy }

/// Size of Ed448 public keys in bytes (57 bytes = 456 bits / 8 + 1 sign bit).
const int publicKeySize = 57;

/// Size of Ed448 private keys in bytes (full expanded key).
const int privateKeySize = 114;

/// Size of Ed448 signatures in bytes.
const int signatureSize = 114;

/// Size of Ed448 seed (secret scalar input) in bytes.
const int seedSize = 57;

/// Edwards curve parameter d = -39081 encoded as affine coordinates.
const String _legacyXHex =
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555';
const String _legacyYHex =
    'ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed';
const String _rfcXHex =
    '4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e';
const String _rfcYHex =
    '693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14';

/// RFC 8032 base point.
late final curve.Ed448Point _rfcBasePoint = _pointFromHex(_rfcXHex, _rfcYHex);

/// Legacy base point used by older Goldilocks implementations.
late final curve.Ed448Point _legacyBasePoint =
    _pointFromHex(_legacyXHex, _legacyYHex);

curve.Ed448Point _basePointFor(Ed448Generator generator) {
  return generator == Ed448Generator.rfc8032
      ? _rfcBasePoint
      : _legacyBasePoint;
}

/// The order of the prime-order subgroup (RFC 8032, section 4).
late final BigInt _order = _scalarToBigInt(Scalar448.order);

Uint8List _hexToBytes(String hex) {
  final cleaned = hex.replaceAll(RegExp(r"\s"), '');
  final result = Uint8List(cleaned.length ~/ 2);
  for (var i = 0; i < cleaned.length; i += 2) {
    result[i >> 1] = int.parse(cleaned.substring(i, i + 2), radix: 16);
  }
  return result;
}

Uint32List _hexToField(String hex) {
  final bytes = _hexToBytes(hex);
  if (bytes.length != 56) {
    throw ArgumentError('Field elements must be 56 bytes, got ${bytes.length}');
  }
  final little = Uint8List(56);
  for (var i = 0; i < 56; i++) {
    little[i] = bytes[55 - i];
  }
  return fp.Fp448.decode(little);
}

curve.Ed448Point _pointFromHex(String xHex, String yHex) {
  final x = _hexToField(xHex);
  final y = _hexToField(yHex);
  return curve.Ed448Point.fromAffine(x, y);
}

Scalar448 _scalarFromBigInt(BigInt value) {
  final normalized = value % _order;
  final bytes = _bigIntToBytes(normalized, 56);
  return Scalar448.fromBytes(bytes);
}

BigInt _scalarToBigInt(Scalar448 scalar) {
  final bytes = scalar.toBytesRfc8032();
  return _bytesToBigInt(bytes);
}

/// SHAKE256 hash function (XOF)
Uint8List _shake256(List<int> input, int outputLength) {
  return shake.shake256(input, outputLength);
}

/// Ed448 public key
class Ed448PublicKeyImpl {
  final Uint8List bytes;
  final curve.Ed448Point _point;

  Ed448PublicKeyImpl._(this.bytes, this._point);

  factory Ed448PublicKeyImpl(Uint8List bytes) {
    if (bytes.length != publicKeySize) {
      throw ArgumentError('Ed448 public key must be $publicKeySize bytes');
    }
    final point = curve.Ed448Point.decompress(bytes);
    if (point == null) {
      throw ArgumentError('Invalid Ed448 public key encoding');
    }
    return Ed448PublicKeyImpl._(Uint8List.fromList(bytes), point);
  }

  /// Verify a signature.
  ///
  /// By default the verifier first tries the RFC 8032 base point and, if that
  /// fails, retries with the legacy base point that older Goldilocks ports
  /// used. Set [enableLegacyFallback] to false to enforce RFC-only semantics.
  bool verify(
    Uint8List message,
    Uint8List signature, {
    Uint8List? context,
    bool enableLegacyFallback = true,
  }) {
    if (signature.length != signatureSize) return false;

    context ??= Uint8List(0);
    if (context.length > 255) return false;

    // Split signature into R and S
    final rBytes = signature.sublist(0, 57);
    final sBytes = signature.sublist(57, 114);

    // Decode R
    final r = curve.Ed448Point.decompress(rBytes);
    if (r == null) return false;

    // Decode S (little-endian scalar)
    final s = _bytesToBigInt(Uint8List.fromList(sBytes));
    if (s >= _order) return false;

    // Compute hash: H(dom4(F, C) || R || A || M)
    final dom4 = _computeDom4(0, context);
    final toHash = <int>[...dom4, ...rBytes, ...bytes, ...message];
    final hBytes = _shake256(toHash, 114);
    final h = _bytesToBigInt(Uint8List.fromList(hBytes)) % _order;

    // Verify: [S]B = R + [h]A for each supported base point.
    final ha = _point.scalarMul(_scalarFromBigInt(h));
    final rPlusHa = r + ha;

    if (_matchesEquation(_rfcBasePoint, s, rPlusHa)) {
      return true;
    }
    if (!enableLegacyFallback) {
      return false;
    }
    return _matchesEquation(_legacyBasePoint, s, rPlusHa);
  }

  bool _matchesEquation(
    curve.Ed448Point basePoint,
    BigInt scalar,
    curve.Ed448Point expected,
  ) {
    final sb = basePoint.scalarMul(_scalarFromBigInt(scalar));
    return sb == expected;
  }
}

/// Ed448 private key
class Ed448PrivateKeyImpl {
  final Uint8List _seed;
  final Uint8List _publicKeyBytes;
  final BigInt _scalar;
  final Ed448Generator generator;

  Ed448PrivateKeyImpl._(
      this._seed, this._publicKeyBytes, this._scalar, this.generator);

  factory Ed448PrivateKeyImpl.fromSeed(
    Uint8List seed, {
    Ed448Generator generator = Ed448Generator.rfc8032,
  }) {
    if (seed.length != seedSize) {
      throw ArgumentError('Ed448 seed must be $seedSize bytes');
    }

    // Hash the seed with SHAKE256 to get 114 bytes
    final h = _shake256([...seed], 114);

    // First 57 bytes become the scalar (after clamping)
    final scalarBytes = Uint8List.fromList(h.sublist(0, 57));
    scalarBytes[0] &= 0xFC; // Clear bottom 2 bits
    scalarBytes[55] |= 0x80; // Set bit 447
    scalarBytes[56] = 0; // Clear top byte

    final scalar = _bytesToBigInt(scalarBytes);

    // Compute public key: A = [s]B
    final basePoint = _basePointFor(generator);
    final publicPoint = basePoint.scalarMul(_scalarFromBigInt(scalar));
    final publicKeyBytes = publicPoint.compress();

    return Ed448PrivateKeyImpl._(
      Uint8List.fromList(seed),
      publicKeyBytes,
      scalar,
      generator,
    );
  }

  /// Get the public key bytes
  Uint8List get publicKeyBytes => Uint8List.fromList(_publicKeyBytes);

  /// Get the public key
  Ed448PublicKeyImpl get publicKey => Ed448PublicKeyImpl(_publicKeyBytes);

  /// Sign a message
  Uint8List sign(Uint8List message, {Uint8List? context}) {
    context ??= Uint8List(0);
    if (context.length > 255) {
      throw ArgumentError('Context must be at most 255 bytes');
    }

    // Hash the seed to get prefix (second 57 bytes of hash)
    final h = _shake256([..._seed], 114);
    final prefix = h.sublist(57, 114);

    // Compute r = H(dom4(F, C) || prefix || M) mod L
    final dom4 = _computeDom4(0, context);
    final rHash = _shake256([...dom4, ...prefix, ...message], 114);
    final r = _bytesToBigInt(Uint8List.fromList(rHash)) % _order;

    // Compute R = [r]B
    final basePoint = _basePointFor(generator);
    final rPoint = basePoint.scalarMul(_scalarFromBigInt(r));
    final rBytes = rPoint.compress();

    // Compute k = H(dom4(F, C) || R || A || M) mod L
    final kHash =
        _shake256([...dom4, ...rBytes, ..._publicKeyBytes, ...message], 114);
    final k = _bytesToBigInt(Uint8List.fromList(kHash)) % _order;

    // Compute S = (r + k * s) mod L
    final s = (r + k * _scalar) % _order;
    final sBytes = _bigIntToBytes(s, 57);

    // Signature is R || S
    return Uint8List.fromList([...rBytes, ...sBytes]);
  }
}

/// Compute dom4 prefix for Ed448
List<int> _computeDom4(int flag, Uint8List context) {
  const sigEd448 = [0x53, 0x69, 0x67, 0x45, 0x64, 0x34, 0x34, 0x38];
  return [...sigEd448, flag, context.length, ...context];
}

/// Generate a new Ed448 key pair
Ed448PrivateKeyImpl generateEd448KeyPair(
  Uint8List seed, {
  Ed448Generator generator = Ed448Generator.rfc8032,
}) {
  return Ed448PrivateKeyImpl.fromSeed(seed, generator: generator);
}

/// Verify an Ed448 signature
bool verifyEd448(Uint8List publicKey, Uint8List message, Uint8List signature,
    {Uint8List? context, bool enableLegacyFallback = true}) {
  try {
    final pk = Ed448PublicKeyImpl(publicKey);
    return pk.verify(
      message,
      signature,
      context: context,
      enableLegacyFallback: enableLegacyFallback,
    );
  } catch (_) {
    return false;
  }
}

/// Sign a message with Ed448
Uint8List signEd448(
  Uint8List seed,
  Uint8List message, {
  Uint8List? context,
  Ed448Generator generator = Ed448Generator.rfc8032,
}) {
  final sk = Ed448PrivateKeyImpl.fromSeed(seed, generator: generator);
  return sk.sign(message, context: context);
}

/// Convert BigInt to little-endian bytes
Uint8List _bigIntToBytes(BigInt value, int length) {
  final result = Uint8List(length);
  var temp = value;
  for (var i = 0; i < length; i++) {
    result[i] = (temp & BigInt.from(0xFF)).toInt();
    temp = temp >> 8;
  }
  return result;
}

/// Convert little-endian bytes to BigInt
BigInt _bytesToBigInt(Uint8List bytes) {
  var result = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}
