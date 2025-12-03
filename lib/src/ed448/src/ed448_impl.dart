/// Ed448-Goldilocks field element and point arithmetic implementation.
///
/// Ed448 curve parameters (RFC 8032):
/// - Prime p = 2^448 - 2^224 - 1 (Goldilocks prime)
/// - Curve equation: x² + y² = 1 - 39081x²y² (Edwards form)
/// - d = -39081
/// - Base point order: n (446-bit prime)
/// - Cofactor: 4


import 'dart:typed_data';
import '../../crypto/shake256.dart' as shake;

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

/// The Goldilocks prime: p = 2^448 - 2^224 - 1
final BigInt _p = (BigInt.one << 448) - (BigInt.one << 224) - BigInt.one;

/// The Edwards curve parameter d = -39081
final BigInt _d = BigInt.from(-39081) % _p;

/// The order of the base point (subgroup order)
/// n = 2^446 - 13818066809895115352007386748515426880336692926039124900827223412438753392305
final BigInt _order = BigInt.parse(
  '181709681073901722637330951972001133588695961144550069148172289770193512315330859843'
  '68641522306865591085144654610268026812310302060879',
);

/// The cofactor h = 4
// ignore: unused_element
const int _cofactor = 4;

/// Base point x-coordinate (RFC 8032 basepoint)
final BigInt _gx = BigInt.parse(
  '4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e',
  radix: 16,
);

/// Base point y-coordinate (RFC 8032 basepoint)
final BigInt _gy = BigInt.parse(
  '693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14',
  radix: 16,
);

/// Legacy (pre-RFC) generator x-coordinate.
final BigInt _legacyGx = BigInt.parse(
  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555',
  radix: 16,
);

/// Legacy (pre-RFC) generator y-coordinate.
final BigInt _legacyGy = BigInt.parse(
  'ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed',
  radix: 16,
);

/// RFC 8032 base point.
late final Ed448Point _rfcBasePoint = Ed448Point(_gx, _gy);

/// Legacy base point used by older Goldilocks implementations.
late final Ed448Point _legacyBasePoint = Ed448Point(_legacyGx, _legacyGy);

Ed448Point _basePointFor(Ed448Generator generator) {
  return generator == Ed448Generator.rfc8032
      ? _rfcBasePoint
      : _legacyBasePoint;
}

/// Modular inverse using extended Euclidean algorithm
BigInt _modInverse(BigInt a, BigInt modulus) {
  return a.modInverse(modulus);
}

/// A point on the Ed448 curve in extended coordinates (X:Y:Z:T) where x=X/Z, y=Y/Z, xy=T/Z
class Ed448Point {
  final BigInt x;
  final BigInt y;
  final BigInt z;
  final BigInt t;

  Ed448Point(BigInt x, BigInt y)
      : x = x % _p,
        y = y % _p,
        z = BigInt.one,
        t = (x * y) % _p;

  Ed448Point.extended(this.x, this.y, this.z, this.t);

  /// The identity point (0, 1)
  factory Ed448Point.identity() {
    return Ed448Point(BigInt.zero, BigInt.one);
  }

  /// Check if this is the identity point
  bool get isIdentity {
    final xNorm = (x * _modInverse(z, _p)) % _p;
    final yNorm = (y * _modInverse(z, _p)) % _p;
    return xNorm == BigInt.zero && yNorm == BigInt.one;
  }

  /// Normalize point to affine coordinates
  Ed448Point normalize() {
    if (z == BigInt.one) return this;
    final zInv = _modInverse(z, _p);
    final xNorm = (x * zInv) % _p;
    final yNorm = (y * zInv) % _p;
    return Ed448Point(xNorm, yNorm);
  }

  /// Point addition using the unified addition formula for twisted Edwards curves
  Ed448Point operator +(Ed448Point other) {
    final x1 = x, y1 = y, z1 = z, t1 = t;
    final x2 = other.x, y2 = other.y, z2 = other.z, t2 = other.t;

    final a = (x1 * x2) % _p;
    final b = (y1 * y2) % _p;
    final c = (t1 * _d % _p * t2) % _p;
    final dVal = (z1 * z2) % _p;
    final e = ((x1 + y1) * (x2 + y2) - a - b) % _p;
    final f = (dVal - c) % _p;
    final g = (dVal + c) % _p;
    final h = (b - a) % _p;

    final x3 = (e * f) % _p;
    final y3 = (g * h) % _p;
    final t3 = (e * h) % _p;
    final z3 = (f * g) % _p;

    return Ed448Point.extended(x3, y3, z3, t3);
  }

  /// Point doubling
  Ed448Point double_() {
    final x1 = x, y1 = y, z1 = z;

    final a = (x1 * x1) % _p;
    final b = (y1 * y1) % _p;
    final c = (BigInt.two * z1 * z1) % _p;
    final h = (a + b) % _p;
    final e = (h - ((x1 + y1) * (x1 + y1) % _p)) % _p;
    final g = (a - b) % _p;
    final f = (c + g) % _p;

    final x3 = (e * f) % _p;
    final y3 = (g * h) % _p;
    final t3 = (e * h) % _p;
    final z3 = (f * g) % _p;

    return Ed448Point.extended(x3, y3, z3, t3);
  }

  /// Scalar multiplication using double-and-add
  Ed448Point operator *(BigInt scalar) {
    scalar = scalar % _order;
    if (scalar == BigInt.zero) return Ed448Point.identity();

    var result = Ed448Point.identity();
    var addend = this;

    while (scalar > BigInt.zero) {
      if (scalar.isOdd) {
        result = result + addend;
      }
      addend = addend.double_();
      scalar = scalar >> 1;
    }

    return result;
  }

  /// Negate point: -(x, y) = (-x, y)
  Ed448Point operator -() {
    return Ed448Point.extended((-x) % _p, y, z, (-t) % _p);
  }

  /// Point subtraction
  Ed448Point operator -(Ed448Point other) {
    return this + (-other);
  }

  /// Encode point to bytes (57 bytes)
  Uint8List encode() {
    final normalized = normalize();
    final yBytes = _bigIntToBytes(normalized.y, 57);
    // Set the sign bit of x in the last byte
    if (normalized.x.isOdd) {
      yBytes[56] |= 0x80;
    }
    return yBytes;
  }

  /// Decode point from bytes
  static Ed448Point? decode(Uint8List bytes) {
    if (bytes.length != 57) return null;

    // Copy bytes and extract sign bit
    final yBytes = Uint8List.fromList(bytes);
    final xSign = (yBytes[56] >> 7) & 1;
    yBytes[56] &= 0x7F;

    final y = _bytesToBigInt(yBytes);
    if (y >= _p) return null;

    // Curve equation: x² + y² = 1 + d*x²*y² (with d = -39081)
    // => 1 - y² = x² (1 - d*y²)
    // => x² = (1 - y²) / (1 - d*y²)
    final y2 = (y * y) % _p;
    final num = (BigInt.one - y2) % _p;
    final den = (BigInt.one - _d * y2) % _p;

    if (den == BigInt.zero) return null;

    final denInv = _modInverse(den, _p);
    final x2 = (num * denInv) % _p;

    // Compute square root
    var x = _modSqrt(x2, _p);
    if (x == null) return null;

    // Adjust sign
    if ((x.isOdd ? 1 : 0) != xSign) {
      x = _p - x;
    }

    return Ed448Point(x, y);
  }

  @override
  bool operator ==(Object other) {
    if (other is! Ed448Point) return false;
    final p1 = normalize();
    final p2 = other.normalize();
    return p1.x == p2.x && p1.y == p2.y;
  }

  @override
  int get hashCode => normalize().x.hashCode ^ normalize().y.hashCode;
}

/// Compute modular square root using Tonelli-Shanks
BigInt? _modSqrt(BigInt a, BigInt p) {
  a = a % p;
  if (a == BigInt.zero) return BigInt.zero;

  // Check if a is a quadratic residue
  if (a.modPow((p - BigInt.one) ~/ BigInt.two, p) != BigInt.one) {
    return null;
  }

  // For p ≡ 3 (mod 4), use simple formula
  if (p % BigInt.from(4) == BigInt.from(3)) {
    return a.modPow((p + BigInt.one) ~/ BigInt.from(4), p);
  }

  // Tonelli-Shanks algorithm
  var q = p - BigInt.one;
  var s = 0;
  while (q.isEven) {
    q = q >> 1;
    s++;
  }

  // Find a quadratic non-residue
  var z = BigInt.two;
  while (z.modPow((p - BigInt.one) ~/ BigInt.two, p) != p - BigInt.one) {
    z += BigInt.one;
  }

  var m = s;
  var c = z.modPow(q, p);
  var tt = a.modPow(q, p);
  var r = a.modPow((q + BigInt.one) ~/ BigInt.two, p);

  while (true) {
    if (tt == BigInt.zero) return BigInt.zero;
    if (tt == BigInt.one) return r;

    var i = 1;
    var temp = (tt * tt) % p;
    while (temp != BigInt.one) {
      temp = (temp * temp) % p;
      i++;
      if (i == m) return null;
    }

    var b = c;
    for (var j = 0; j < m - i - 1; j++) {
      b = (b * b) % p;
    }

    m = i;
    c = (b * b) % p;
    tt = (tt * c) % p;
    r = (r * b) % p;
  }
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

/// SHAKE256 hash function (XOF)
Uint8List _shake256(List<int> input, int outputLength) {
  return shake.shake256(input, outputLength);
}

/// Ed448 public key
class Ed448PublicKeyImpl {
  final Uint8List bytes;
  final Ed448Point _point;

  Ed448PublicKeyImpl._(this.bytes, this._point);

  factory Ed448PublicKeyImpl(Uint8List bytes) {
    if (bytes.length != publicKeySize) {
      throw ArgumentError('Ed448 public key must be $publicKeySize bytes');
    }
    final point = Ed448Point.decode(bytes);
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
    final r = Ed448Point.decode(rBytes);
    if (r == null) return false;

    // Decode S (little-endian scalar)
    final s = _bytesToBigInt(sBytes);
    if (s >= _order) return false;

    // Compute hash: H(dom4(F, C) || R || A || PH(M))
    // For Ed448 (pure): dom4(0, context) || R || A || M
    final dom4 = _computeDom4(0, context);
    final toHash = <int>[...dom4, ...rBytes, ...bytes, ...message];
    final hBytes = _shake256(toHash, 114);
    final h = _bytesToBigInt(Uint8List.fromList(hBytes)) % _order;

    // Verify: [S]B = R + [h]A for each supported base point.
    final ha = _point * h;
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
    Ed448Point basePoint,
    BigInt scalar,
    Ed448Point expected,
  ) {
    final sb = basePoint * scalar;
    return sb == expected;
  }
}

/// Ed448 private key
class Ed448PrivateKeyImpl {
  final Uint8List _seed;
  final Uint8List _publicKeyBytes;
  // ignore: unused_field
  final Ed448Point _publicPoint;
  final BigInt _scalar;
  final Ed448Generator generator;

  Ed448PrivateKeyImpl._(this._seed, this._publicKeyBytes, this._publicPoint,
      this._scalar, this.generator);

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
    // Clamp the scalar
    scalarBytes[0] &= 0xFC; // Clear bottom 2 bits
    scalarBytes[55] |= 0x80; // Set bit 447
    scalarBytes[56] = 0; // Clear top byte

    final scalar = _bytesToBigInt(scalarBytes);

    // Compute public key: A = [s]B
    final basePoint = _basePointFor(generator);
    final publicPoint = basePoint * scalar;
    final publicKeyBytes = publicPoint.encode();

    return Ed448PrivateKeyImpl._(
      Uint8List.fromList(seed),
      publicKeyBytes,
      publicPoint,
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
    final rPoint = basePoint * r;
    final rBytes = rPoint.encode();

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
  // dom4(x, y) = "SigEd448" || octet(x) || octet(OLEN(y)) || y
  const sigEd448 = [
    0x53,
    0x69,
    0x67,
    0x45,
    0x64,
    0x34,
    0x34,
    0x38
  ]; // "SigEd448"
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
  } catch (e) {
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
