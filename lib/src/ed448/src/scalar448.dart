

import 'dart:typed_data';

/// Scalar for Ed448 (element of the prime-order subgroup).
/// Represented as 14 saturated 32-bit limbs.
/// Order n = 2^446 - 13818066809895115352007386748515426880336692926039124900827223412438753392305
class Scalar448 {
  final Uint32List limbs;

  Scalar448(this.limbs) {
    assert(limbs.length == 14);
  }

  factory Scalar448.zero() => Scalar448(Uint32List(14));

  factory Scalar448.one() {
    final limbs = Uint32List(14);
    limbs[0] = 1;
    return Scalar448(limbs);
  }

  factory Scalar448.fromInt(int value) {
    final limbs = Uint32List(14);
    limbs[0] = value & 0xFFFFFFFF;
    return Scalar448(limbs);
  }

  /// The order of the Ed448 base point
  static final Scalar448 order = Scalar448(Uint32List.fromList([
    0xab5844f3,
    0x2378c292,
    0x8dc58f55,
    0x216cc272,
    0xaed63690,
    0xc44edb49,
    0x7cca23e9,
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0xffffffff,
    0x3fffffff,
  ]));

  /// Montgomery R^2 for reduction
  static final Scalar448 _r2 = Scalar448(Uint32List.fromList([
    0x049b9b60,
    0xe3539257,
    0xc1b195d9,
    0x7af32c4b,
    0x88ea1859,
    0x0d66de23,
    0x5ee4d838,
    0xae17cf72,
    0xa3c47c44,
    0x1a9cc14b,
    0xe4d070af,
    0x2052bcb7,
    0xf823b729,
    0x3402a939,
  ]));

  /// Montgomery factor
  static const int _montgomeryFactor = 0xae918bc5;

  int operator [](int i) => limbs[i];
  void operator []=(int i, int v) => limbs[i] = v;

  Scalar448 clone() => Scalar448(Uint32List.fromList(limbs));

  /// Add two scalars
  Scalar448 operator +(Scalar448 other) {
    final result = Scalar448.zero();
    var chain = 0;

    for (var i = 0; i < 14; i++) {
      chain += limbs[i] + other.limbs[i];
      result.limbs[i] = chain & 0xFFFFFFFF;
      chain >>>= 32;
    }

    return _subExtra(result, order, chain);
  }

  /// Subtract two scalars
  Scalar448 operator -(Scalar448 other) {
    return _subExtra(this, other, 0);
  }

  /// Multiply two scalars
  Scalar448 operator *(Scalar448 other) {
    final unreduced = _montgomeryMultiply(this, other);
    return _montgomeryMultiply(unreduced, _r2);
  }

  /// Negate a scalar
  Scalar448 negate() => Scalar448.zero() - this;

  /// Halve a scalar
  Scalar448 halve() {
    final result = Scalar448.zero();
    final mask = (0 - (limbs[0] & 1)) & 0xFFFFFFFF;
    var chain = 0;

    for (var i = 0; i < 14; i++) {
      chain += limbs[i] + (order.limbs[i] & mask);
      result.limbs[i] = chain & 0xFFFFFFFF;
      chain >>>= 32;
    }

    for (var i = 0; i < 13; i++) {
      result.limbs[i] =
          ((result.limbs[i] >>> 1) | (result.limbs[i + 1] << 31)) & 0xFFFFFFFF;
    }
    result.limbs[13] = ((result.limbs[13] >>> 1) | (chain << 31)) & 0xFFFFFFFF;

    return result;
  }

  /// Divide by four (used in isogeny)
  void divByFour() {
    for (var i = 0; i <= 12; i++) {
      limbs[i] = ((limbs[i + 1] << 30) | (limbs[i] >>> 2)) & 0xFFFFFFFF;
    }
    limbs[13] >>>= 2;
  }

  /// Square a scalar
  Scalar448 square() => _montgomeryMultiply(this, this);

  /// Invert a scalar (modular inverse)
  Scalar448 invert() {
    const scalarWindowBits = 3;
    const last = (1 << scalarWindowBits) - 1;

    final preComp = List<Scalar448>.generate(8, (_) => Scalar448.zero());
    var result = Scalar448.zero();

    // Precompute [a^1, a^3, ...]
    preComp[0] = _montgomeryMultiply(this, _r2);

    if (last > 0) {
      preComp[last] = _montgomeryMultiply(preComp[0], preComp[0]);
    }

    for (var i = 1; i <= last; i++) {
      preComp[i] = _montgomeryMultiply(preComp[i - 1], preComp[last]);
    }

    // Sliding window
    var residue = 0;
    var trailing = 0;
    var started = 0;

    for (var i = 446 - 1; i >= -scalarWindowBits; i--) {
      if (started != 0) {
        result = result.square();
      }

      int w;
      if (i >= 0) {
        w = order.limbs[i ~/ 32];
      } else {
        w = 0;
      }

      if (i >= 0 && i < 32) {
        w -= 2;
      }

      residue = ((residue << 1) | ((w >>> (i % 32)) & 1)) & 0xFFFFFFFF;
      if (residue >>> scalarWindowBits != 0) {
        trailing = residue;
        residue = 0;
      }

      if (trailing > 0 && (trailing & ((1 << scalarWindowBits) - 1)) == 0) {
        if (started != 0) {
          result = _montgomeryMultiply(
              result, preComp[trailing >>> (scalarWindowBits + 1)]);
        } else {
          result = preComp[trailing >>> (scalarWindowBits + 1)];
          started = 1;
        }
        trailing = 0;
      }
      trailing <<= 1;
    }

    // De-montgomerize
    return _montgomeryMultiply(result, Scalar448.one());
  }

  /// Convert to bytes (56 bytes, little-endian)
  Uint8List toBytes() {
    final result = Uint8List(56);
    for (var i = 0; i < 14; i++) {
      var l = limbs[i];
      for (var j = 0; j < 4; j++) {
        result[4 * i + j] = l & 0xFF;
        l >>>= 8;
      }
    }
    return result;
  }

  /// Convert to bytes per RFC 8032 (57 bytes)
  Uint8List toBytesRfc8032() {
    final bytes = toBytes();
    final result = Uint8List(57);
    result.setRange(0, 56, bytes);
    return result;
  }

  /// Create from bytes (56 bytes, little-endian)
  factory Scalar448.fromBytes(Uint8List bytes) {
    assert(bytes.length >= 56);
    final result = Scalar448.zero();
    for (var i = 0; i < 14; i++) {
      result.limbs[i] = bytes[4 * i] |
          (bytes[4 * i + 1] << 8) |
          (bytes[4 * i + 2] << 16) |
          (bytes[4 * i + 3] << 24);
    }
    return result;
  }

  /// Create from bytes with wide reduction (114 bytes)
  factory Scalar448.fromBytesModOrderWide(Uint8List input) {
    assert(input.length >= 114);

    // Montgomery R
    final r = Scalar448(Uint32List.fromList([
      0x529eec34,
      0x721cf5b5,
      0xc8e9c2ab,
      0x7a4cf635,
      0x44a725bf,
      0xeec492d9,
      0xcd77058,
      0x2,
      0,
      0,
      0,
      0,
      0,
      0,
    ]));

    // Low 56 bytes
    final loBytes = Uint8List(56);
    loBytes.setRange(0, 56, input);
    var lo = Scalar448.fromBytes(loBytes);
    lo = _montgomeryMultiply(lo, r);

    // High 56 bytes
    final hiBytes = Uint8List(56);
    hiBytes.setRange(0, 56, input.sublist(56));
    var hi = Scalar448.fromBytes(hiBytes);
    hi = _montgomeryMultiply(hi, _r2);

    // Top 2 bytes
    final topBytes = Uint8List(56);
    topBytes[0] = input[112];
    topBytes[1] = input[113];
    var top = Scalar448.fromBytes(topBytes);
    top = _montgomeryMultiply(top, _r2);
    top = _montgomeryMultiply(top, _r2);

    return lo + hi + top;
  }

  /// Check if scalar is zero
  bool get isZero {
    var acc = 0;
    for (var i = 0; i < 14; i++) {
      acc |= limbs[i];
    }
    return acc == 0;
  }

  @override
  bool operator ==(Object other) {
    if (other is! Scalar448) return false;
    final a = toBytes();
    final b = other.toBytes();
    var diff = 0;
    for (var i = 0; i < 56; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  @override
  int get hashCode => Object.hashAll(limbs);

  /// Subtract with extra carry
  static Scalar448 _subExtra(Scalar448 a, Scalar448 b, int carry) {
    final result = Scalar448.zero();

    // a - b
    var chain = 0;
    for (var i = 0; i < 14; i++) {
      chain += a.limbs[i] - b.limbs[i];
      result.limbs[i] = chain & 0xFFFFFFFF;
      chain >>= 32;
      // Sign extend for negative numbers
      if (chain < 0) chain = chain | ~0xFFFFFFFF;
    }

    // Conditional add modulus if result was negative
    final borrow = (chain + carry) & 0xFFFFFFFF;
    final mask = (borrow >> 31) != 0 ? 0xFFFFFFFF : 0;

    chain = 0;
    for (var i = 0; i < 14; i++) {
      chain += result.limbs[i] + (order.limbs[i] & mask);
      result.limbs[i] = chain & 0xFFFFFFFF;
      chain >>>= 32;
    }

    return result;
  }

  /// Montgomery multiplication
  static Scalar448 _montgomeryMultiply(Scalar448 x, Scalar448 y) {
    final result = Scalar448.zero();
    var carry = 0;

    for (var i = 0; i < 14; i++) {
      var chain = 0;
      for (var j = 0; j < 14; j++) {
        chain += x.limbs[i] * y.limbs[j] + result.limbs[j];
        result.limbs[j] = chain & 0xFFFFFFFF;
        chain >>>= 32;
      }

      final saved = chain & 0xFFFFFFFF;
      final multiplicand = (result.limbs[0] * _montgomeryFactor) & 0xFFFFFFFF;
      chain = 0;

      for (var j = 0; j < 14; j++) {
        chain += multiplicand * order.limbs[j] + result.limbs[j];
        if (j > 0) {
          result.limbs[j - 1] = chain & 0xFFFFFFFF;
        }
        chain >>>= 32;
      }
      chain += saved + carry;
      result.limbs[13] = chain & 0xFFFFFFFF;
      carry = (chain >>> 32) & 0xFFFFFFFF;
    }

    return _subExtra(result, order, carry);
  }
}
