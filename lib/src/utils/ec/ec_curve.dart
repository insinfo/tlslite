/// Pure-Dart prime-field short-Weierstrass elliptic curves
/// (y^2 = x^3 + a*x + b over GF(p)).
///
/// Internally points are kept in homogeneous projective coordinates and
/// combined with the complete addition formulas of Renes, Costello and Batina
/// ("Complete addition formulas for prime order elliptic curves", 2016,
/// algorithms 1 and 3). The formulas have no exceptional cases (doubling,
/// point at infinity, P + (-P)) for curves of odd order, which holds for
/// every curve registered in `ec_curves.dart` (all of them have cofactor 1).
/// Runs of four doublings inside the window loops go through Jacobian
/// coordinates (cheaper doubling formulas, no exceptional cases for points
/// other than infinity). Field elements are reduced lazily with a Barrett
/// reduction instead of `BigInt.%`, which is several times slower.
///
/// Scalar multiplication used for secret scalars ([EcCurve.mulSecret],
/// [EcCurve.mulBaseSecret]) uses a regular signed-digit recoding: the scalar
/// is turned into an odd value congruent modulo `n`, recoded into digits in
/// {±1, ±3, ..., ±15} and every window performs exactly 4 doublings plus one
/// addition with a table entry chosen by scanning the whole table with
/// masks. The sequence of field operations therefore does not depend on the
/// secret bits. Dart's [BigInt] is not constant time by itself, so this is a
/// best-effort protection, not a formal guarantee.
library;

import 'dart:typed_data';

/// Kind of the `a` coefficient, used to pick cheaper formulas.
enum _AKind { zero, minusThree, generic }

final BigInt _two = BigInt.two;
final BigInt _three = BigInt.from(3);

/// Masks used for branch-free selection: index 0 -> 0, index 1 -> all ones.
final List<BigInt> _masks = [BigInt.zero, BigInt.from(-1)];

/// Point in homogeneous projective coordinates (X : Y : Z); x = X/Z, y = Y/Z.
/// The point at infinity is (0 : 1 : 0).
class _Proj {
  const _Proj(this.x, this.y, this.z);
  final BigInt x;
  final BigInt y;
  final BigInt z;
}

/// Domain parameters of a prime-field short-Weierstrass curve.
class EcCurve {
  EcCurve({
    required this.name,
    required this.p,
    required this.a,
    required this.b,
    required BigInt gx,
    required BigInt gy,
    required this.n,
    BigInt? h,
    this.oid,
  })  : h = h ?? BigInt.one,
        fieldBytes = (p.bitLength + 7) ~/ 8,
        orderBits = n.bitLength,
        orderBytes = (n.bitLength + 7) ~/ 8,
        _aKind = a == BigInt.zero
            ? _AKind.zero
            : (a == p - _three ? _AKind.minusThree : _AKind.generic),
        _b3 = (b * _three) % p,
        _pMinus2 = p - _two,
        _nMinus2 = n - _two,
        _bs1 = p.bitLength - 1,
        _bs2 = p.bitLength + 17,
        _mu = (BigInt.one << (2 * p.bitLength + 16)) ~/ p {
    if (this.h != BigInt.one) {
      throw ArgumentError('Only prime-order curves (cofactor 1) are supported');
    }
    if (!isOnCurve(gx, gy)) {
      throw ArgumentError('Generator is not on curve $name');
    }
    generator = EcPoint._(this, gx, gy);
    // Number of 4-bit windows needed for odd scalars in [1, 2n).
    _windows = (orderBits + 1 + 3) ~/ 4;
  }

  /// Canonical curve name (e.g. `secp256r1`).
  final String name;

  /// Field prime.
  final BigInt p;

  /// Curve coefficient `a`.
  final BigInt a;

  /// Curve coefficient `b`.
  final BigInt b;

  /// Order of the generator.
  final BigInt n;

  /// Cofactor.
  final BigInt h;

  /// Object identifier arcs of the named curve, if known.
  final List<int>? oid;

  /// Length in bytes of one encoded field element (one coordinate).
  final int fieldBytes;

  /// Bit length of the group order.
  final int orderBits;

  /// Length in bytes of a scalar modulo [n].
  final int orderBytes;

  /// Base point.
  late final EcPoint generator;

  /// Alias of [generator] (naming used by the previous backend).
  EcPoint get G => generator;

  /// Field size in bits.
  int get fieldSize => p.bitLength;

  /// The point at infinity of this curve.
  late final EcPoint infinity = EcPoint._infinity(this);

  final _AKind _aKind;
  final BigInt _b3;
  final BigInt _pMinus2;
  final BigInt _nMinus2;
  late final int _windows;

  // Barrett reduction constants: mu = floor(2^(s1+s2) / p).
  final int _bs1;
  final int _bs2;
  final BigInt _mu;

  /// Precomputed fixed-base table: `_baseTable[i][j] = (2j+1) * 16^i * G`.
  late final List<List<_Proj>> _baseTable = _buildBaseTable();

  /// Non-residue used by Tonelli-Shanks (only when p ≡ 1 mod 4).
  late final BigInt _nonResidue = _findNonResidue();

  // ---------------------------------------------------------------------------
  // Public API
  // ---------------------------------------------------------------------------

  /// True if (x, y) satisfies the curve equation and both coordinates are
  /// field elements in canonical form.
  bool isOnCurve(BigInt x, BigInt y) {
    if (x.isNegative || y.isNegative || x >= p || y >= p) return false;
    final lhs = (y * y) % p;
    final rhs = (((x * x) % p + a) * x + b) % p;
    return lhs == rhs;
  }

  /// Creates an affine point, validating that it lies on the curve.
  ///
  /// Throws [ArgumentError] when the coordinates are not a curve point.
  EcPoint createPoint(BigInt x, BigInt y) {
    if (!isOnCurve(x, y)) {
      throw ArgumentError('Point is not on curve $name');
    }
    return EcPoint._(this, x, y);
  }

  /// Decodes a SEC 1 / X9.62 encoded point (0x04 uncompressed, 0x02/0x03
  /// compressed, or the single byte 0x00 for the point at infinity).
  ///
  /// The returned point is always on the curve. Throws [FormatException] on
  /// malformed encodings or points that are not on the curve. Hybrid
  /// encodings (0x06/0x07) are rejected.
  EcPoint decodePoint(List<int> encoded) {
    if (encoded.isEmpty) {
      throw const FormatException('Empty EC point encoding');
    }
    final type = encoded[0];
    final len = fieldBytes;
    switch (type) {
      case 0x00:
        if (encoded.length != 1) {
          throw const FormatException('Invalid encoding of point at infinity');
        }
        return infinity;
      case 0x04:
        if (encoded.length != 1 + 2 * len) {
          throw const FormatException('Invalid uncompressed EC point length');
        }
        final x = _bytesToBigInt(encoded, 1, 1 + len);
        final y = _bytesToBigInt(encoded, 1 + len, 1 + 2 * len);
        if (!isOnCurve(x, y)) {
          throw const FormatException('EC point is not on the curve');
        }
        return EcPoint._(this, x, y);
      case 0x02:
      case 0x03:
        if (encoded.length != 1 + len) {
          throw const FormatException('Invalid compressed EC point length');
        }
        final x = _bytesToBigInt(encoded, 1, 1 + len);
        if (x >= p) {
          throw const FormatException('EC point x coordinate out of range');
        }
        final rhs = (((x * x) % p + a) * x + b) % p;
        final root = sqrtMod(rhs);
        if (root == null) {
          throw const FormatException('EC point is not on the curve');
        }
        final wantOdd = type == 0x03;
        var y = root;
        if (y.isOdd != wantOdd) {
          if (y == BigInt.zero) {
            throw const FormatException('Invalid compressed EC point');
          }
          y = p - y;
        }
        return EcPoint._(this, x, y);
      default:
        throw FormatException(
            'Unsupported EC point encoding type 0x${type.toRadixString(16)}');
    }
  }

  /// Square root modulo [p], or `null` if [value] is a non-residue.
  ///
  /// Uses the (p+1)/4 exponent when p ≡ 3 (mod 4) and Tonelli-Shanks
  /// otherwise. Only meant for public data (point decompression).
  BigInt? sqrtMod(BigInt value) {
    final c = value % p;
    if (c == BigInt.zero) return BigInt.zero;
    BigInt r;
    if ((p & _three) == _three) {
      r = c.modPow((p + BigInt.one) >> 2, p);
    } else {
      r = _tonelliShanks(c);
    }
    if ((r * r) % p != c) return null;
    return r;
  }

  /// Multiplies [point] by a secret [k] using the regular (fixed operation
  /// sequence) algorithm. [k] is reduced modulo [n].
  EcPoint mulSecret(EcPoint point, BigInt k) {
    if (point.curve != this) {
      throw ArgumentError('Point belongs to a different curve');
    }
    if (point.isInfinity) return infinity;
    return _toAffine(_mulRegular(_fromAffine(point), k), secret: true);
  }

  /// Multiplies the generator by a secret [k] (fixed-base, regular algorithm).
  EcPoint mulBaseSecret(BigInt k) {
    return _toAffine(_mulBaseRegular(k), secret: true);
  }

  /// Computes `u1*G + u2*Q` for public scalars (signature verification).
  EcPoint mulDoublePublic(BigInt u1, EcPoint q, BigInt u2) {
    if (q.curve != this) {
      throw ArgumentError('Point belongs to a different curve');
    }
    final r1 = _mulBaseRegular(u1);
    if (q.isInfinity) return _toAffine(r1, secret: false);
    final r2 = _mulVarTime(_fromAffine(q), u2 % n);
    return _toAffine(_add(r1, r2), secret: false);
  }

  /// Point addition (affine in, affine out). Public data only.
  EcPoint add(EcPoint p1, EcPoint p2) {
    if (p1.curve != this || p2.curve != this) {
      throw ArgumentError('Point belongs to a different curve');
    }
    return _toAffine(_add(_fromAffine(p1), _fromAffine(p2)), secret: false);
  }

  /// Modular inverse modulo [n] computed as k^(n-2) mod n (n is prime).
  BigInt invModOrder(BigInt k) => (k % n).modPow(_nMinus2, n);

  @override
  String toString() => 'EcCurve($name)';

  // ---------------------------------------------------------------------------
  // Internal arithmetic
  // ---------------------------------------------------------------------------

  _Proj get _inf => _Proj(BigInt.zero, BigInt.one, BigInt.zero);

  _Proj _fromAffine(EcPoint pt) =>
      pt.isInfinity ? _inf : _Proj(pt.x!, pt.y!, BigInt.one);

  EcPoint _toAffine(_Proj pt, {required bool secret}) {
    final z = pt.z % p;
    if (z == BigInt.zero) return infinity;
    final zInv = secret ? z.modPow(_pMinus2, p) : z.modInverse(p);
    final x = (pt.x * zInv) % p;
    final y = (pt.y * zInv) % p;
    return EcPoint._(this, x, y);
  }

  /// Lazy Barrett reduction. For |t| < 2^16 * p^2 the result is congruent
  /// to t modulo p and lies in (-p, 4p). Coordinates produced by [_add] and
  /// [_dbl] are therefore not canonical; callers reduce with `% p` when a
  /// canonical value is needed.
  BigInt _red(BigInt t) {
    final q = ((t >> _bs1) * _mu) >> _bs2;
    return t - q * p;
  }

  BigInt _mulA(BigInt t) {
    switch (_aKind) {
      case _AKind.zero:
        return BigInt.zero;
      case _AKind.minusThree:
        return -(t + t + t);
      case _AKind.generic:
        return _red(a * t);
    }
  }

  /// Complete addition, RCB 2016 algorithm 1 (generic a).
  _Proj _add(_Proj P, _Proj Q) {
    final b3 = _b3;
    final x1 = P.x, y1 = P.y, z1 = P.z;
    final x2 = Q.x, y2 = Q.y, z2 = Q.z;
    var t0 = _red(x1 * x2);
    var t1 = _red(y1 * y2);
    var t2 = _red(z1 * z2);
    var t3 = _red((x1 + y1) * (x2 + y2));
    var t4 = t0 + t1;
    t3 = t3 - t4;
    t4 = _red((x1 + z1) * (x2 + z2));
    var t5 = t0 + t2;
    t4 = t4 - t5;
    t5 = _red((y1 + z1) * (y2 + z2));
    var x3 = t1 + t2;
    t5 = t5 - x3;
    var z3 = _mulA(t4);
    x3 = _red(b3 * t2);
    z3 = x3 + z3;
    x3 = t1 - z3;
    z3 = t1 + z3;
    var y3 = _red(x3 * z3);
    t1 = t0 + t0 + t0;
    t2 = _mulA(t2);
    t4 = _red(b3 * t4);
    t1 = t1 + t2;
    t2 = t0 - t2;
    t2 = _mulA(t2);
    t4 = t4 + t2;
    t0 = _red(t1 * t4);
    y3 = y3 + t0;
    t0 = _red(t5 * t4);
    x3 = _red(t3 * x3);
    x3 = x3 - t0;
    t0 = _red(t3 * t1);
    z3 = _red(t5 * z3);
    z3 = z3 + t0;
    return _Proj(x3, y3, z3);
  }

  /// Complete doubling, RCB 2016 algorithm 3 (generic a).
  _Proj _dbl(_Proj P) {
    final b3 = _b3;
    final x = P.x, y = P.y, z = P.z;
    var t0 = _red(x * x);
    var t1 = _red(y * y);
    var t2 = _red(z * z);
    var t3 = _red(x * y);
    t3 = t3 + t3;
    var z3 = _red(x * z);
    z3 = z3 + z3;
    var x3 = _mulA(z3);
    var y3 = _red(b3 * t2);
    y3 = x3 + y3;
    x3 = t1 - y3;
    y3 = t1 + y3;
    y3 = _red(x3 * y3);
    x3 = _red(t3 * x3);
    z3 = _red(b3 * z3);
    t2 = _mulA(t2);
    t3 = t0 - t2;
    t3 = _mulA(t3);
    t3 = t3 + z3;
    z3 = t0 + t0;
    t0 = z3 + t0;
    t0 = t0 + t2;
    t0 = _red(t0 * t3);
    y3 = y3 + t0;
    t2 = _red(y * z);
    t2 = t2 + t2;
    t0 = _red(t2 * t3);
    x3 = x3 - t0;
    z3 = _red(t2 * t1);
    z3 = z3 + z3;
    z3 = z3 + z3;
    return _Proj(x3, y3, z3);
  }

  /// Computes 16*P (four doublings) through Jacobian coordinates, which have
  /// cheaper doubling formulas than the complete projective ones.
  ///
  /// [P] must not be the point at infinity (callers guarantee this: the
  /// accumulator of the window loops is always a non-zero multiple of a point
  /// of prime order n).
  _Proj _dbl4(_Proj P) {
    final z0 = P.z;
    final zz0 = _red(z0 * z0);
    // Homogeneous (X:Y:Z) -> Jacobian (X*Z, Y*Z^2, Z).
    var x = _red(P.x * z0);
    var y = _red(P.y * zz0);
    var z = z0;
    switch (_aKind) {
      case _AKind.minusThree:
        // EFD dbl-2001-b (a = -3): 3M + 5S.
        for (var i = 0; i < 4; i++) {
          final delta = _red(z * z);
          final gamma = _red(y * y);
          final beta = _red(x * gamma);
          final alpha3 = _red((x - delta) * (x + delta));
          final alpha = alpha3 + alpha3 + alpha3;
          final beta4 = beta + beta + beta + beta;
          final x3 = _red(alpha * alpha) - (beta4 + beta4);
          final yz = y + z;
          final z3 = _red(yz * yz) - gamma - delta;
          final gamma2 = _red(gamma * gamma);
          final g8 = gamma2 + gamma2;
          final g8b = g8 + g8;
          y = _red(alpha * (beta4 - x3)) - (g8b + g8b);
          x = x3;
          z = z3;
        }
      case _AKind.zero:
      case _AKind.generic:
        // EFD dbl-2007-bl: 1M + 8S (+ 1 multiplication by a).
        final isZero = _aKind == _AKind.zero;
        for (var i = 0; i < 4; i++) {
          final xx = _red(x * x);
          final yy = _red(y * y);
          final yyyy = _red(yy * yy);
          final zz = _red(z * z);
          final xyy = x + yy;
          final s0 = _red(xyy * xyy) - xx - yyyy;
          final s = s0 + s0;
          var m = xx + xx + xx;
          if (!isZero) m = m + _red(a * _red(zz * zz));
          final t = _red(m * m) - (s + s);
          final y8 = yyyy + yyyy;
          final y8b = y8 + y8;
          final yz = y + z;
          final z3 = _red(yz * yz) - yy - zz;
          y = _red(m * (s - t)) - (y8b + y8b);
          x = t;
          z = z3;
        }
    }
    // Jacobian -> homogeneous (X*Z, Y, Z^3).
    final zz = _red(z * z);
    return _Proj(_red(x * z), y, _red(zz * z));
  }

  /// Returns an odd scalar k' ≡ k (mod n) with k' < 2n, selected without
  /// branching on the value of k.
  BigInt _oddScalar(BigInt k) {
    final k0 = k % n;
    final k1 = k0 + n;
    final isEven = 1 - (k0 & BigInt.one).toInt();
    final mask = _masks[isEven];
    return k0 ^ ((k0 ^ k1) & mask);
  }

  /// Regular signed recoding of an odd scalar into `_windows` digits in
  /// {±1, ±3, ..., ±15} (least significant first); the implicit top digit
  /// is 1 at position `_windows`.
  Int32List _recode(BigInt oddK) {
    final w = _windows;
    // Fixed-length nibble expansion (w + 1 nibbles, little endian).
    final nibbles = Int32List(w + 1);
    final bytes = _bigIntToBytesLE(oddK, (w + 2) ~/ 2);
    for (var i = 0; i <= w; i++) {
      final byte = bytes[i >> 1];
      nibbles[i] = (i & 1) == 0 ? byte & 0x0f : byte >> 4;
    }
    final digits = Int32List(w);
    for (var i = 0; i < w; i++) {
      final window = nibbles[i] | ((nibbles[i + 1] & 1) << 4) | 1;
      digits[i] = window - 16;
    }
    return digits;
  }

  /// Branch-free table lookup of entry `(|d|-1)/2` with conditional negation
  /// when `d < 0`.
  _Proj _select(List<_Proj> table, int d) {
    final sign = (d >> 31) & 1; // 1 when negative
    final abs = (d ^ -sign) + sign;
    final idx = (abs - 1) >> 1;
    var x = BigInt.zero, y = BigInt.zero, z = BigInt.zero;
    for (var j = 0; j < table.length; j++) {
      final eq = (((j ^ idx) - 1) >> 31) & 1;
      final m = _masks[eq];
      final e = table[j];
      x = x | (e.x & m);
      y = y | (e.y & m);
      z = z | (e.z & m);
    }
    final negY = p - y;
    final m = _masks[sign];
    y = y ^ ((y ^ negY) & m);
    return _Proj(x, y, z);
  }

  /// Odd multiples P, 3P, ..., 15P, with canonical coordinates.
  List<_Proj> _oddMultiples(_Proj P) {
    final table = List<_Proj>.filled(8, P);
    final twoP = _dbl(P);
    for (var j = 1; j < 8; j++) {
      table[j] = _add(table[j - 1], twoP);
    }
    for (var j = 0; j < 8; j++) {
      final e = table[j];
      table[j] = _Proj(e.x % p, e.y % p, e.z % p);
    }
    return table;
  }

  _Proj _mulRegular(_Proj P, BigInt k) {
    final digits = _recode(_oddScalar(k));
    final table = _oddMultiples(P);
    // Top digit is always +1.
    var r = P;
    for (var i = digits.length - 1; i >= 0; i--) {
      r = _dbl4(r);
      r = _add(r, _select(table, digits[i]));
    }
    return r;
  }

  _Proj _mulBaseRegular(BigInt k) {
    final digits = _recode(_oddScalar(k));
    final tables = _baseTable;
    // Top digit (+1) at weight 16^windows.
    var r = tables[digits.length][0];
    for (var i = digits.length - 1; i >= 0; i--) {
      r = _add(r, _select(tables[i], digits[i]));
    }
    return r;
  }

  List<List<_Proj>> _buildBaseTable() {
    final result = <List<_Proj>>[];
    var base = _fromAffine(generator);
    for (var i = 0; i <= _windows; i++) {
      result.add(List<_Proj>.unmodifiable(_normalizeAll(_oddMultiples(base))));
      base = _dbl(_dbl(_dbl(_dbl(base))));
    }
    return List.unmodifiable(result);
  }

  /// Converts projective points to Z = 1 (batch inversion).
  List<_Proj> _normalizeAll(List<_Proj> pts) {
    final prefix = List<BigInt>.filled(pts.length, BigInt.one);
    var acc = BigInt.one;
    for (var i = 0; i < pts.length; i++) {
      prefix[i] = acc;
      acc = (acc * pts[i].z) % p;
    }
    var inv = acc.modInverse(p);
    final out = List<_Proj>.filled(pts.length, pts[0]);
    for (var i = pts.length - 1; i >= 0; i--) {
      final zi = (inv * prefix[i]) % p;
      inv = (inv * pts[i].z) % p;
      out[i] = _Proj((pts[i].x * zi) % p, (pts[i].y * zi) % p, BigInt.one);
    }
    return out;
  }

  /// Variable-time 4-bit window multiplication; for public scalars only.
  _Proj _mulVarTime(_Proj P, BigInt k) {
    if (k == BigInt.zero) return _inf;
    final table = List<_Proj>.filled(16, _inf);
    table[1] = P;
    for (var j = 2; j < 16; j++) {
      table[j] = (j & 1) == 0 ? _dbl(table[j >> 1]) : _add(table[j - 1], P);
    }
    final nibbleCount = (k.bitLength + 3) ~/ 4;
    final bytes = _bigIntToBytesLE(k, (nibbleCount + 1) ~/ 2);
    var r = _inf;
    var started = false;
    for (var i = nibbleCount - 1; i >= 0; i--) {
      if (started) r = _dbl4(r);
      final byte = bytes[i >> 1];
      final nib = (i & 1) == 0 ? byte & 0x0f : byte >> 4;
      if (nib != 0) {
        r = started ? _add(r, table[nib]) : table[nib];
        started = true;
      }
    }
    return r;
  }

  BigInt _tonelliShanks(BigInt c) {
    // p - 1 = q * 2^s with q odd.
    var q = p - BigInt.one;
    var s = 0;
    while (q.isEven) {
      q >>= 1;
      s++;
    }
    var m = s;
    var cc = _nonResidue.modPow(q, p);
    var t = c.modPow(q, p);
    var r = c.modPow((q + BigInt.one) >> 1, p);
    while (t != BigInt.one) {
      if (t == BigInt.zero) return BigInt.zero;
      var i = 0;
      var t2 = t;
      while (t2 != BigInt.one) {
        t2 = (t2 * t2) % p;
        i++;
        if (i == m) return BigInt.zero; // not a residue
      }
      var bb = cc;
      for (var j = 0; j < m - i - 1; j++) {
        bb = (bb * bb) % p;
      }
      m = i;
      cc = (bb * bb) % p;
      t = (t * cc) % p;
      r = (r * bb) % p;
    }
    return r;
  }

  BigInt _findNonResidue() {
    final exp = (p - BigInt.one) >> 1;
    var z = _two;
    while (z.modPow(exp, p) != p - BigInt.one) {
      z += BigInt.one;
    }
    return z;
  }
}

/// Affine point on an [EcCurve] (or the point at infinity).
class EcPoint {
  EcPoint._(this.curve, BigInt this.x, BigInt this.y) : isInfinity = false;
  EcPoint._infinity(this.curve)
      : x = null,
        y = null,
        isInfinity = true;

  /// Curve this point belongs to.
  final EcCurve curve;

  /// Affine x coordinate (`null` for the point at infinity).
  final BigInt? x;

  /// Affine y coordinate (`null` for the point at infinity).
  final BigInt? y;

  /// True for the neutral element.
  final bool isInfinity;

  /// SEC 1 encoding: `0x04 || X || Y` or `0x02/0x03 || X` when [compressed].
  /// The point at infinity encodes as the single byte 0x00.
  Uint8List encode({bool compressed = false}) {
    if (isInfinity) return Uint8List(1);
    final len = curve.fieldBytes;
    if (compressed) {
      final out = Uint8List(1 + len);
      out[0] = y!.isOdd ? 0x03 : 0x02;
      _writeBigInt(out, 1, len, x!);
      return out;
    }
    final out = Uint8List(1 + 2 * len);
    out[0] = 0x04;
    _writeBigInt(out, 1, len, x!);
    _writeBigInt(out, 1 + len, len, y!);
    return out;
  }

  /// Point addition (public data only).
  EcPoint operator +(EcPoint other) => curve.add(this, other);

  /// Point negation.
  EcPoint operator -() =>
      isInfinity ? this : EcPoint._(curve, x!, (curve.p - y!) % curve.p);

  /// Scalar multiplication using the regular algorithm (safe for secrets).
  EcPoint operator *(BigInt k) => curve.mulSecret(this, k);

  /// True if this point satisfies the curve equation (infinity counts).
  bool get isValid => isInfinity || curve.isOnCurve(x!, y!);

  @override
  bool operator ==(Object other) =>
      other is EcPoint &&
      identical(other.curve, curve) &&
      other.isInfinity == isInfinity &&
      other.x == x &&
      other.y == y;

  @override
  int get hashCode => Object.hash(curve.name, x, y, isInfinity);

  @override
  String toString() => isInfinity
      ? 'EcPoint(${curve.name}, infinity)'
      : 'EcPoint(${curve.name}, 0x${x!.toRadixString(16)}, '
          '0x${y!.toRadixString(16)})';
}

// -----------------------------------------------------------------------------
// Byte helpers
// -----------------------------------------------------------------------------

BigInt _bytesToBigInt(List<int> bytes, int start, int end) {
  var result = BigInt.zero;
  // Process 4 bytes at a time to reduce BigInt allocations.
  var i = start;
  final lead = (end - start) % 4;
  if (lead != 0) {
    var chunk = 0;
    for (var j = 0; j < lead; j++) {
      chunk = (chunk << 8) | (bytes[i++] & 0xff);
    }
    result = BigInt.from(chunk);
  }
  while (i < end) {
    final chunk = ((bytes[i] & 0xff) << 24) |
        ((bytes[i + 1] & 0xff) << 16) |
        ((bytes[i + 2] & 0xff) << 8) |
        (bytes[i + 3] & 0xff);
    result = (result << 32) | BigInt.from(chunk);
    i += 4;
  }
  return result;
}

/// Big-endian unsigned bytes to BigInt.
BigInt ecBytesToBigInt(List<int> bytes) =>
    _bytesToBigInt(bytes, 0, bytes.length);

final BigInt _mask32 = BigInt.from(0xffffffff);
final BigInt _mask8 = BigInt.from(0xff);

void _writeBigInt(Uint8List out, int offset, int len, BigInt value) {
  var v = value;
  var i = offset + len - 1;
  while (i >= offset + 3 && v != BigInt.zero) {
    final chunk = (v & _mask32).toInt();
    out[i] = chunk & 0xff;
    out[i - 1] = (chunk >> 8) & 0xff;
    out[i - 2] = (chunk >> 16) & 0xff;
    out[i - 3] = (chunk >> 24) & 0xff;
    v >>= 32;
    i -= 4;
  }
  while (i >= offset && v != BigInt.zero) {
    out[i] = (v & _mask8).toInt();
    v >>= 8;
    i--;
  }
  if (v != BigInt.zero) {
    throw ArgumentError('Value does not fit in $len bytes');
  }
}

/// Fixed-length big-endian encoding of a non-negative [value].
Uint8List ecBigIntToBytes(BigInt value, int len) {
  if (value.isNegative) {
    throw ArgumentError('Value must be non-negative');
  }
  final out = Uint8List(len);
  _writeBigInt(out, 0, len, value);
  return out;
}

/// Fixed-length little-endian encoding (always processes every byte).
Uint8List _bigIntToBytesLE(BigInt value, int len) {
  final out = Uint8List(len);
  var v = value;
  for (var i = 0; i < len; i++) {
    out[i] = (v & _mask8).toInt();
    v >>= 8;
  }
  return out;
}
