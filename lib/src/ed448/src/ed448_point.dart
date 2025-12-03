library;

import 'dart:typed_data';
import 'fp448.dart';
import 'scalar448.dart';

/// Edwards curve parameter d = -39081
final Uint32List _edwardsD = () {
  // -39081 mod p = p - 39081
  final d = Fp448.create();
  d[0] = 268396374; // 0x0FFFFFFF - 39081 + 1 = 268396374
  for (var i = 1; i < 16; i++) {
    d[i] = i == 8 ? 268435454 : 268435455; // 0x0FFFFFFF or 0x0FFFFFFE for i=8
  }
  return d;
}();

/// Point on the Ed448-Goldilocks curve in extended coordinates.
/// Represents point (x, y) as (X:Y:Z:T) where x=X/Z, y=Y/Z, xy=T/Z.
class Ed448Point {
  final Uint32List X;
  final Uint32List Y;
  final Uint32List Z;
  final Uint32List T;

  Ed448Point._(this.X, this.Y, this.Z, this.T);

  /// Create identity point (0, 1)
  factory Ed448Point.identity() {
    final x = Fp448.create();
    final y = Fp448.create();
    final z = Fp448.create();
    final t = Fp448.create();
    Fp448.one(y);
    Fp448.one(z);
    return Ed448Point._(x, y, z, t);
  }

  /// Create point from affine coordinates
  factory Ed448Point.fromAffine(Uint32List x, Uint32List y) {
    final X = Fp448.create();
    final Y = Fp448.create();
    final Z = Fp448.create();
    final T = Fp448.create();

    Fp448.copy(x, X);
    Fp448.copy(y, Y);
    Fp448.one(Z);
    Fp448.mul(x, y, T);

    return Ed448Point._(X, Y, Z, T);
  }

  /// The Ed448-Goldilocks base point
  static Ed448Point get generator {
    // x = 0xaaaa...9555...55 (isogeny from the old basepoint)
    final x = Fp448.create();
    x.setAll(0, [
      118276190,
      40534716,
      9670182,
      135141552,
      85017403,
      259173222,
      68333082,
      171784774,
      174973732,
      15824510,
      73756743,
      57518561,
      94773951,
      248652241,
      107736333,
      82941708,
    ]);

    // y coordinate
    final y = Fp448.create();
    y.setAll(0, [
      36764180,
      8885695,
      130592152,
      20104429,
      163904957,
      30304195,
      121295871,
      5901357,
      125344798,
      171541512,
      175338348,
      209069246,
      3626697,
      38307682,
      24032956,
      110359655,
    ]);

    return Ed448Point.fromAffine(x, y);
  }

  /// Check if this is the identity point
  bool get isIdentity {
    final xNorm = Fp448.create();
    final yNorm = Fp448.create();
    final zInv = Fp448.create();

    Fp448.inv(Z, zInv);
    Fp448.mul(X, zInv, xNorm);
    Fp448.mul(Y, zInv, yNorm);
    Fp448.normalize(xNorm);
    Fp448.normalize(yNorm);

    // Identity is (0, 1)
    final one = Fp448.create();
    Fp448.one(one);

    return Fp448.isZero(xNorm) && Fp448.equals(yNorm, one);
  }

  /// Convert to affine coordinates
  (Uint32List, Uint32List) toAffine() {
    final x = Fp448.create();
    final y = Fp448.create();
    final zInv = Fp448.create();

    Fp448.inv(Z, zInv);
    Fp448.mul(X, zInv, x);
    Fp448.mul(Y, zInv, y);
    Fp448.normalize(x);
    Fp448.normalize(y);

    return (x, y);
  }

  /// Point addition using unified formula
  /// Based on https://iacr.org/archive/asiacrypt2008/53500329/53500329.pdf (3.1)
  Ed448Point operator +(Ed448Point other) {
    final aXX = Fp448.create(); // X1 * X2
    final dTT = Fp448.create(); // d * T1 * T2
    final ZZ = Fp448.create(); // Z1 * Z2
    final YY = Fp448.create(); // Y1 * Y2
    final temp1 = Fp448.create();
    final temp2 = Fp448.create();

    Fp448.mul(X, other.X, aXX);
    Fp448.mul(T, other.T, temp1);
    Fp448.mul(temp1, _edwardsD, dTT);
    Fp448.mul(Z, other.Z, ZZ);
    Fp448.mul(Y, other.Y, YY);

    // X3 = (X1*Y2 + Y1*X2) * (Z1*Z2 - d*T1*T2)
    final x3 = Fp448.create();
    Fp448.mul(X, other.Y, temp1);
    Fp448.mul(Y, other.X, temp2);
    Fp448.add(temp1, temp2, temp1); // X1*Y2 + Y1*X2
    Fp448.sub(ZZ, dTT, temp2); // Z1*Z2 - d*T1*T2
    Fp448.mul(temp1, temp2, x3);

    // Y3 = (Y1*Y2 - X1*X2) * (Z1*Z2 + d*T1*T2)
    final y3 = Fp448.create();
    Fp448.sub(YY, aXX, temp1); // Y1*Y2 - X1*X2
    Fp448.add(ZZ, dTT, temp2); // Z1*Z2 + d*T1*T2
    Fp448.mul(temp1, temp2, y3);

    // T3 = (Y1*Y2 - X1*X2) * (X1*Y2 + Y1*X2)
    final t3 = Fp448.create();
    Fp448.sub(YY, aXX, temp1); // Y1*Y2 - X1*X2
    Fp448.mul(X, other.Y, temp2);
    final temp3 = Fp448.create();
    Fp448.mul(Y, other.X, temp3);
    Fp448.add(temp2, temp3, temp2); // X1*Y2 + Y1*X2
    Fp448.mul(temp1, temp2, t3);

    // Z3 = (Z1*Z2 - d*T1*T2) * (Z1*Z2 + d*T1*T2)
    final z3 = Fp448.create();
    Fp448.sub(ZZ, dTT, temp1);
    Fp448.add(ZZ, dTT, temp2);
    Fp448.mul(temp1, temp2, z3);

    return Ed448Point._(x3, y3, z3, t3);
  }

  /// Point doubling
  Ed448Point double_() {
    return this + this; // Using unified formula
  }

  /// Point negation: -(X:Y:Z:T) = (-X:Y:Z:-T)
  Ed448Point negate() {
    final negX = Fp448.create();
    final negT = Fp448.create();

    Fp448.neg(X, negX);
    Fp448.neg(T, negT);

    final newY = Fp448.create();
    final newZ = Fp448.create();
    Fp448.copy(Y, newY);
    Fp448.copy(Z, newZ);

    return Ed448Point._(negX, newY, newZ, negT);
  }

  /// Point subtraction
  Ed448Point operator -(Ed448Point other) {
    return this + other.negate();
  }

  /// Scalar multiplication using double-and-add
  Ed448Point scalarMul(Scalar448 scalar) {
    var result = Ed448Point.identity();
    var addend = this;

    final bits = scalar.toBytes();
    for (var i = 0; i < 56; i++) {
      var byte = bits[i];
      for (var j = 0; j < 8; j++) {
        if ((byte & 1) != 0) {
          result = result + addend;
        }
        addend = addend.double_();
        byte >>= 1;
      }
    }

    return result;
  }

  /// Compress point to 57 bytes (store Y and sign of X)
  Uint8List compress() {
    final (x, y) = toAffine();

    final yBytes = Fp448.encode(y);
    final result = Uint8List(57);
    result.setRange(0, 56, yBytes);

    // Set sign bit of X in the last byte
    final xBytes = Fp448.encode(x);
    final xSign = xBytes[0] & 1; // LSB of x is the sign
    result[56] = xSign << 7;

    return result;
  }

  /// Decompress point from 57 bytes
  static Ed448Point? decompress(Uint8List bytes) {
    if (bytes.length != 57) return null;

    // Extract sign bit
    final sign = (bytes[56] >> 7) & 1;

    // Extract Y
    final yBytes = Uint8List(56);
    yBytes.setRange(0, 56, bytes);
    final y = Fp448.decode(yBytes);

    // Compute x from curve equation: x² + y² = 1 + d*x²*y²
    // => x² (1 - d*y²) = y² - 1
    // => x² = (y² - 1) / (1 - d*y²)
    final yy = Fp448.create();
    final num = Fp448.create();
    final den = Fp448.create();
    final one = Fp448.create();

    Fp448.sqr(y, yy);
    Fp448.one(one);
    Fp448.sub(yy, one, num); // y² - 1

    // 1 - d*y²
    final dyy = Fp448.create();
    Fp448.mul(_edwardsD, yy, dyy);
    Fp448.sub(one, dyy, den);

    // Check if denominator is zero
    if (Fp448.isZero(den)) return null;

    // x² = num / den
    final x2 = Fp448.create();
    final denInv = Fp448.create();
    Fp448.inv(den, denInv);
    Fp448.mul(num, denInv, x2);

    // Compute square root
    final x = Fp448.create();
    final (sqrtResult, isRes) = Fp448.sqrtRatio(x2, one);
    if (!isRes) return null;
    Fp448.copy(sqrtResult, x);

    // Adjust sign
    Fp448.normalize(x);
    final xBytes = Fp448.encode(x);
    final currentSign = xBytes[0] & 1;
    if (currentSign != sign) {
      Fp448.neg(x, x);
    }

    return Ed448Point.fromAffine(x, y);
  }

  /// Check point equality
  @override
  bool operator ==(Object other) {
    if (other is! Ed448Point) return false;

    // Compare X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1
    final xz = Fp448.create();
    final zx = Fp448.create();
    final yz = Fp448.create();
    final zy = Fp448.create();

    Fp448.mul(X, other.Z, xz);
    Fp448.mul(other.X, Z, zx);
    Fp448.mul(Y, other.Z, yz);
    Fp448.mul(other.Y, Z, zy);

    return Fp448.equals(xz, zx) && Fp448.equals(yz, zy);
  }

  @override
  int get hashCode {
    final (x, y) = toAffine();
    return Object.hash(x, y);
  }

  /// Check if point is on the curve
  bool isOnCurve() {
    final (x, y) = toAffine();

    // x² + y² = 1 + d*x²*y²
    final xx = Fp448.create();
    final yy = Fp448.create();
    final lhs = Fp448.create();
    final one = Fp448.create();

    Fp448.sqr(x, xx);
    Fp448.sqr(y, yy);
    Fp448.add(xx, yy, lhs);
    Fp448.one(one);

    // rhs = 1 + d*x²*y²
    final xxyy = Fp448.create();
    final dxxyy = Fp448.create();
    final rhs = Fp448.create();

    Fp448.mul(xx, yy, xxyy);
    Fp448.mul(_edwardsD, xxyy, dxxyy);
    Fp448.add(one, dxxyy, rhs);

    return Fp448.equals(lhs, rhs);
  }
}
