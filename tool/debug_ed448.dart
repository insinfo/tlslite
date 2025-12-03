import 'dart:typed_data';

import 'package:tlslite/src/ed448/src/ed448_impl.dart' as big;
import 'package:tlslite/src/ed448/src/ed448_point.dart' as curve;
import 'package:tlslite/src/ed448/src/fp448.dart' as fp;
import 'package:tlslite/src/ed448/src/scalar448.dart' as scalars;

final BigInt _p =
  (BigInt.one << 448) - (BigInt.one << 224) - BigInt.one;
final BigInt _d = BigInt.from(-39081) % _p;

Uint8List hexToBytes(String hex) {
  final cleaned = hex.replaceAll(RegExp(r"\s"), "");
  final bytes = <int>[];
  for (var i = 0; i < cleaned.length; i += 2) {
    bytes.add(int.parse(cleaned.substring(i, i + 2), radix: 16));
  }
  return Uint8List.fromList(bytes);
}

Uint32List hexToField(String hex) {
  final bytes = hexToBytes(hex);
  if (bytes.length != 56) {
    throw ArgumentError('field hex must be 56 bytes');
  }
  final little = Uint8List(56);
  for (var i = 0; i < 56; i++) {
    little[i] = bytes[55 - i];
  }
  return fp.Fp448.decode(little);
}

Uint32List hexToFieldLE(String hex) {
  final bytes = hexToBytes(hex);
  if (bytes.length != 56) {
    throw ArgumentError('field hex must be 56 bytes');
  }
  return fp.Fp448.decode(bytes);
}

curve.Ed448Point pointFromHex(String xHex, String yHex) {
  final x = hexToField(xHex);
  final y = hexToField(yHex);
  return curve.Ed448Point.fromAffine(x, y);
}

curve.Ed448Point pointFromHexLE(String xHex, String yHex) {
  final x = hexToFieldLE(xHex);
  final y = hexToFieldLE(yHex);
  return curve.Ed448Point.fromAffine(x, y);
}

String fieldToHex(Uint32List value) {
  final little = fp.Fp448.encode(value);
  final buffer = StringBuffer();
  for (var i = 55; i >= 0; i--) {
    buffer.write(little[i].toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

BigInt _bytesToBigInt(Uint8List bytes) {
  var result = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}

BigInt _modInverse(BigInt a, BigInt m) => a.modInverse(m);

BigInt? _modSqrt(BigInt a, BigInt p) {
  a = a % p;
  if (a == BigInt.zero) return BigInt.zero;
  if (a.modPow((p - BigInt.one) ~/ BigInt.two, p) != BigInt.one) {
    return null;
  }
  if (p % BigInt.from(4) == BigInt.from(3)) {
    return a.modPow((p + BigInt.one) ~/ BigInt.from(4), p);
  }
  throw StateError('unexpected p mod 4');
}

void main() {
  final bytes = hexToBytes(
    '649c6a53b109897d962d033f23d01fd4e1053dddf3746d2ddce9bd66aea38ccf'
    'c3df061df03ca399eb806312ab3037c0c31523142956ada780',
  );

  final yBytes = Uint8List.fromList(bytes);
  final sign = (yBytes[56] >> 7) & 1;
  yBytes[56] &= 0x7F;

  final y = _bytesToBigInt(yBytes);
  print('y < p? ${y < _p}');
  print('sign bit: $sign');

  final y2 = (y * y) % _p;
  final num = (y2 - BigInt.one) % _p;
  final den = (BigInt.one + _d * y2) % _p;

  print('num A: $num');
  print('den A: $den');

  if (den == BigInt.zero) {
    print('den zero');
    return;
  }

  final denInv = _modInverse(den, _p);
  final x2 = (num * denInv) % _p;
  final x = _modSqrt(x2, _p);
  print('sqrt exists A? ${x != null}');

  final numB = (BigInt.one - y2) % _p;
  final denB = (BigInt.one - _d * y2) % _p;
  final x2b = (numB * _modInverse(denB, _p)) % _p;
  final xb = _modSqrt(x2b, _p);
  print('sqrt exists B? ${xb != null}');

  print('big decode: ${big.Ed448Point.decode(bytes) != null}');
  print('curve decode: ${curve.Ed448Point.decompress(bytes) != null}');

  final identityBytes = Uint8List(57);
  identityBytes[0] = 1;
  print('curve identity decode: ${curve.Ed448Point.decompress(identityBytes) != null}');

  final identityHexBytes = hexToBytes(
      '0100000000000000000000000000000000000000000000000000000000000000'
      '000000000000000000000000000000000000000000000000000000000000');
  print('hex identity len: ${identityHexBytes.length}');
  print('curve identity(hex) decode: ${curve.Ed448Point.decompress(identityHexBytes) != null}');

    final oldX =
      '4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e';
    final oldY =
      '693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14';
    final newX =
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555';
    final newY =
      'ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed';

    final oldBase = pointFromHex(oldX, oldY);
    final oldBaseLE = pointFromHexLE(oldX, oldY);
    final newBase = pointFromHex(newX, newY);
    final doubled = oldBase.double_().double_();
    final doubledLE = oldBaseLE.double_().double_();
    print('old base on curve? ${oldBase.isOnCurve()}');
    print('old base (LE) on curve? ${oldBaseLE.isOnCurve()}');
    print('new base on curve? ${newBase.isOnCurve()}');
    final (ox, oy) = oldBase.toAffine();
    print('old base x hex: ${fieldToHex(ox)}');
    print('old base y hex: ${fieldToHex(oy)}');
    final (oxLE, oyLE) = oldBaseLE.toAffine();
    print('old base LE x hex: ${fieldToHex(oxLE)}');
    print('old base LE y hex: ${fieldToHex(oyLE)}');
    print('old -> new equals? ${doubled == newBase}');
    print('oldLE -> new equals? ${doubledLE == newBase}');
    print('generator equals newBase? ${curve.Ed448Point.generator == newBase}');
    final (gx, gy) = curve.Ed448Point.generator.toAffine();
    print('generator x: ${fieldToHex(gx)}');
    print('generator y: ${fieldToHex(gy)}');
    final (nx, ny) = newBase.toAffine();
    print('new base limbs X: ${nx.toList()}');
    print('new base limbs Y: ${ny.toList()}');
    final (dx, dy) = doubled.toAffine();
    print('doubled x: ${fieldToHex(dx)}');
    print('doubled y: ${fieldToHex(dy)}');
    final (dxLE, dyLE) = doubledLE.toAffine();
    print('doubledLE x: ${fieldToHex(dxLE)}');
    print('doubledLE y: ${fieldToHex(dyLE)}');

    final oldBig = big.Ed448Point(
      BigInt.parse(oldX, radix: 16),
      BigInt.parse(oldY, radix: 16),
    );
    final newBig = big.Ed448Point(
      BigInt.parse(newX, radix: 16),
      BigInt.parse(newY, radix: 16),
    );
    final bigDoubled = oldBig.double_().double_();
    print('big old->new equals? ${bigDoubled == newBig}');
    final mulFour = oldBase.scalarMul(scalars.Scalar448.fromInt(4));
    print('scalarMul(4) equals new base? ${mulFour == newBase}');

    final generatorBytes = curve.Ed448Point.generator.compress();
    final genHex = generatorBytes.reversed
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
    print('generator encoding (big-endian hex): $genHex');
    final newBytes = newBase.compress();
    final newHexLe = newBytes
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();
    print('new base encoding (little-endian hex): $newHexLe');
}
