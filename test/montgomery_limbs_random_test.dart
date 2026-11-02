import 'dart:math';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/experimental/montgomery_limbs.dart';

Uint8List _toBytes(BigInt v) {
  var hex = v.toRadixString(16);
  if (hex.length.isOdd) hex = '0$hex';
  return Uint8List.fromList([
    for (var i = 0; i < hex.length; i += 2) int.parse(hex.substring(i, i + 2), radix: 16)
  ]);
}

BigInt _fromBytes(Uint8List b) =>
    b.fold(BigInt.zero, (acc, x) => (acc << 8) | BigInt.from(x));

BigInt _random(Random rng, int bits) {
  var v = BigInt.zero;
  for (var i = 0; i < bits; i += 16) {
    v = (v << 16) | BigInt.from(rng.nextInt(1 << 16));
  }
  return v & ((BigInt.one << bits) - BigInt.one);
}

void main() {
  test('modPow matches BigInt.modPow for odd moduli of 1 to 64 limbs', () {
    final rng = Random(42);
    for (var limbs = 1; limbs <= 64; limbs++) {
      final bits = limbs * 32;
      final cases = [
        // All bits set: 32x32 products at the 2^64 limit.
        (BigInt.one << bits) - BigInt.one,
        _random(rng, bits) | (BigInt.one << (bits - 1)) | BigInt.one,
      ];
      for (final mod in cases) {
        final base = _random(rng, bits) % mod;
        final exp = _random(rng, limbs <= 8 ? bits : 64) | BigInt.one;
        final expected = base.modPow(exp, mod);
        final result = MontgomeryModPow(BN.fromBytes(_toBytes(mod)))
            .modPow(BN.fromBytes(_toBytes(base)), BN.fromBytes(_toBytes(exp)));
        expect(_fromBytes(result.toBytes()), expected,
            reason: 'limbs=$limbs mod=${mod.toRadixString(16)}');
      }
    }
  });
}
