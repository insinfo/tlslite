// Debug script for montgomery_limbs
import 'dart:typed_data';
import 'package:tlslite/src/utils/montgomery_limbs.dart';

Uint8List bigIntToBytes(BigInt n) {
  if (n == BigInt.zero) return Uint8List(1);
  var hex = n.toRadixString(16);
  if (hex.length.isOdd) hex = '0$hex';
  final bytes = Uint8List(hex.length ~/ 2);
  for (int i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}

BigInt bytesToBigInt(Uint8List bytes) {
  var hex = '';
  for (final b in bytes) {
    hex += b.toRadixString(16).padLeft(2, '0');
  }
  return hex.isEmpty ? BigInt.zero : BigInt.parse(hex, radix: 16);
}

void main() {
  print('=== Montgomery Limbs Debug ===\n');
  
  // Test case from failing test
  final base = BigInt.parse('123456789');
  final exp = BigInt.parse('65537');
  //final mod = BigInt.parse('0xFFFFFFFFFFFFFFFF'); // 2^64 - 1
  // Try a different modulus (prime)
  final mod = BigInt.parse('0xFFFFFFFFFFFFFFC5'); // Próximo primo < 2^64
  
  print('Input:');
  print('  base = $base (${base.toRadixString(16)})');
  print('  exp  = $exp');
  print('  mod  = $mod (${mod.toRadixString(16)})');
  print('');
  
  // Calculate R^2 mod n manually
  final bigR = BigInt.one << 64; // R = 2^64
  final bigR2 = bigR * bigR; // R^2 = 2^128
  final expectedR2 = bigR2 % mod;
  print('Expected R^2 mod n = $expectedR2 (${expectedR2.toRadixString(16)})');
  print('');
  
  // Expected from BigInt
  final expected = base.modPow(exp, mod);
  print('Expected: $expected (${expected.toRadixString(16)})');
  print('');
  
  // Create BN objects
  final baseBN = BN.fromBytes(bigIntToBytes(base));
  final expBN = BN.fromBytes(bigIntToBytes(exp));
  final modBN = BN.fromBytes(bigIntToBytes(mod));
  
  print('BN representations:');
  print('  baseBN: top=${baseBN.top}, d=${baseBN.d.sublist(0, baseBN.top)}');
  print('  expBN:  top=${expBN.top}, d=${expBN.d.sublist(0, expBN.top)}');
  print('  modBN:  top=${modBN.top}, d=${modBN.d.sublist(0, modBN.top)}');
  print('');
  
  // Create Montgomery context
  final ctx = MontgomeryCtx.fromModulus(modBN);
  print('Montgomery Context:');
  print('  n0 = ${ctx.n0.toRadixString(16)}');
  print('  R^2 top = ${ctx.rr.top}');
  print('  R^2 d = ${ctx.rr.d.sublist(0, ctx.rr.top)}');
  
  // Verify n0: n0 * n[0] ≡ -1 (mod 2^32)
  final n0Check = (ctx.n0 * modBN.d[0]) & 0xFFFFFFFF;
  print('  n0 * n[0] mod 2^32 = ${n0Check.toRadixString(16)} (should be FFFFFFFF)');
  print('');
  
  // Debug toMont for base
  print('Debugging bnToMont for base:');
  print('  base value: $base');
  final expectedBaseMont = (base * BigInt.from(59)) % mod;
  print('  Expected base_mont: $expectedBaseMont (${expectedBaseMont.toRadixString(16)})');
  
  // Manual multiplication: base * rr
  print('  baseBN: top=${baseBN.top}, d=${baseBN.d.sublist(0, baseBN.top)}');
  print('  rr: top=${ctx.rr.top}, d=${ctx.rr.d.sublist(0, ctx.rr.top)}');
  
  // Do montgomery mul step by step
  final ret = BN(modBN.top + 1);
  print('\n  Calling bnMontMul(ret, baseBN, rr, ctx):');
  bnMontMul(ret, baseBN, ctx.rr, ctx);
  print('  Result: top=${ret.top}, d=${ret.d.sublist(0, ret.top).map((e) => e.toRadixString(16))}');
  final retVal = bytesToBigInt(ret.toBytes());
  print('  Value: $retVal (${retVal.toRadixString(16)})');
  print('');
  
  // Test simple multiplication
  print('Testing Montgomery multiply:');
  final a = BN.fromBytes(bigIntToBytes(BigInt.from(5)));
  final b = BN.fromBytes(bigIntToBytes(BigInt.from(7)));
  
  final aMont = BN(modBN.top);
  final bMont = BN(modBN.top);
  bnToMont(aMont, a, ctx);
  bnToMont(bMont, b, ctx);
  
  print('  a in Mont form: ${aMont.d.sublist(0, aMont.top)}');
  print('  b in Mont form: ${bMont.d.sublist(0, bMont.top)}');
  
  final resultMont = BN(modBN.top);
  bnMontMul(resultMont, aMont, bMont, ctx);
  
  final result = BN(modBN.top);
  bnFromMont(result, resultMont, ctx);
  
  final resultVal = bytesToBigInt(result.toBytes());
  print('  5 * 7 mod n = $resultVal (expected: 35)');
  print('');
  
  // Now test modPow
  print('Testing modPow:');
  final mont = MontgomeryModPow(modBN);
  final modPowResult = mont.modPow(baseBN, expBN);
  final actual = bytesToBigInt(modPowResult.toBytes());
  
  print('  Actual:   $actual (${actual.toRadixString(16)})');
  print('  Expected: $expected (${expected.toRadixString(16)})');
  print('  Match: ${actual == expected}');
  
  // Step by step for small exp
  print('\nStep-by-step for base^3 mod n:');
  final exp3 = BN.fromBytes(bigIntToBytes(BigInt.from(3)));
  final base3Result = mont.modPow(baseBN, exp3);
  final actual3 = bytesToBigInt(base3Result.toBytes());
  final expected3 = base.modPow(BigInt.from(3), mod);
  print('  Actual:   $actual3');
  print('  Expected: $expected3');
  print('  Match: ${actual3 == expected3}');
  
  // Manual step by step
  print('\nManual step-by-step for base^3:');
  final ctx2 = MontgomeryCtx.fromModulus(modBN);
  
  // base em Montgomery form
  final baseMont2 = BN(modBN.top);
  bnToMont(baseMont2, baseBN, ctx2);
  print('  base_mont: ${baseMont2.d.sublist(0, baseMont2.top).map((e) => e.toRadixString(16))}');
  
  // acc = 1 em Montgomery form
  final acc = BN(modBN.top);
  acc.setOne();
  bnToMont(acc, acc, ctx2);
  print('  1_mont: ${acc.d.sublist(0, acc.top).map((e) => e.toRadixString(16))}');
  
  // exp = 3 = 0b11, so 2 bits
  // bit 1: sqr(acc) then mul by base
  // bit 0: sqr(acc) then mul by base
  
  // First iteration (bit 1):
  print('\n  Iteration for bit 1:');
  bnMontSqr(acc, acc, ctx2); // acc = acc^2
  print('    After sqr: ${acc.d.sublist(0, acc.top).map((e) => e.toRadixString(16))}');
  
  // Check value
  final checkBN = BN(modBN.top);
  bnFromMont(checkBN, acc, ctx2);
  var checkVal = bytesToBigInt(checkBN.toBytes());
  print('    Value after sqr: $checkVal (expected: 1)');
  
  // Multiply by base (using temp to avoid aliasing)
  final temp = BN(modBN.top + 1);
  bnMontMul(temp, acc, baseMont2, ctx2);
  for (int i = 0; i < temp.top; i++) acc.d[i] = temp.d[i];
  acc.top = temp.top;
  print('    After mul: ${acc.d.sublist(0, acc.top).map((e) => e.toRadixString(16))}');
  
  bnFromMont(checkBN, acc, ctx2);
  checkVal = bytesToBigInt(checkBN.toBytes());
  print('    Value after mul: $checkVal (expected: $base)');
  
  // Second iteration (bit 0):
  print('\n  Iteration for bit 0:');
  bnMontSqr(acc, acc, ctx2); // acc = acc^2
  print('    After sqr: ${acc.d.sublist(0, acc.top).map((e) => e.toRadixString(16))}');
  
  bnFromMont(checkBN, acc, ctx2);
  checkVal = bytesToBigInt(checkBN.toBytes());
  final expectedSqr = (base * base) % mod;
  print('    Value after sqr: $checkVal (expected: $expectedSqr)');
  
  // Multiply by base
  bnMontMul(temp, acc, baseMont2, ctx2);
  for (int i = 0; i < temp.top; i++) acc.d[i] = temp.d[i];
  acc.top = temp.top;
  print('    After mul: ${acc.d.sublist(0, acc.top).map((e) => e.toRadixString(16))}');
  
  bnFromMont(checkBN, acc, ctx2);
  checkVal = bytesToBigInt(checkBN.toBytes());
  print('    Value after mul: $checkVal (expected: $expected3)');
}
