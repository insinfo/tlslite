/// Teste do MontgomeryAsmContext completo
/// 
/// Verifica montMul e modPow

import 'dart:typed_data';
import 'package:tlslite/src/utils/montgomery_asm_x86_64.dart';

void main() {
  print('Teste MontgomeryAsmContext');
  print('=' * 50);
  
  // Teste com secp256k1 (256 bits = 4 limbs de 64 bits = 32 bytes)
  print('\n--- Teste modPow 256-bit ---');
  
  // n = primo secp256k1_p
  final nBytes = Uint8List.fromList([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
  ]);
  
  // base = pequeno valor
  final baseBytes = Uint8List.fromList([0x07]); // 7
  
  // exp = 65537
  final expBytes = Uint8List.fromList([0x01, 0x00, 0x01]);
  
  print('n = 0x${nBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('base = 7');
  print('exp = 65537');
  
  // Calcula resultado esperado com BigInt
  final nBig = _bytesToBigInt(nBytes);
  final baseBig = BigInt.from(7);
  final expBig = BigInt.from(65537);
  final expectedBig = baseBig.modPow(expBig, nBig);
  print('Esperado (BigInt): 0x${expectedBig.toRadixString(16)}');
  
  // Calcula com MontgomeryAsmContext
  final ctx = MontgomeryAsmContext.fromModulus(nBytes);
  print('numLimbs = ${ctx.numLimbs}');
  print('n0 = 0x${ctx.n0.toUnsigned(64).toRadixString(16)}');
  
  final resultBytes = ctx.modPow(baseBytes, expBytes);
  final resultBig = _bytesToBigInt(resultBytes);
  print('Resultado (ASM): 0x${resultBig.toRadixString(16)}');
  
  if (resultBig == expectedBig) {
    print('✓ modPow OK!');
  } else {
    print('✗ ERRO modPow!');
    print('  Diferença: ${(resultBig - expectedBig).abs()}');
  }
  
  ctx.dispose();
  
  // Teste montMul isolado
  print('\n--- Teste montMul isolado ---');
  _testMontMulIsolated();
}

void _testMontMulIsolated() {
  // Módulo pequeno: 17
  final nBytes = Uint8List.fromList([0x11]);
  
  final ctx = MontgomeryAsmContext.fromModulus(nBytes);
  print('n = 17, numLimbs = ${ctx.numLimbs}');
  print('n0 = 0x${ctx.n0.toUnsigned(64).toRadixString(16)}');
  print('rr = [${ctx.rr.map((x) => '0x${x.toUnsigned(64).toRadixString(16)}').join(', ')}]');
  
  // a = 3, b = 5
  // Em Montgomery: a' = a * R mod n, b' = b * R mod n
  // montMul(a', b') = a' * b' * R^-1 mod n = a * b * R mod n
  
  // Teste: montMul(3, 5) = 3 * 5 * R^-1 mod 17
  // R = 2^64, R^-1 mod 17 = ?
  // R mod 17 = 2^64 mod 17 = ?
  
  final a = Uint64List(1)..[0] = 3;
  final b = Uint64List(1)..[0] = 5;
  final result = Uint64List(1);
  
  ctx.montMul(result, a, b);
  print('montMul(3, 5) = ${result[0]}');
  
  // Verifica: 3 * 5 * R^-1 mod 17
  final R = BigInt.one << 64;
  final Rinv = R.modInverse(BigInt.from(17));
  final expected = (BigInt.from(3) * BigInt.from(5) * Rinv) % BigInt.from(17);
  print('Esperado: $expected');
  
  if (result[0] == expected.toInt()) {
    print('✓ montMul OK!');
  } else {
    print('✗ ERRO montMul!');
  }
  
  // Teste modPow com valores pequenos
  print('\n--- Teste modPow 17^1 mod 19 ---');
  final n19 = Uint8List.fromList([0x13]); // 19
  final ctx19 = MontgomeryAsmContext.fromModulus(n19);
  
  print('n = 19, numLimbs = ${ctx19.numLimbs}');
  print('n0 = 0x${ctx19.n0.toUnsigned(64).toRadixString(16)}');
  print('rr = [${ctx19.rr.map((x) => '0x${x.toUnsigned(64).toRadixString(16)}').join(', ')}]');
  
  // base = 7, exp = 3
  // 7^3 mod 19 = 343 mod 19 = 343 - 18*19 = 343 - 342 = 1
  final base7 = Uint8List.fromList([0x07]);
  final exp3 = Uint8List.fromList([0x03]);
  
  final resultBytes = ctx19.modPow(base7, exp3);
  final resultVal = resultBytes.isEmpty ? 0 : resultBytes[0];
  print('7^3 mod 19 = $resultVal');
  
  final expected73 = BigInt.from(7).modPow(BigInt.from(3), BigInt.from(19));
  print('Esperado: $expected73');
  
  if (BigInt.from(resultVal) == expected73) {
    print('✓ modPow pequeno OK!');
  } else {
    print('✗ ERRO modPow pequeno!');
  }
  
  ctx.dispose();
  ctx19.dispose();
  
  // Teste modPow com 2 limbs (128 bits)
  print('\n--- Teste modPow 128-bit ---');
  // n = 2^128 - 159 (primo de Mersenne próximo)
  final n128 = Uint8List.fromList([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x61,
  ]);
  
  final ctx128 = MontgomeryAsmContext.fromModulus(n128);
  print('n128 numLimbs = ${ctx128.numLimbs}');
  print('rr = [${ctx128.rr.map((x) => '0x${x.toUnsigned(64).toRadixString(16)}').join(', ')}]');
  
  // base = 7, exp = 65537
  final res128 = ctx128.modPow(Uint8List.fromList([0x07]), Uint8List.fromList([0x01, 0x00, 0x01]));
  final res128Big = _bytesToBigInt(res128);
  
  final n128Big = _bytesToBigInt(n128);
  final expected128 = BigInt.from(7).modPow(BigInt.from(65537), n128Big);
  
  print('7^65537 mod n128:');
  print('  Esperado: 0x${expected128.toRadixString(16)}');
  print('  Obtido:   0x${res128Big.toRadixString(16)}');
  
  if (res128Big == expected128) {
    print('✓ modPow 128-bit OK!');
  } else {
    print('✗ ERRO modPow 128-bit!');
  }
  
  // Teste montMul 2 limbs via contexto
  print('\n--- Teste montMul 2 limbs via contexto ---');
  final nTest = Uint8List.fromList([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC5,
  ]); // 2^128 - 59
  
  final ctxTest = MontgomeryAsmContext.fromModulus(nTest);
  print('n = 0x${nTest.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
  print('numLimbs = ${ctxTest.numLimbs}');
  print('modulus = [${ctxTest.modulus.map((x) => '0x${x.toUnsigned(64).toRadixString(16)}').join(', ')}]');
  print('n0 = 0x${ctxTest.n0.toUnsigned(64).toRadixString(16)}');
  
  // Teste: montMul(7, 11) 
  final aTest = Uint64List(2)..[0] = 7;
  final bTest = Uint64List(2)..[0] = 11;
  final resTest = Uint64List(2);
  
  ctxTest.montMul(resTest, aTest, bTest);
  
  // Resultado esperado: 7 * 11 * R^-1 mod n
  final nBig2 = _bytesToBigInt(nTest);
  final R2 = BigInt.one << 128;
  final Rinv2 = R2.modInverse(nBig2);
  final exp2 = (BigInt.from(7) * BigInt.from(11) * Rinv2) % nBig2;
  
  final got2 = (BigInt.from(resTest[1]).toUnsigned(64) << 64) | BigInt.from(resTest[0]).toUnsigned(64);
  
  print('montMul(7, 11):');
  print('  Esperado: 0x${exp2.toRadixString(16)}');
  print('  Obtido:   0x${got2.toRadixString(16)}');
  
  if (got2 == exp2) {
    print('✓ montMul 2 limbs OK!');
  } else {
    print('✗ ERRO montMul 2 limbs!');
  }
  
  ctxTest.dispose();
  ctx128.dispose();
}

BigInt _bytesToBigInt(Uint8List bytes) {
  if (bytes.isEmpty) return BigInt.zero;
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return BigInt.parse(hex, radix: 16);
}
