/// Debug detalhado do modPow

import 'dart:typed_data';
import 'package:tlslite/src/utils/montgomery_asm_x86_64.dart';

void main() {
  print('Debug modPow passo a passo');
  print('=' * 60);
  
  // Módulo 128-bit pequeno para debug
  final n128 = Uint8List.fromList([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC5, // último byte = 197 (ímpar)
  ]);
  
  final nBig = _bytesToBigInt(n128);
  print('n = 0x${nBig.toRadixString(16)}');
  print('n = $nBig');
  
  final ctx = MontgomeryAsmContext.fromModulus(n128);
  print('\nnumLimbs = ${ctx.numLimbs}');
  print('modulus = [${ctx.modulus.map((x) => '0x${x.toUnsigned(64).toRadixString(16)}').join(', ')}]');
  print('n0 = 0x${ctx.n0.toUnsigned(64).toRadixString(16)}');
  print('rr = [${ctx.rr.map((x) => '0x${x.toUnsigned(64).toRadixString(16)}').join(', ')}]');
  
  // Verifica modulus está correto
  print('\n--- Verificando modulus ---');
  BigInt modulusBig = BigInt.zero;
  for (int i = ctx.numLimbs - 1; i >= 0; i--) {
    modulusBig = (modulusBig << 64) | BigInt.from(ctx.modulus[i]).toUnsigned(64);
  }
  print('modulus como BigInt: 0x${modulusBig.toRadixString(16)}');
  print('n original: 0x${nBig.toRadixString(16)}');
  print('modulus == n? ${modulusBig == nBig}');
  
  // Verifica n0
  print('\n--- Verificando n0 ---');
  final n0Big = BigInt.from(ctx.n0).toUnsigned(64);
  print('n0 = 0x${n0Big.toRadixString(16)}');
  // n0 deve ser -n^-1 mod 2^64
  // Então n * n0 ≡ -1 (mod 2^64)
  // Ou seja (n * n0 + 1) % 2^64 == 0
  final n0limb = BigInt.from(ctx.modulus[0]).toUnsigned(64);
  final product = (n0limb * n0Big) & BigInt.parse('FFFFFFFFFFFFFFFF', radix: 16);
  print('n[0] * n0 mod 2^64 = 0x${product.toRadixString(16)}');
  print('Esperado: 0xffffffffffffffff (-1)');
  print('n0 correto? ${product == BigInt.parse('FFFFFFFFFFFFFFFF', radix: 16)}');
  
  // Verifica RR
  print('\n--- Verificando RR ---');
  BigInt rrBig = BigInt.zero;
  for (int i = ctx.numLimbs - 1; i >= 0; i--) {
    rrBig = (rrBig << 64) | BigInt.from(ctx.rr[i]).toUnsigned(64);
  }
  print('rr = 0x${rrBig.toRadixString(16)}');
  final R = BigInt.one << (ctx.numLimbs * 64);
  final rrExpected = (R * R) % nBig;
  print('R^2 mod n esperado: 0x${rrExpected.toRadixString(16)}');
  print('RR correto? ${rrBig == rrExpected}');
  
  // Teste montMul 
  print('\n--- Teste montMul simples ---');
  // montMul(7, 11) = 7 * 11 * R^-1 mod n
  final a = Uint64List(ctx.numLimbs)..[0] = 7;
  final b = Uint64List(ctx.numLimbs)..[0] = 11;
  final result = Uint64List(ctx.numLimbs);
  
  ctx.montMul(result, a, b);
  
  BigInt resultBig = BigInt.zero;
  for (int i = ctx.numLimbs - 1; i >= 0; i--) {
    resultBig = (resultBig << 64) | BigInt.from(result[i]).toUnsigned(64);
  }
  print('montMul(7, 11) = 0x${resultBig.toRadixString(16)}');
  
  final Rinv = R.modInverse(nBig);
  final expectedMul = (BigInt.from(7) * BigInt.from(11) * Rinv) % nBig;
  print('Esperado: 0x${expectedMul.toRadixString(16)}');
  print('montMul correto? ${resultBig == expectedMul}');
  
  // Teste conversão para domínio Montgomery
  print('\n--- Conversão para Montgomery ---');
  // base_mont = base * R mod n = montMul(base, R^2)
  final base = Uint64List(ctx.numLimbs)..[0] = 7;
  final baseMont = Uint64List(ctx.numLimbs);
  ctx.montMul(baseMont, base, ctx.rr);
  
  BigInt baseMontBig = BigInt.zero;
  for (int i = ctx.numLimbs - 1; i >= 0; i--) {
    baseMontBig = (baseMontBig << 64) | BigInt.from(baseMont[i]).toUnsigned(64);
  }
  print('baseMont = montMul(7, R^2) = 0x${baseMontBig.toRadixString(16)}');
  final baseMontExpected = (BigInt.from(7) * R) % nBig;
  print('Esperado (7*R mod n): 0x${baseMontExpected.toRadixString(16)}');
  print('Conversão correta? ${baseMontBig == baseMontExpected}');
  
  // Teste 1_mont
  print('\n--- 1 em Montgomery ---');
  final one = Uint64List(ctx.numLimbs)..[0] = 1;
  final oneMont = Uint64List(ctx.numLimbs);
  ctx.montMul(oneMont, one, ctx.rr);
  
  BigInt oneMontBig = BigInt.zero;
  for (int i = ctx.numLimbs - 1; i >= 0; i--) {
    oneMontBig = (oneMontBig << 64) | BigInt.from(oneMont[i]).toUnsigned(64);
  }
  print('oneMont = montMul(1, R^2) = 0x${oneMontBig.toRadixString(16)}');
  final oneMontExpected = R % nBig;
  print('Esperado (R mod n): 0x${oneMontExpected.toRadixString(16)}');
  print('1_mont correto? ${oneMontBig == oneMontExpected}');
  
  // Teste modPow com expoente simples (7^3 mod n)
  print('\n--- modPow 7^3 mod n ---');
  final baseBytes = Uint8List.fromList([0x07]);
  final expBytes = Uint8List.fromList([0x03]);
  
  final modPowResult = ctx.modPow(baseBytes, expBytes);
  final modPowBig = _bytesToBigInt(modPowResult);
  
  final expected = BigInt.from(7).modPow(BigInt.from(3), nBig);
  print('7^3 mod n:');
  print('  Esperado: 0x${expected.toRadixString(16)} (${expected})');
  print('  Obtido:   0x${modPowBig.toRadixString(16)} (${modPowBig})');
  print('modPow correto? ${modPowBig == expected}');
  
  // Teste modPow 7^1 mod n (trivial)
  print('\n--- modPow 7^1 mod n ---');
  final expBytes1 = Uint8List.fromList([0x01]);
  final modPowResult1 = ctx.modPow(baseBytes, expBytes1);
  final modPowBig1 = _bytesToBigInt(modPowResult1);
  
  final expected1 = BigInt.from(7).modPow(BigInt.from(1), nBig);
  print('7^1 mod n:');
  print('  Esperado: 0x${expected1.toRadixString(16)} (${expected1})');
  print('  Obtido:   0x${modPowBig1.toRadixString(16)} (${modPowBig1})');
  print('modPow^1 correto? ${modPowBig1 == expected1}');
  
  // Teste modPow 7^2 mod n
  print('\n--- modPow 7^2 mod n ---');
  final expBytes2 = Uint8List.fromList([0x02]);
  final modPowResult2 = ctx.modPow(baseBytes, expBytes2);
  final modPowBig2 = _bytesToBigInt(modPowResult2);
  
  final expected2 = BigInt.from(7).modPow(BigInt.from(2), nBig);
  print('7^2 mod n:');
  print('  Esperado: 0x${expected2.toRadixString(16)} (${expected2})');
  print('  Obtido:   0x${modPowBig2.toRadixString(16)} (${modPowBig2})');
  print('modPow^2 correto? ${modPowBig2 == expected2}');
  
  // Teste modPow com vários expoentes
  print('\n--- Testando vários expoentes ---');
  final testExps = [4, 7, 8, 15, 16, 17, 63, 64, 65, 66, 67, 126, 127, 128, 129, 255, 256, 511, 512, 1023, 65537];
  for (final e in testExps) {
    final expBytesTest = _intToBytes(e);
    final result = ctx.modPow(baseBytes, expBytesTest);
    final resultBig = _bytesToBigInt(result);
    final expected = BigInt.from(7).modPow(BigInt.from(e), nBig);
    final ok = resultBig == expected;
    print('7^$e (bits=${e.bitLength}): ${ok ? "✓" : "✗"} ${ok ? "" : "(esperado: ${expected}, obtido: ${resultBig})"}');
  }

  ctx.dispose();
}

Uint8List _intToBytes(int value) {
  final bytes = <int>[];
  while (value > 0) {
    bytes.insert(0, value & 0xFF);
    value >>= 8;
  }
  return Uint8List.fromList(bytes.isEmpty ? [0] : bytes);
}

BigInt _bytesToBigInt(Uint8List bytes) {
  BigInt result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}
