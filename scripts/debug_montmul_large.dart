/// Debug montMul com valores grandes

import 'dart:typed_data';
import 'package:tlslite/src/utils/montgomery_asm_x86_64.dart';

void main() {
  print('Debug montMul com valores grandes');
  print('=' * 60);
  
  // Módulo 128-bit
  final n128 = Uint8List.fromList([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC5,
  ]);
  
  final nBig = _bytesToBigInt(n128);
  print('n = 0x${nBig.toRadixString(16)}');
  
  final ctx = MontgomeryAsmContext.fromModulus(n128);
  final R = BigInt.one << (ctx.numLimbs * 64);
  final Rinv = R.modInverse(nBig);
  
  // Teste montMul com valores perto do limite
  print('\n--- Teste montMul com valores perto do módulo ---');
  
  // a = n - 1 (valor máximo possível)
  final aBytes = Uint8List.fromList([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC4,
  ]);
  
  // b = n - 2
  final bBytes = Uint8List.fromList([
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC3,
  ]);
  
  final aBig = _bytesToBigInt(aBytes);
  final bBig = _bytesToBigInt(bBytes);
  
  print('a = 0x${aBig.toRadixString(16)}');
  print('b = 0x${bBig.toRadixString(16)}');
  
  final aLimbs = Uint64List(ctx.numLimbs);
  final bLimbs = Uint64List(ctx.numLimbs);
  final result = Uint64List(ctx.numLimbs);
  
  _bigIntToLimbs(aBig, aLimbs);
  _bigIntToLimbs(bBig, bLimbs);
  
  ctx.montMul(result, aLimbs, bLimbs);
  
  final resultBig = _limbsToBigInt(result);
  print('montMul(a, b) = 0x${resultBig.toRadixString(16)}');
  
  final expected = (aBig * bBig * Rinv) % nBig;
  print('Esperado: 0x${expected.toRadixString(16)}');
  print('Correto? ${resultBig == expected}');
  
  // Teste montMul^2 (squaring) com valores grandes
  print('\n--- Teste squaring ---');
  ctx.montMul(result, aLimbs, aLimbs);
  final resultSq = _limbsToBigInt(result);
  final expectedSq = (aBig * aBig * Rinv) % nBig;
  print('montMul(a, a) = 0x${resultSq.toRadixString(16)}');
  print('Esperado: 0x${expectedSq.toRadixString(16)}');
  print('Squaring correto? ${resultSq == expectedSq}');
  
  // Teste sequência de operações (simula exponenciação)
  print('\n--- Teste sequência de operações (simula exp) ---');
  
  // Converte 7 para Montgomery
  final base = Uint64List(ctx.numLimbs)..[0] = 7;
  final baseMont = Uint64List(ctx.numLimbs);
  ctx.montMul(baseMont, base, ctx.rr);
  
  final baseMontBig = _limbsToBigInt(baseMont);
  print('baseMont (7*R mod n) = 0x${baseMontBig.toRadixString(16)}');
  
  // Inicializa acc = 1 em Montgomery
  final one = Uint64List(ctx.numLimbs)..[0] = 1;
  final acc = Uint64List(ctx.numLimbs);
  ctx.montMul(acc, one, ctx.rr);
  
  // Simula 7^127 = 7 * 7^2 * 7^4 * ... * 7^64 (todos os bits setados)
  // Ou seja: square e multiply 7 vezes seguidas
  print('\nSimulando 7^127 passo a passo:');
  
  // acc = R mod n (1 em Montgomery)
  final accBig = _limbsToBigInt(acc);
  print('Inicial: acc = 0x${accBig.toRadixString(16)}');
  
  final temp = Uint64List(ctx.numLimbs);
  BigInt expectedAcc = R % nBig; // R mod n = 1 em Montgomery
  
  // Exp = 127 = 0b1111111 (7 bits)
  // Left-to-right: bit 6 primeiro
  for (int bit = 6; bit >= 0; bit--) {
    // Square
    ctx.montMul(temp, acc, acc);
    for (int j = 0; j < ctx.numLimbs; j++) acc[j] = temp[j];
    expectedAcc = (expectedAcc * expectedAcc * Rinv) % nBig;
    
    final accAfterSq = _limbsToBigInt(acc);
    final sqOk = accAfterSq == expectedAcc;
    
    // Multiply (bit sempre 1 para 127)
    ctx.montMul(temp, acc, baseMont);
    for (int j = 0; j < ctx.numLimbs; j++) acc[j] = temp[j];
    expectedAcc = (expectedAcc * baseMontBig * Rinv) % nBig;
    
    final accAfterMul = _limbsToBigInt(acc);
    final mulOk = accAfterMul == expectedAcc;
    
    print('Bit $bit: sq=${sqOk ? "✓" : "✗"} mul=${mulOk ? "✓" : "✗"}');
    if (!sqOk || !mulOk) {
      print('  acc após sq: 0x${accAfterSq.toRadixString(16)}');
      print('  esperado sq: 0x${((expectedAcc * baseMontBig.modInverse(nBig)) % nBig).toRadixString(16)}');
      break;
    }
  }
  
  // Converte de volta
  for (int i = 0; i < ctx.numLimbs; i++) one[i] = 0;
  one[0] = 1;
  ctx.montMul(temp, acc, one);
  final finalResult = _limbsToBigInt(temp);
  
  final expected127 = BigInt.from(7).modPow(BigInt.from(127), nBig);
  print('\nResultado 7^127: 0x${finalResult.toRadixString(16)}');
  print('Esperado: 0x${expected127.toRadixString(16)}');
  print('Correto? ${finalResult == expected127}');
  
  ctx.dispose();
}

BigInt _bytesToBigInt(Uint8List bytes) {
  BigInt result = BigInt.zero;
  for (final b in bytes) {
    result = (result << 8) | BigInt.from(b);
  }
  return result;
}

void _bigIntToLimbs(BigInt value, Uint64List limbs) {
  final mask64 = BigInt.parse('FFFFFFFFFFFFFFFF', radix: 16);
  for (int i = 0; i < limbs.length; i++) {
    limbs[i] = (value & mask64).toSigned(64).toInt();
    value >>= 64;
  }
}

BigInt _limbsToBigInt(Uint64List limbs) {
  BigInt result = BigInt.zero;
  for (int i = limbs.length - 1; i >= 0; i--) {
    result = (result << 64) | BigInt.from(limbs[i]).toUnsigned(64);
  }
  return result;
}
