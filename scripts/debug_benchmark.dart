/// Debug específico do benchmark

import 'dart:typed_data';
import 'package:tlslite/src/utils/montgomery_asm_x86_64.dart';

void main() {
  print('Debug benchmark data');
  print('=' * 60);
  
  // Mesmo código que o benchmark
  final modBytes = _generateOddNumber(32); // 256 bits
  final baseBytes = _generateRandomBytes(31);
  final expBytes = Uint8List.fromList([0x01, 0x00, 0x01]); // 65537

  final modBigInt = _bytesToBigInt(modBytes);
  final baseBigInt = _bytesToBigInt(baseBytes);
  final expBigInt = _bytesToBigInt(expBytes);

  print('mod = 0x${modBigInt.toRadixString(16)}');
  print('base = 0x${baseBigInt.toRadixString(16)}');
  print('exp = 65537');
  
  // Resultado esperado
  final expected = baseBigInt.modPow(expBigInt, modBigInt);
  print('\nEsperado (BigInt): 0x${expected.toRadixString(16)}');
  
  // Montgomery ASM
  final ctx = MontgomeryAsmContext.fromModulus(modBytes);
  print('\nnumLimbs = ${ctx.numLimbs}');
  print('modulus = [${ctx.modulus.map((x) => '0x${x.toUnsigned(64).toRadixString(16)}').join(', ')}]');
  
  // Verifica modulus
  BigInt modulusBig = BigInt.zero;
  for (int i = ctx.numLimbs - 1; i >= 0; i--) {
    modulusBig = (modulusBig << 64) | BigInt.from(ctx.modulus[i]).toUnsigned(64);
  }
  print('modulus como BigInt: 0x${modulusBig.toRadixString(16)}');
  print('mod == modulusBig? ${modBigInt == modulusBig}');
  
  final result = ctx.modPow(baseBytes, expBytes);
  final resultBig = _bytesToBigInt(result);
  print('\nObtido (ASM): 0x${resultBig.toRadixString(16)}');
  print('Correto? ${resultBig == expected}');
  
  if (resultBig != expected) {
    print('\nDiferença: ${(resultBig - expected).abs()}');
    
    // Testa modPow passo a passo
    print('\n--- Debug passo a passo ---');
    _debugModPow(ctx, baseBytes, expBytes, expected);
  }
  
  ctx.dispose();
}

void _debugModPow(MontgomeryAsmContext ctx, Uint8List baseBytes, Uint8List expBytes, BigInt expected) {
  final numLimbs = ctx.numLimbs;
  final R = BigInt.one << (numLimbs * 64);
  
  BigInt modulusBig = BigInt.zero;
  for (int i = numLimbs - 1; i >= 0; i--) {
    modulusBig = (modulusBig << 64) | BigInt.from(ctx.modulus[i]).toUnsigned(64);
  }
  
  final Rinv = R.modInverse(modulusBig);
  
  // Converte base para limbs
  final base = _bytesToLimbs64(baseBytes, numLimbs);
  print('base limbs: [${base.map((x) => '0x${x.toUnsigned(64).toRadixString(16)}').join(', ')}]');
  
  // baseMont = base * RR
  final baseMont = Uint64List(numLimbs);
  ctx.montMul(baseMont, base, ctx.rr);
  
  final baseMontBig = _limbsToBigInt(baseMont);
  final baseBig = _bytesToBigInt(baseBytes);
  final baseMontExpected = (baseBig * R) % modulusBig;
  print('baseMont: 0x${baseMontBig.toRadixString(16)}');
  print('baseMont esperado: 0x${baseMontExpected.toRadixString(16)}');
  print('baseMont OK? ${baseMontBig == baseMontExpected}');
  
  // acc = 1 * RR
  final one = Uint64List(numLimbs)..[0] = 1;
  final acc = Uint64List(numLimbs);
  ctx.montMul(acc, one, ctx.rr);
  
  final accBig = _limbsToBigInt(acc);
  final accExpected = R % modulusBig;
  print('acc inicial (1_mont): 0x${accBig.toRadixString(16)}');
  print('acc esperado (R mod n): 0x${accExpected.toRadixString(16)}');
  print('acc inicial OK? ${accBig == accExpected}');
  
  // Verifica alguns passos da exponenciação
  final exp = _bytesToLimbs64(expBytes, numLimbs);
  final expBits = _countBits64(exp);
  print('\nexp bits = $expBits');
  print('exp limbs: [${exp.map((x) => '0x${x.toUnsigned(64).toRadixString(16)}').join(', ')}]');
  
  // Simula alguns passos
  final temp = Uint64List(numLimbs);
  BigInt expectedAcc = R % modulusBig;
  
  int errorsShown = 0;
  for (int i = expBits - 1; i >= 0 && errorsShown < 5; i--) {
    // Square
    ctx.montMul(temp, acc, acc);
    for (int j = 0; j < numLimbs; j++) acc[j] = temp[j];
    expectedAcc = (expectedAcc * expectedAcc * Rinv) % modulusBig;
    
    final accAfterSq = _limbsToBigInt(acc);
    final sqOk = accAfterSq == expectedAcc;
    
    // Multiply if bit set
    final limbIdx = i ~/ 64;
    final bitIdx = i % 64;
    final bitSet = limbIdx < exp.length && ((exp[limbIdx] >> bitIdx) & 1) == 1;
    
    if (bitSet) {
      ctx.montMul(temp, acc, baseMont);
      for (int j = 0; j < numLimbs; j++) acc[j] = temp[j];
      expectedAcc = (expectedAcc * baseMontExpected * Rinv) % modulusBig;
    }
    
    final accAfterMul = _limbsToBigInt(acc);
    final mulOk = accAfterMul == expectedAcc;
    
    if (!sqOk || !mulOk) {
      print('Bit $i: sq=${sqOk ? "✓" : "✗"} mul=${mulOk ? "✓" : "✗"} bitSet=$bitSet');
      if (!sqOk) {
        print('  acc após sq: 0x${accAfterSq.toRadixString(16)}');
        print('  esperado:    0x${((expectedAcc * baseMontExpected.modInverse(modulusBig)) % modulusBig).toRadixString(16)}');
      }
      errorsShown++;
    }
  }
}

Uint64List _bytesToLimbs64(Uint8List bytes, int numLimbs) {
  final limbs = Uint64List(numLimbs);
  int limbIdx = 0;
  int shift = 0;
  BigInt limb = BigInt.zero;
  final mask64 = BigInt.parse('FFFFFFFFFFFFFFFF', radix: 16);

  for (int i = bytes.length - 1; i >= 0; i--) {
    limb |= BigInt.from(bytes[i]) << shift;
    shift += 8;
    if (shift >= 64) {
      limbs[limbIdx++] = (limb & mask64).toSigned(64).toInt();
      limb = BigInt.zero;
      shift = 0;
    }
  }
  if (shift > 0 && limbIdx < numLimbs) {
    limbs[limbIdx] = (limb & mask64).toSigned(64).toInt();
  }
  return limbs;
}

int _countBits64(Uint64List limbs) {
  for (int i = limbs.length - 1; i >= 0; i--) {
    if (limbs[i] != 0) {
      return i * 64 + BigInt.from(limbs[i]).toUnsigned(64).bitLength;
    }
  }
  return 0;
}

BigInt _limbsToBigInt(Uint64List limbs) {
  BigInt result = BigInt.zero;
  for (int i = limbs.length - 1; i >= 0; i--) {
    result = (result << 64) | BigInt.from(limbs[i]).toUnsigned(64);
  }
  return result;
}

Uint8List _generateOddNumber(int byteLength) {
  final bytes = Uint8List(byteLength);
  for (int i = 0; i < byteLength; i++) {
    bytes[i] = ((i * 17 + 37) ^ (i * 13)) & 0xFF;
  }
  bytes[0] |= 0xC0;
  bytes[byteLength - 1] |= 0x01;
  return bytes;
}

Uint8List _generateRandomBytes(int length) {
  final bytes = Uint8List(length);
  for (int i = 0; i < length; i++) {
    bytes[i] = ((i * 23 + 41) ^ (i * 7)) & 0xFF;
  }
  return bytes;
}

BigInt _bytesToBigInt(Uint8List bytes) {
  if (bytes.isEmpty) return BigInt.zero;
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return BigInt.parse(hex, radix: 16);
}
