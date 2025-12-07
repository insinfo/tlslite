/// Debug montMul 4 limbs

import 'dart:typed_data';
import 'package:tlslite/src/utils/montgomery_asm_x86_64.dart';

void main() {
  print('Debug montMul 4 limbs');
  print('=' * 60);
  
  // Módulo do benchmark (256 bits = 4 limbs)
  final modBytes = _generateOddNumber(32);
  final modBig = _bytesToBigInt(modBytes);
  print('mod = 0x${modBig.toRadixString(16)}');
  
  final ctx = MontgomeryAsmContext.fromModulus(modBytes);
  print('numLimbs = ${ctx.numLimbs}');
  
  final R = BigInt.one << (ctx.numLimbs * 64);
  final Rinv = R.modInverse(modBig);
  
  // Teste montMul simples: 7 * 11
  print('\n--- Teste montMul(7, 11) ---');
  final a = Uint64List(ctx.numLimbs)..[0] = 7;
  final b = Uint64List(ctx.numLimbs)..[0] = 11;
  final result = Uint64List(ctx.numLimbs);
  
  ctx.montMul(result, a, b);
  
  final resultBig = _limbsToBigInt(result);
  final expected = (BigInt.from(7) * BigInt.from(11) * Rinv) % modBig;
  print('result = 0x${resultBig.toRadixString(16)}');
  print('expected = 0x${expected.toRadixString(16)}');
  print('OK? ${resultBig == expected}');
  
  // Teste montMul(1, RR) - deve dar R mod n
  print('\n--- Teste montMul(1, RR) = R mod n ---');
  final one = Uint64List(ctx.numLimbs)..[0] = 1;
  ctx.montMul(result, one, ctx.rr);
  
  final resultOneMont = _limbsToBigInt(result);
  final expectedOneMont = R % modBig;
  print('result = 0x${resultOneMont.toRadixString(16)}');
  print('expected = 0x${expectedOneMont.toRadixString(16)}');
  print('OK? ${resultOneMont == expectedOneMont}');
  
  // Teste montMul(base, RR)
  print('\n--- Teste montMul(base, RR) ---');
  final baseBytes = _generateRandomBytes(31);
  final baseBig = _bytesToBigInt(baseBytes);
  final base = _bytesToLimbs64(baseBytes, ctx.numLimbs);
  
  ctx.montMul(result, base, ctx.rr);
  
  final resultBase = _limbsToBigInt(result);
  final expectedBase = (baseBig * R) % modBig;
  print('result = 0x${resultBase.toRadixString(16)}');
  print('expected = 0x${expectedBase.toRadixString(16)}');
  print('OK? ${resultBase == expectedBase}');
  
  // Verifica RR
  print('\n--- Verificando RR ---');
  final rrBig = _limbsToBigInt(ctx.rr);
  final rrExpected = (R * R) % modBig;
  print('RR = 0x${rrBig.toRadixString(16)}');
  print('R^2 mod n = 0x${rrExpected.toRadixString(16)}');
  print('RR OK? ${rrBig == rrExpected}');
  
  // Verifica n0
  print('\n--- Verificando n0 ---');
  final n0Big = BigInt.from(ctx.n0).toUnsigned(64);
  final n0limb = BigInt.from(ctx.modulus[0]).toUnsigned(64);
  final product = (n0limb * n0Big) & BigInt.parse('FFFFFFFFFFFFFFFF', radix: 16);
  print('n0 = 0x${n0Big.toRadixString(16)}');
  print('n[0] * n0 mod 2^64 = 0x${product.toRadixString(16)}');
  print('Esperado: 0xffffffffffffffff');
  print('n0 OK? ${product == BigInt.parse('FFFFFFFFFFFFFFFF', radix: 16)}');
  
  ctx.dispose();
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
