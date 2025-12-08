/// Benchmark: Montgomery ASM vs BigInt.modPow vs Montgomery Dart
///
/// Compara performance das implementações Montgomery

import 'dart:typed_data';
import 'package:tlslite/src/experimental/montgomery_limbs.dart';
import 'package:tlslite/src/experimental/montgomery_asm_x86_64.dart';

void main() {
  print('='.padRight(70, '='));
  print('Montgomery ASM Benchmark');
  print('='.padRight(70, '='));
  print('');

  // Verifica suporte
  print('Suporte de hardware:');
  print('  BMI2 (MULX):     ${MontgomeryAsmSupport.isBmi2Supported ? "✓" : "✗"}');
  print('  ADX (ADCX/ADOX): ${MontgomeryAsmSupport.isAdxSupported ? "✓" : "✗"}');
  print('');

  // Testa diferentes tamanhos
  _benchmarkSize('Curve-256', 256); // Este usa shellcode ASM!
  _benchmarkSize('RSA-512', 512);
  _benchmarkSize('RSA-1024', 1024);
  _benchmarkSize('RSA-2048', 2048);
  _benchmarkSize('RSA-4096', 4096);

  print('');
  print('='.padRight(70, '='));
}

void _benchmarkSize(String name, int bits) {
  print('');
  print('-'.padRight(70, '-'));
  print('$name ($bits bits)');
  if (bits == 256) {
    print('>>> Este tamanho usa shellcode ASM! <<<');
  }
  print('-'.padRight(70, '-'));

  // Gera dados de teste
  final modBytes = _generateOddNumber(bits ~/ 8);
  final baseBytes = _generateRandomBytes((bits ~/ 8) - 1);
  final expBytes = Uint8List.fromList([0x01, 0x00, 0x01]); // 65537

  final modBigInt = _bytesToBigInt(modBytes);
  final baseBigInt = _bytesToBigInt(baseBytes);
  final expBigInt = _bytesToBigInt(expBytes);

  // Resultado esperado
  final expected = baseBigInt.modPow(expBigInt, modBigInt);

  // Verifica Montgomery Dart
  final dartResult = _bytesToBigInt(modPowBytes(baseBytes, expBytes, modBytes));
  if (dartResult != expected) {
    print('ERRO Montgomery Dart: resultado incorreto!');
    return;
  }
  print('✓ Montgomery Dart (limbs): OK');

  // Verifica Montgomery ASM Context
  final ctx = MontgomeryAsmContext.fromModulus(modBytes);
  try {
    final asmResultBytes = ctx.modPow(baseBytes, expBytes);
    final asmResult = _bytesToBigInt(asmResultBytes);
    if (asmResult != expected) {
      print('ERRO Montgomery ASM: resultado incorreto!');
      print('  numLimbs: ${ctx.numLimbs}');
      print('  Esperado: $expected');
      print('  Obtido:   $asmResult');
      ctx.dispose();
      return;
    }
    print('✓ Montgomery ASM Context: OK ${bits == 256 ? "(usando shellcode 4-limbs)" : "(usando shellcode genérico)"}');
  } catch (e, st) {
    print('ERRO Montgomery ASM: excecao!');
    print('  $e');
    print('  $st');
    ctx.dispose();
    return;
  }
  ctx.dispose();

  // Warmup
  const warmupIterations = 5;
  final ctxWarmup = MontgomeryAsmContext.fromModulus(modBytes);
  for (int i = 0; i < warmupIterations; i++) {
    baseBigInt.modPow(expBigInt, modBigInt);
    modPowBytes(baseBytes, expBytes, modBytes);
    ctxWarmup.modPow(baseBytes, expBytes);
  }
  ctxWarmup.dispose();

  // Benchmark - usando mais iterações para resultados estáveis
  const iterations = 500;

  // BigInt.modPow
  final bigIntStopwatch = Stopwatch()..start();
  for (int i = 0; i < iterations; i++) {
    baseBigInt.modPow(expBigInt, modBigInt);
  }
  bigIntStopwatch.stop();
  final bigIntTimeUs = bigIntStopwatch.elapsedMicroseconds / iterations;

  // Montgomery Dart
  final dartStopwatch = Stopwatch()..start();
  for (int i = 0; i < iterations; i++) {
    modPowBytes(baseBytes, expBytes, modBytes);
  }
  dartStopwatch.stop();
  final dartTimeUs = dartStopwatch.elapsedMicroseconds / iterations;

  // Montgomery ASM Context (usa shellcode para 256-bit)
  final ctxBench = MontgomeryAsmContext.fromModulus(modBytes);
  final asmStopwatch = Stopwatch()..start();
  for (int i = 0; i < iterations; i++) {
    ctxBench.modPow(baseBytes, expBytes);
  }
  asmStopwatch.stop();
  final asmTimeUs = asmStopwatch.elapsedMicroseconds / iterations;
  ctxBench.dispose();

  // Resultados
  print('');
  print('Resultados ($iterations iterações):');
  print('');
  print('  BigInt.modPow:        ${bigIntTimeUs.toStringAsFixed(1)} µs/op');
  print('  Montgomery Limbs:     ${dartTimeUs.toStringAsFixed(1)} µs/op');
  print('  Montgomery ASM Ctx:   ${asmTimeUs.toStringAsFixed(1)} µs/op');
  print('');

  final dartSpeedup = bigIntTimeUs / dartTimeUs;
  final asmSpeedup = bigIntTimeUs / asmTimeUs;
  if (dartSpeedup > 1) {
    print('  Limbs vs BigInt: ${dartSpeedup.toStringAsFixed(2)}x mais rápido');
  } else {
    print('  Limbs vs BigInt: ${(1/dartSpeedup).toStringAsFixed(2)}x mais lento');
  }
  if (asmSpeedup > 1) {
    print('  ASM vs BigInt:   ${asmSpeedup.toStringAsFixed(2)}x mais rápido');
  } else {
    print('  ASM vs BigInt:   ${(1/asmSpeedup).toStringAsFixed(2)}x mais lento');
  }
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
