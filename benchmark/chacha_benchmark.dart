// dart format width=5000
// Benchmark: ChaCha20 ASM (SSE2) vs Original

import 'dart:typed_data';
import 'package:tlslite/src/experimental/chacha_asm_x86_64.dart';
import 'package:tlslite/src/utils/chacha.dart' as original;

void main() {
  print('=== ChaCha20 ASM (SSE2) Benchmark ===\n');

  if (!ChaChaAsmSupport.isSSE2Supported) {
    print('SSE2 não suportado!');
    return;
  }
  print('SSE2: Suportado\n');

  final key = Uint8List.fromList(List.generate(32, (i) => i));
  final nonce = Uint8List.fromList(List.generate(12, (i) => i));

  final sizes = [64, 256, 1024, 4096, 16384, 65536];

  for (final size in sizes) {
    final data = Uint8List.fromList(List.generate(size, (i) => i & 0xFF));

    // Aquecimento
    for (int i = 0; i < 50; i++) {
      ChaChaAsm(key, nonce).encrypt(data);
      original.ChaCha(key, nonce).encrypt(data);
    }

    final iterations = size < 1024 ? 5000 : (size < 16384 ? 500 : 50);

    // Original
    final swOrig = Stopwatch()..start();
    for (int i = 0; i < iterations; i++) {
      original.ChaCha(key, nonce).encrypt(data);
    }
    swOrig.stop();
    final timeOrig = swOrig.elapsedMicroseconds / iterations;

    // ASM
    final swAsm = Stopwatch()..start();
    for (int i = 0; i < iterations; i++) {
      ChaChaAsm(key, nonce).encrypt(data);
    }
    swAsm.stop();
    final timeAsm = swAsm.elapsedMicroseconds / iterations;

    print('Tamanho: ${size.toString().padLeft(5)} bytes');
    print('  Original: ${timeOrig.toStringAsFixed(2)} µs');
    print('  ASM SSE2: ${timeAsm.toStringAsFixed(2)} µs');
    print('  Speedup:  ${(timeOrig / timeAsm).toStringAsFixed(2)}x\n');
  }

  // Verificação
  print('=== Verificação ===');
  final testData = Uint8List.fromList(List.generate(1000, (i) => i & 0xFF));
  final origResult = original.ChaCha(key, nonce).encrypt(testData);
  final asmResult = ChaChaAsm(key, nonce).encrypt(testData);
  
  bool correct = true;
  for (int i = 0; i < origResult.length; i++) {
    if (origResult[i] != asmResult[i]) {
      correct = false;
      print('Diferença em [$i]: orig=${origResult[i]}, asm=${asmResult[i]}');
      break;
    }
  }
  print('Resultados iguais: $correct');

  // Throughput 1MB
  print('\n=== Throughput ===');
  final largeData = Uint8List(1024 * 1024);
  
  final swOrigT = Stopwatch()..start();
  for (int i = 0; i < 10; i++) {
    original.ChaCha(key, nonce).encrypt(largeData);
  }
  swOrigT.stop();
  final tpOrig = (10.0 * 1024 * 1024) / (swOrigT.elapsedMicroseconds / 1000000) / (1024 * 1024);

  final swAsmT = Stopwatch()..start();
  for (int i = 0; i < 10; i++) {
    ChaChaAsm(key, nonce).encrypt(largeData);
  }
  swAsmT.stop();
  final tpAsm = (10.0 * 1024 * 1024) / (swAsmT.elapsedMicroseconds / 1000000) / (1024 * 1024);

  print('Original: ${tpOrig.toStringAsFixed(2)} MB/s');
  print('ASM SSE2: ${tpAsm.toStringAsFixed(2)} MB/s');
  print('Speedup:  ${(tpAsm / tpOrig).toStringAsFixed(2)}x');
}
