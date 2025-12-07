// dart format width=5000
// Benchmark para Poly1305 otimizado vs original

import 'dart:typed_data';

import 'package:tlslite/src/utils/poly1305_fast.dart';
import 'package:tlslite/src/utils/poly1305.dart' as original;

void main() {
  print('=== Poly1305 Benchmark ===\n');

  final key = Uint8List.fromList(List.generate(32, (i) => i));

  // Tamanhos de teste
  final sizes = [64, 256, 1024, 4096, 16384, 65536];

  for (final size in sizes) {
    final data = Uint8List.fromList(List.generate(size, (i) => i & 0xFF));

    // Aquecimento
    for (int i = 0; i < 100; i++) {
      Poly1305Asm(key).createTag(data);
      original.Poly1305(key).createTag(data);
    }

    // Benchmark original (BigInt)
    final iterations = size < 1024 ? 10000 : (size < 16384 ? 1000 : 100);

    final swOriginal = Stopwatch()..start();
    for (int i = 0; i < iterations; i++) {
      original.Poly1305(key).createTag(data);
    }
    swOriginal.stop();
    final timeOriginal = swOriginal.elapsedMicroseconds / iterations;

    // Benchmark otimizado
    final swOptimized = Stopwatch()..start();
    for (int i = 0; i < iterations; i++) {
      Poly1305Asm(key).createTag(data);
    }
    swOptimized.stop();
    final timeOptimized = swOptimized.elapsedMicroseconds / iterations;

    final speedup = timeOriginal / timeOptimized;

    print('Tamanho: ${size.toString().padLeft(5)} bytes');
    print('  Original (BigInt): ${timeOriginal.toStringAsFixed(2)} µs');
    print('  Otimizado (int64): ${timeOptimized.toStringAsFixed(2)} µs');
    print('  Speedup: ${speedup.toStringAsFixed(2)}x');
    print('');
  }

  // Verificação de correção
  print('=== Verificação de Correção ===');
  final testData = Uint8List.fromList(List.generate(1000, (i) => i & 0xFF));
  final tagOriginal = original.Poly1305(key).createTag(testData);
  final tagOptimized = Poly1305Asm(key).createTag(testData);

  bool correct = true;
  for (int i = 0; i < 16; i++) {
    if (tagOriginal[i] != tagOptimized[i]) {
      correct = false;
      break;
    }
  }
  print('Tags iguais: $correct');

  // Throughput
  print('\n=== Throughput (MB/s) ===');
  final largeData = Uint8List(1024 * 1024); // 1 MB
  for (int i = 0; i < largeData.length; i++) {
    largeData[i] = i & 0xFF;
  }

  final swThroughputOrig = Stopwatch()..start();
  for (int i = 0; i < 10; i++) {
    original.Poly1305(key).createTag(largeData);
  }
  swThroughputOrig.stop();
  final throughputOrig = (10 * 1024 * 1024) / (swThroughputOrig.elapsedMicroseconds / 1000000) / (1024 * 1024);

  final swThroughputOpt = Stopwatch()..start();
  for (int i = 0; i < 10; i++) {
    Poly1305Asm(key).createTag(largeData);
  }
  swThroughputOpt.stop();
  final throughputOpt = (10 * 1024 * 1024) / (swThroughputOpt.elapsedMicroseconds / 1000000) / (1024 * 1024);

  print('Original (BigInt): ${throughputOrig.toStringAsFixed(2)} MB/s');
  print('Otimizado (int64): ${throughputOpt.toStringAsFixed(2)} MB/s');
  print('Speedup: ${(throughputOpt / throughputOrig).toStringAsFixed(2)}x');
}
