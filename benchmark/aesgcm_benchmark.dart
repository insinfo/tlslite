// dart format width=5000
// Benchmark comparando AES-GCM BigInt vs PCLMULQDQ

import 'dart:typed_data';
import 'package:tlslite/src/utils/aesgcm.dart';
import 'package:tlslite/src/utils/aesgcm_asm_x86_64.dart';
import 'package:tlslite/src/utils/rijndael_fast.dart';
import 'package:tlslite/src/utils/rijndael_fast_asm_x86_64.dart';

void main() {
  print('=== AES-GCM Benchmark: BigInt vs PCLMULQDQ ===\n');

  // Verifica suporte de hardware
  final aesNiSupported = AesNiSupport.isSupported;
  final pclmulqdqSupported = PclmulqdqSupport.isSupported;

  print('Hardware Support:');
  print('  AES-NI: $aesNiSupported');
  print('  PCLMULQDQ: $pclmulqdqSupported');
  print('');

  if (!aesNiSupported || !pclmulqdqSupported) {
    print('⚠️  Hardware não suportado. Usando apenas implementação BigInt.');
  }

  // Dados de teste
  final key128 = Uint8List.fromList(List.generate(16, (i) => i));
  final nonce = Uint8List.fromList(List.generate(12, (i) => i));
  final aad = Uint8List.fromList(List.generate(16, (i) => i + 0x80));

  // Tamanhos de dados para teste
  final dataSizes = [16, 64, 256, 1024, 4096, 16384];

  print('Benchmark Results (operations/second):');
  print('─' * 70);
  print('${'Data Size'.padRight(12)} | ${'BigInt'.padRight(15)} | ${'PCLMULQDQ'.padRight(15)} | Speedup');
  print('─' * 70);

  for (final size in dataSizes) {
    final plaintext = Uint8List.fromList(List.generate(size, (i) => i & 0xFF));

    // === BigInt Implementation ===
    final aesSoftware = RijndaelFast(key128);
    final gcmBigInt = AESGCM(key128, 'dart', (block) => aesSoftware.encrypt(block));

    // Warm-up
    for (int i = 0; i < 10; i++) {
      final ct = gcmBigInt.seal(nonce, plaintext, aad);
      gcmBigInt.open(nonce, ct, aad);
    }

    // Benchmark BigInt
    final bigIntIterations = _calculateIterations(size);
    final bigIntStart = DateTime.now();
    for (int i = 0; i < bigIntIterations; i++) {
      final ct = gcmBigInt.seal(nonce, plaintext, aad);
      gcmBigInt.open(nonce, ct, aad);
    }
    final bigIntElapsed = DateTime.now().difference(bigIntStart).inMicroseconds;
    final bigIntOpsPerSec = (bigIntIterations * 2 * 1000000) / bigIntElapsed;

    // === PCLMULQDQ Implementation ===
    double pclmulOpsPerSec = 0;
    double speedup = 0;

    if (aesNiSupported && pclmulqdqSupported) {
      final aesHardware = RijndaelAsmX8664(key128);
      final gcmAsm = AESGCMAsm(key128, (block) => aesHardware.encrypt(block));

      // Warm-up
      for (int i = 0; i < 10; i++) {
        final ct = gcmAsm.seal(nonce, plaintext, aad);
        gcmAsm.open(nonce, ct, aad);
      }

      // Benchmark PCLMULQDQ
      final pclmulIterations = bigIntIterations * 10; // Mais iterações pois é mais rápido
      final pclmulStart = DateTime.now();
      for (int i = 0; i < pclmulIterations; i++) {
        final ct = gcmAsm.seal(nonce, plaintext, aad);
        gcmAsm.open(nonce, ct, aad);
      }
      final pclmulElapsed = DateTime.now().difference(pclmulStart).inMicroseconds;
      pclmulOpsPerSec = (pclmulIterations * 2 * 1000000) / pclmulElapsed;
      speedup = pclmulOpsPerSec / bigIntOpsPerSec;

      gcmAsm.dispose();
    }

    // Print results
    final sizeStr = '${size}B'.padRight(12);
    final bigIntStr = bigIntOpsPerSec.toStringAsFixed(0).padRight(15);
    final pclmulStr = pclmulOpsPerSec > 0 ? pclmulOpsPerSec.toStringAsFixed(0).padRight(15) : 'N/A'.padRight(15);
    final speedupStr = speedup > 0 ? '${speedup.toStringAsFixed(1)}x' : 'N/A';

    print('$sizeStr | $bigIntStr | $pclmulStr | $speedupStr');
  }

  print('─' * 70);

  // Benchmark detalhado de GHASH puro
  if (pclmulqdqSupported) {
    print('\n=== GHASH Pure Benchmark ===\n');

    final h = Uint8List.fromList(List.generate(16, (i) => i + 0x66));
    final data1KB = Uint8List(1024);

    final ghash = GhashAsm(h);

    // Warm-up
    for (int i = 0; i < 100; i++) {
      ghash.reset();
      ghash.update(data1KB);
      ghash.finalize(0, 1024);
    }

    // Benchmark
    final iterations = 10000;
    final start = DateTime.now();
    for (int i = 0; i < iterations; i++) {
      ghash.reset();
      ghash.update(data1KB);
      ghash.finalize(0, 1024);
    }
    final elapsed = DateTime.now().difference(start).inMicroseconds;

    final opsPerSec = (iterations * 1000000) / elapsed;
    final gbPerSec = (iterations * 1024 * 1000000) / (elapsed * 1024 * 1024 * 1024);

    print('GHASH (1KB blocks):');
    print('  Operations/sec: ${opsPerSec.toStringAsFixed(0)}');
    print('  Throughput: ${(gbPerSec * 1024).toStringAsFixed(2)} MB/s');

    ghash.dispose();
  }

  print('\n✅ Benchmark concluído!');
}

int _calculateIterations(int dataSize) {
  // Ajusta iterações baseado no tamanho dos dados
  if (dataSize <= 64) return 1000;
  if (dataSize <= 256) return 500;
  if (dataSize <= 1024) return 200;
  if (dataSize <= 4096) return 100;
  return 50;
}
