// dart format width=5000
// Benchmark SHA-256

import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;
import 'package:tlslite/src/experimental/sha256_asm_x86_64.dart';

void main() {
  print('=== SHA-256 Benchmark ===\n');

  final shaNiSupported = ShaNiSupport.isSupported;
  print('SHA-NI suportado: $shaNiSupported');
  if (!shaNiSupported) {
    print('⚠️  SHA-NI não disponível. Usando implementação software otimizada.');
  }
  print('');

  // Tamanhos de dados para teste
  final dataSizes = [64, 256, 1024, 4096, 16384, 65536];

  print('Benchmark Results (hashes/segundo):');
  print('─' * 70);
  print('${'Data Size'.padRight(12)} | ${'crypto (pkg)'.padRight(15)} | ${'Sha256Asm'.padRight(15)} | Ratio');
  print('─' * 70);

  for (final size in dataSizes) {
    final data = Uint8List.fromList(List.generate(size, (i) => i & 0xFF));

    // === Package crypto ===
    // Warm-up
    for (int i = 0; i < 10; i++) {
      crypto.sha256.convert(data);
    }

    final cryptoIterations = _calculateIterations(size);
    final cryptoStart = DateTime.now();
    for (int i = 0; i < cryptoIterations; i++) {
      crypto.sha256.convert(data);
    }
    final cryptoElapsed = DateTime.now().difference(cryptoStart).inMicroseconds;
    final cryptoOpsPerSec = (cryptoIterations * 1000000) / cryptoElapsed;

    // === Sha256Asm ===
    // Warm-up
    for (int i = 0; i < 10; i++) {
      Sha256Asm.hash(data);
    }

    final asmIterations = cryptoIterations;
    final asmStart = DateTime.now();
    for (int i = 0; i < asmIterations; i++) {
      Sha256Asm.hash(data);
    }
    final asmElapsed = DateTime.now().difference(asmStart).inMicroseconds;
    final asmOpsPerSec = (asmIterations * 1000000) / asmElapsed;

    final ratio = asmOpsPerSec / cryptoOpsPerSec;

    final sizeStr = '${size}B'.padRight(12);
    final cryptoStr = cryptoOpsPerSec.toStringAsFixed(0).padRight(15);
    final asmStr = asmOpsPerSec.toStringAsFixed(0).padRight(15);
    final ratioStr = '${ratio.toStringAsFixed(2)}x';

    print('$sizeStr | $cryptoStr | $asmStr | $ratioStr');
  }

  print('─' * 70);

  // Benchmark HMAC
  print('\n=== HMAC-SHA256 Benchmark ===\n');

  final key = Uint8List.fromList(List.generate(32, (i) => i));
  final hmacData = Uint8List.fromList(List.generate(1024, (i) => i & 0xFF));

  // crypto package HMAC
  final cryptoHmac = crypto.Hmac(crypto.sha256, key);
  for (int i = 0; i < 100; i++) {
    cryptoHmac.convert(hmacData);
  }

  final hmacIterations = 5000;
  final cryptoHmacStart = DateTime.now();
  for (int i = 0; i < hmacIterations; i++) {
    cryptoHmac.convert(hmacData);
  }
  final cryptoHmacElapsed = DateTime.now().difference(cryptoHmacStart).inMicroseconds;
  final cryptoHmacOps = (hmacIterations * 1000000) / cryptoHmacElapsed;

  // HmacSha256Asm
  final asmHmac = HmacSha256Asm(key);
  for (int i = 0; i < 100; i++) {
    asmHmac.compute(hmacData);
  }

  final asmHmacStart = DateTime.now();
  for (int i = 0; i < hmacIterations; i++) {
    asmHmac.compute(hmacData);
  }
  final asmHmacElapsed = DateTime.now().difference(asmHmacStart).inMicroseconds;
  final asmHmacOps = (hmacIterations * 1000000) / asmHmacElapsed;

  print('HMAC-SHA256 (1KB data):');
  print('  crypto package: ${cryptoHmacOps.toStringAsFixed(0)} ops/sec');
  print('  HmacSha256Asm:  ${asmHmacOps.toStringAsFixed(0)} ops/sec');
  print('  Ratio: ${(asmHmacOps / cryptoHmacOps).toStringAsFixed(2)}x');

  print('\n✅ Benchmark concluído!');
}

int _calculateIterations(int dataSize) {
  if (dataSize <= 256) return 10000;
  if (dataSize <= 1024) return 5000;
  if (dataSize <= 4096) return 2000;
  if (dataSize <= 16384) return 500;
  return 200;
}
