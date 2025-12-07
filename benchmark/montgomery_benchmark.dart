/// Benchmark: Montgomery Fast vs BigInt.modPow
///
/// Compara performance da implementação Montgomery otimizada
/// contra o BigInt.modPow nativo do Dart.

import 'dart:typed_data';
import 'package:tlslite/src/utils/montgomery_limbs.dart';

void main() {
  print('='.padRight(70, '='));
  print('Montgomery Fast Benchmark');
  print('='.padRight(70, '='));
  print('');

  // Testa diferentes tamanhos de chave RSA
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
  print('-'.padRight(70, '-'));

  // Gera módulo de teste (número ímpar grande)
  final modBytes = _generateOddNumber(bits ~/ 8);
  final baseBytes = _generateRandomBytes((bits ~/ 8) - 1);
  final expBytes = Uint8List.fromList([0x01, 0x00, 0x01]); // 65537

  final modBigInt = _bytesToBigInt(modBytes);
  final baseBigInt = _bytesToBigInt(baseBytes);
  final expBigInt = _bytesToBigInt(expBytes);

  // Verifica correção primeiro
  final expectedResult = baseBigInt.modPow(expBigInt, modBigInt);
  final montgomeryResult = _bytesToBigInt(modPowBytes(baseBytes, expBytes, modBytes));
  
  if (expectedResult != montgomeryResult) {
    print('ERRO: Resultados diferentes!');
    print('  BigInt:      $expectedResult');
    print('  Montgomery:  $montgomeryResult');
    return;
  }
  print('✓ Verificação de correção OK');
  print('');

  // Warmup
  const warmupIterations = 10;
  for (int i = 0; i < warmupIterations; i++) {
    baseBigInt.modPow(expBigInt, modBigInt);
    modPowBytes(baseBytes, expBytes, modBytes);
  }

  // Benchmark BigInt.modPow
  const iterations = 100;
  
  final bigIntStopwatch = Stopwatch()..start();
  for (int i = 0; i < iterations; i++) {
    baseBigInt.modPow(expBigInt, modBigInt);
  }
  bigIntStopwatch.stop();
  final bigIntTimeUs = bigIntStopwatch.elapsedMicroseconds / iterations;

  // Benchmark Montgomery
  final montStopwatch = Stopwatch()..start();
  for (int i = 0; i < iterations; i++) {
    modPowBytes(baseBytes, expBytes, modBytes);
  }
  montStopwatch.stop();
  final montTimeUs = montStopwatch.elapsedMicroseconds / iterations;

  // Benchmark Montgomery com contexto reutilizado
  final modBN = BN.fromBytes(modBytes);
  final baseBN = BN.fromBytes(baseBytes);
  final expBN = BN.fromBytes(expBytes);
  final mont = MontgomeryModPow(modBN);

  final montReuseStopwatch = Stopwatch()..start();
  for (int i = 0; i < iterations; i++) {
    mont.modPow(baseBN, expBN);
  }
  montReuseStopwatch.stop();
  final montReuseTimeUs = montReuseStopwatch.elapsedMicroseconds / iterations;

  // Resultados
  print('Resultados ($iterations iterações cada):');
  print('');
  print('  BigInt.modPow:           ${bigIntTimeUs.toStringAsFixed(1)} µs/op');
  print('  Montgomery (novo ctx):   ${montTimeUs.toStringAsFixed(1)} µs/op');
  print('  Montgomery (ctx reuse):  ${montReuseTimeUs.toStringAsFixed(1)} µs/op');
  print('');

  final speedupNew = bigIntTimeUs / montTimeUs;
  final speedupReuse = bigIntTimeUs / montReuseTimeUs;

  if (speedupNew > 1) {
    print('  Speedup (novo ctx):   ${speedupNew.toStringAsFixed(2)}x mais rápido');
  } else {
    print('  Speedup (novo ctx):   ${(1/speedupNew).toStringAsFixed(2)}x mais LENTO');
  }

  if (speedupReuse > 1) {
    print('  Speedup (ctx reuse):  ${speedupReuse.toStringAsFixed(2)}x mais rápido');
  } else {
    print('  Speedup (ctx reuse):  ${(1/speedupReuse).toStringAsFixed(2)}x mais LENTO');
  }

  // Throughput
  final opsPerSec = 1000000 / montReuseTimeUs;
  print('');
  print('  Throughput Montgomery: ${opsPerSec.toStringAsFixed(1)} ops/s');
}

/// Gera número ímpar de tamanho específico
Uint8List _generateOddNumber(int byteLength) {
  final bytes = Uint8List(byteLength);
  // Preenche com padrão determinístico
  for (int i = 0; i < byteLength; i++) {
    bytes[i] = ((i * 17 + 37) ^ (i * 13)) & 0xFF;
  }
  // Garante MSB alto para tamanho correto
  bytes[0] |= 0xC0;
  // Garante ímpar
  bytes[byteLength - 1] |= 0x01;
  return bytes;
}

/// Gera bytes pseudo-aleatórios
Uint8List _generateRandomBytes(int length) {
  final bytes = Uint8List(length);
  for (int i = 0; i < length; i++) {
    bytes[i] = ((i * 23 + 41) ^ (i * 7)) & 0xFF;
  }
  return bytes;
}

/// Converte bytes big-endian para BigInt
BigInt _bytesToBigInt(Uint8List bytes) {
  if (bytes.isEmpty) return BigInt.zero;
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return BigInt.parse(hex, radix: 16);
}
