/// Benchmark: Montgomery Fast vs BigInt.modPow
///
/// Compares the performance of the optimized Montgomery implementation
/// against Dart's native BigInt.modPow.

import 'dart:typed_data';
import 'package:tlslite/src/experimental/montgomery_limbs.dart';

void main() {
  print('='.padRight(70, '='));
  print('Montgomery Fast Benchmark');
  print('='.padRight(70, '='));
  print('');

  // Test several RSA key sizes
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

  // Generate a test modulus (large odd number)
  final modBytes = _generateOddNumber(bits ~/ 8);
  final baseBytes = _generateRandomBytes((bits ~/ 8) - 1);
  final expBytes = Uint8List.fromList([0x01, 0x00, 0x01]); // 65537

  final modBigInt = _bytesToBigInt(modBytes);
  final baseBigInt = _bytesToBigInt(baseBytes);
  final expBigInt = _bytesToBigInt(expBytes);

  // Check correctness first
  final expectedResult = baseBigInt.modPow(expBigInt, modBigInt);
  final montgomeryResult = _bytesToBigInt(modPowBytes(baseBytes, expBytes, modBytes));
  
  if (expectedResult != montgomeryResult) {
    print('ERROR: results differ!');
    print('  BigInt:      $expectedResult');
    print('  Montgomery:  $montgomeryResult');
    return;
  }
  print('✓ Correctness check OK');
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

  // Benchmark Montgomery with a reused context
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

  // Results
  print('Results ($iterations iterations each):');
  print('');
  print('  BigInt.modPow:           ${bigIntTimeUs.toStringAsFixed(1)} µs/op');
  print('  Montgomery (new ctx):    ${montTimeUs.toStringAsFixed(1)} µs/op');
  print('  Montgomery (ctx reuse):  ${montReuseTimeUs.toStringAsFixed(1)} µs/op');
  print('');

  final speedupNew = bigIntTimeUs / montTimeUs;
  final speedupReuse = bigIntTimeUs / montReuseTimeUs;

  if (speedupNew > 1) {
    print('  Speedup (new ctx):    ${speedupNew.toStringAsFixed(2)}x faster');
  } else {
    print('  Speedup (new ctx):    ${(1/speedupNew).toStringAsFixed(2)}x SLOWER');
  }

  if (speedupReuse > 1) {
    print('  Speedup (ctx reuse):  ${speedupReuse.toStringAsFixed(2)}x faster');
  } else {
    print('  Speedup (ctx reuse):  ${(1/speedupReuse).toStringAsFixed(2)}x SLOWER');
  }

  // Throughput
  final opsPerSec = 1000000 / montReuseTimeUs;
  print('');
  print('  Throughput Montgomery: ${opsPerSec.toStringAsFixed(1)} ops/s');
}

/// Generates an odd number with the given bit size.
Uint8List _generateOddNumber(int byteLength) {
  final bytes = Uint8List(byteLength);
  // Fill with a deterministic pattern
  for (int i = 0; i < byteLength; i++) {
    bytes[i] = ((i * 17 + 37) ^ (i * 13)) & 0xFF;
  }
  // Set the top bit so the size is exact
  bytes[0] |= 0xC0;
  // Make it odd
  bytes[byteLength - 1] |= 0x01;
  return bytes;
}

/// Generates pseudo-random bytes.
Uint8List _generateRandomBytes(int length) {
  final bytes = Uint8List(length);
  for (int i = 0; i < length; i++) {
    bytes[i] = ((i * 23 + 41) ^ (i * 7)) & 0xFF;
  }
  return bytes;
}

/// Converts big-endian bytes to a BigInt.
BigInt _bytesToBigInt(Uint8List bytes) {
  if (bytes.isEmpty) return BigInt.zero;
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return BigInt.parse(hex, radix: 16);
}
