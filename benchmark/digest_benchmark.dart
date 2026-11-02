// Benchmark: pure-Dart digests (lib/src/utils/digest) vs package:crypto.
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:tlslite/src/utils/digest/digest.dart';

double _mibPerSec(void Function() f, int bytes) {
  for (var i = 0; i < 5; i++) {
    f();
  }
  final sw = Stopwatch()..start();
  var n = 0;
  while (sw.elapsedMilliseconds < 2000) {
    f();
    n++;
  }
  return n * bytes / (1 << 20) / (sw.elapsedMicroseconds / 1e6);
}

void main() {
  final data = Uint8List(1 << 20);
  for (var i = 0; i < data.length; i++) {
    data[i] = (i * 31 + 7) & 0xff;
  }
  final small = Uint8List.sublistView(data, 0, 64);
  final cases = <String, (void Function(), void Function())>{
    'MD5 1MiB': (() => md5Hash(data), () => crypto.md5.convert(data)),
    'SHA-1 1MiB': (() => sha1Hash(data), () => crypto.sha1.convert(data)),
    'SHA-256 1MiB': (() => sha256Hash(data), () => crypto.sha256.convert(data)),
    'SHA-512 1MiB': (() => sha512Hash(data), () => crypto.sha512.convert(data)),
  };
  print(
      '${'case'.padRight(22)} ${'tlslite MiB/s'.padLeft(14)} ${'crypto MiB/s'.padLeft(14)}  ratio');
  for (final e in cases.entries) {
    final ours = _mibPerSec(e.value.$1, data.length);
    final theirs = _mibPerSec(e.value.$2, data.length);
    print('${e.key.padRight(22)} ${ours.toStringAsFixed(1).padLeft(14)} '
        '${theirs.toStringAsFixed(1).padLeft(14)}  ${(ours / theirs).toStringAsFixed(2)}x');
  }
  // Small-message throughput (record-MAC-sized inputs).
  final smallCases = <String, (void Function(), void Function())>{
    'SHA-256 64B': (
      () => sha256Hash(small),
      () => crypto.sha256.convert(small)
    ),
    'HMAC-SHA256 64B': (
      () => hmac('sha256', small, small),
      () => crypto.Hmac(crypto.sha256, small).convert(small)
    ),
  };
  for (final e in smallCases.entries) {
    final ours = _mibPerSec(e.value.$1, 64);
    final theirs = _mibPerSec(e.value.$2, 64);
    print('${e.key.padRight(22)} ${ours.toStringAsFixed(1).padLeft(14)} '
        '${theirs.toStringAsFixed(1).padLeft(14)}  ${(ours / theirs).toStringAsFixed(2)}x');
  }
  final sh = Uint8List(1 << 20);
  final shakeOurs = _mibPerSec(
      () => (Shake(128)..update(data)).readInto(sh), data.length * 2);
  final sha3Ours = _mibPerSec(() => sha3_256(data), data.length);
  print(
      'SHAKE128 in+out 1MiB: ${shakeOurs.toStringAsFixed(1)} MiB/s; SHA3-256 1MiB: ${sha3Ours.toStringAsFixed(1)} MiB/s');
}
