import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/zstd/window.dart';

void main() {
  test('primeHistory seeds dictionary content into window', () {
    final window = ZstdWindow(8);
    final history = Uint8List.fromList([1, 2, 3, 4, 5]);
    window.primeHistory(history);

    final output = <int>[];
    window.copyMatch(5, 5, output);

    expect(output, equals(history));
  });

  test('primeHistory keeps the most recent bytes when truncated', () {
    final window = ZstdWindow(4);
    final history = Uint8List.fromList([10, 11, 12, 13, 14, 15]);
    window.primeHistory(history);

    final output = <int>[];
    window.copyMatch(4, 4, output);

    expect(output, equals([12, 13, 14, 15]));
  });
}
