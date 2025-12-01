import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/brotlidecpy/huffman.dart';
import 'package:tlslite/src/utils/brotlidecpy/huffman_builder.dart';
import 'package:tlslite/src/utils/brotlidecpy/literal_histogram.dart';

void main() {
  test('counts literals across slices', () {
    final histogram = BrotliLiteralHistogram();
    histogram.addSlice(Uint8List.fromList([1, 2, 3, 1]));
    histogram.addSlice(Uint8List.fromList([2, 2, 3]));
    expect(histogram.totalLiterals, equals(7));
    expect(histogram.counts[1], equals(2));
    expect(histogram.counts[2], equals(3));
    expect(histogram.counts[3], equals(2));
  });

  test('builds canonical code lengths accepted by decoder table builder', () {
    final histogram = BrotliLiteralHistogram();
    histogram.addSlice(Uint8List.fromList(List<int>.generate(1024, (i) => i & 0xFF)));
    final codeLengths = buildLiteralCodeLengths(histogram);
    final table = List<HuffmanCode>.generate(4096, (_) => HuffmanCode(0, 0));
    final size = brotli_build_huffman_table(table, 0, 8, codeLengths.toList(), codeLengths.length);
    expect(size, greaterThan(0));
  });

  test('single symbol gets length one', () {
    final histogram = BrotliLiteralHistogram();
    histogram.addSlice(Uint8List.fromList(List<int>.filled(10, 7)));
    final codeLengths = buildLiteralCodeLengths(histogram);
    expect(codeLengths[7], equals(1));
    expect(codeLengths.where((len) => len > 0).length, equals(1));
  });

  test('builder enforces max depth for large alphabets', () {
    const alphabetSize = 704;
    final counts = List<int>.filled(alphabetSize, 1);
    counts[0] = 1 << 20;
    final lengths = buildLimitedHuffmanCodeLengths(counts, alphabetSize, MAX_LENGTH);
    expect(lengths.every((len) => len <= MAX_LENGTH), isTrue);
  });
}
