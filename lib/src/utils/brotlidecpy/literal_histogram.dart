import 'dart:typed_data';

import 'huffman.dart';
import 'huffman_builder.dart';

const int _literalAlphabetSize = 256;

/// Accumulates literal frequencies for a Brotli meta-block.
class BrotliLiteralHistogram {
  BrotliLiteralHistogram()
      : _counts = List<int>.filled(_literalAlphabetSize, 0, growable: false),
        totalLiterals = 0;

  final List<int> _counts;
  int totalLiterals;

  List<int> get counts => _counts;

  void addSlice(Uint8List slice, [int start = 0, int? end]) {
    final limit = end ?? slice.length;
    for (var i = start; i < limit; i++) {
      _counts[slice[i] & 0xFF]++;
    }
    totalLiterals += limit - start;
  }
}

Uint8List buildLiteralCodeLengths(BrotliLiteralHistogram histogram) {
  if (histogram.totalLiterals == 0) {
    return Uint8List(_literalAlphabetSize);
  }
  return buildLimitedHuffmanCodeLengths(
    histogram.counts,
    _literalAlphabetSize,
    MAX_LENGTH,
  );
}

void validateCodeLengths(Uint8List codeLengths) {
  final table = List<HuffmanCode>.generate(2048, (_) => HuffmanCode(0, 0));
  brotli_build_huffman_table(table, 0, 8, codeLengths.toList(), codeLengths.length);
}
