import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/zstd/huffman_encoder.dart';
import 'package:tlslite/src/zstd/literals.dart';

void main() {
  test('encodes skewed literals with Huffman compression', () {
    final context = HuffmanCompressionContext();
    final literals = Uint8List.fromList(
      List<int>.generate(1024, (index) {
        if (index % 11 == 0) {
          return 220;
        }
        if (index % 7 == 0) {
          return 180;
        }
        return index & 0x3F; // values 0..63
      }),
    );

    final result = tryEncodeLiterals(literals, context);
    expect(result, isNotNull, reason: 'Expected Huffman encoder to produce output');
    expect(result!.type, equals(LiteralsBlockType.compressed));
    expect(result.streamCount, anyOf(1, 4));
    expect(result.usedRepeatTable, isFalse);
    expect(result.compressedSize, lessThan(literals.length));
  });

  test('reuses Huffman table on identical literals', () {
    final context = HuffmanCompressionContext();
    final literals = Uint8List.fromList(
      List<int>.generate(960, (index) {
        if (index % 13 == 0) {
          return 205;
        }
        if (index % 9 == 0) {
          return 170;
        }
        return (index * 3) & 0x7F;
      }),
    );

    final first = tryEncodeLiterals(literals, context);
    expect(first, isNotNull);
    expect(first!.usedRepeatTable, isFalse);

    final second = tryEncodeLiterals(literals, context);
    expect(second, isNotNull, reason: 'Repeat call should reuse previous table');
    expect(second!.type, equals(LiteralsBlockType.repeat));
    expect(second.usedRepeatTable, isTrue);
  });
}
