import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/brotlidecpy/bit_reader.dart';
import 'package:tlslite/src/utils/brotlidecpy/brotli_encoder.dart';
import 'package:tlslite/src/utils/brotlidecpy/decode.dart';

void main() {
  test('literal compressor round trips payloads of varying sizes', () {
    const lengths = [1, 19, 1024, 70000];
    for (final length in lengths) {
      final payload = Uint8List.fromList(
        List<int>.generate(length, (i) => (i * 37 + length) & 0xFF),
      );
      final stream = brotliCompressLiteral(payload, windowBits: 17);
      final decoded = brotliDecompressBuffer(stream);
      expect(decoded, equals(payload), reason: 'Failed for length $length');
    }
  });

  test('literal compressor emits compressed meta-block header', () {
    final payload = Uint8List.fromList(
      List<int>.generate(4096, (i) => (i * 11 + 7) & 0xFF),
    );
    final stream = brotliCompressLiteral(payload, windowBits: 18);
    final reader = BrotliBitReader(stream);
    final windowBits = decodeWindowBits(reader);
    expect(windowBits, equals(18));

    final header = decodeMetaBlockLength(reader);
    expect(header.inputEnd, isFalse);
    expect(header.isUncompressed, isFalse);
    expect(header.metaBlockLength, equals(payload.length));
  });
}
