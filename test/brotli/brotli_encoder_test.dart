import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/brotlidecpy/brotli_encoder.dart';
import 'package:tlslite/src/utils/brotlidecpy/decode.dart';

void main() {
  group('brotli encoder round trips', () {
    test('raw meta-blocks preserve payload', () {
      final samples = <Uint8List>[
        Uint8List(0),
        Uint8List.fromList(List<int>.generate(32, (i) => i)),
        Uint8List.fromList(List<int>.generate(brotliRawMaxChunkLength + 17, (i) => i & 0xFF)),
      ];

      for (final input in samples) {
        final encoded = brotliCompressRaw(input);
        final decoded = brotliDecompressBuffer(encoded);
        expect(decoded, equals(input), reason: 'raw round-trip mismatch for size ${input.length}');
      }
    });

    test('literal-only meta-blocks round trip', () {
      final chunk = Uint8List.fromList(List<int>.generate(8192, (i) => (i * 13) & 0xFF));
      final encoded = brotliCompressLiteral(chunk);
      final decoded = brotliDecompressBuffer(encoded);
      expect(decoded, equals(chunk));
    });

    test('literal encoder splits large input across meta-blocks', () {
      final large = Uint8List.fromList(
        List<int>.generate(brotliRawMaxChunkLength * 2 + 5, (i) => (i * 31) & 0xFF),
      );
      final encoded = brotliCompressLiteral(large);
      final decoded = brotliDecompressBuffer(encoded);
      expect(decoded, equals(large));
    });
  });
}
