import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/brotli/dec/Decode.dart';
import 'package:tlslite/src/brotli/enc/brotli_encoder.dart';
import 'package:tlslite/src/brotli/enc/match_finder.dart';

void main() {
  group('BrotliMatchFinder', () {
    test('emits a copy for repeated patterns', () {
      final payload =
          Uint8List.fromList(utf8.encode('hello hello hello hello'));
      final finder = BrotliMatchFinder(maxDistance: 1 << 16);

      final matches = finder.findMatches(payload);
      final hasCopy =
          matches.any((match) => match.matchLength > 0 && match.distance > 0);

      expect(hasCopy, isTrue, reason: 'expected at least one copy command');
    });
  });

  group('Brotli literal encoder', () {
    test('round-trips via decoder when matches are present', () {
      final pattern = utf8.encode('0123456789ABCDEF');
      final payload = Uint8List.fromList(
          List<int>.generate(4096, (i) => pattern[i % pattern.length]));

      final compressed = brotliCompressLiteral(payload);
      final decompressed = brotliDecompressBuffer(compressed);

      expect(decompressed, equals(payload));
    });

    test('encodes mixed literal/copy workloads', () {
      final literalBlock = Uint8List.fromList(
        List<int>.generate(1024, (i) => i & 0xFF),
      );
      final repeatedPhrase = utf8.encode('repeat-me-repeat-me-');
      final builder = BytesBuilder(copy: false);
      for (var i = 0; i < 16; i++) {
        builder
          ..add(literalBlock)
          ..add(repeatedPhrase)
          ..add(repeatedPhrase);
      }
      final payload = builder.takeBytes();

      final compressed = brotliCompressLiteral(payload);
      final decompressed = brotliDecompressBuffer(compressed);

      expect(decompressed, equals(payload));
    });

    test('splits payloads exceeding a single meta-block', () {
      const metaBlockLimit = 0xFFFFFF + 1; // Matches encoder chunk cap.
      final totalLength = metaBlockLimit + 4096;
      final payload = Uint8List(totalLength);
      for (var i = 0; i < totalLength; i++) {
        payload[i] = i & 0xFF;
      }

      final compressed = brotliCompressLiteral(payload);
      final decompressed = brotliDecompressBuffer(compressed);

      expect(decompressed.length, equals(payload.length));
      expect(decompressed, equals(payload));
    });
  });
}
