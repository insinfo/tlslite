import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/brotli/dec/Decode.dart';
import 'package:tlslite/src/brotli/enc/brotli_encoder.dart';
import 'package:tlslite/src/brotli/enc/match_finder.dart';

void main() {
  group('BrotliEncoder', () {
    test('literal-only meta-block round trip', () {
      final payload = Uint8List.fromList(utf8.encode('literal-only payload'));
      final encoder = BrotliEncoder(windowBits: 16);
      final matches = <BrotliMatch>[
        BrotliMatch(unmatchedLength: payload.length, matchLength: 0, distance: 0),
      ];

      final compressed = encoder.encodeChunk(payload, matches, isLastChunk: true);
      final decompressed = brotliDecompressBuffer(compressed);

      expect(decompressed, equals(payload));
    });

    test('literal plus copy round trip', () {
      final phrase = utf8.encode('repeat-me-');
      final payload = BytesBuilder(copy: false)
        ..add(phrase)
        ..add(phrase)
        ..add(phrase)
        ..addByte(33); // '!'
      final chunk = payload.takeBytes();

      final encoder = BrotliEncoder(windowBits: 16);
      final finder = BrotliMatchFinder(maxDistance: 1 << 16);
      final matches = finder.findMatches(chunk);
      expect(
        matches.where((m) => m.matchLength > 0).length,
        greaterThan(0),
        reason: 'expected at least one copy command from the match finder',
      );

      final compressed = encoder.encodeChunk(chunk, matches, isLastChunk: true);
      final decompressed = brotliDecompressBuffer(compressed);

      expect(decompressed, equals(chunk));
    });
  });
}
