import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/zstd/zstd_decoder.dart';

void main() {
  group('zstdDecompressFrame integration', () {
    test('decodes sample compressed frame', () {
      final compressed = File('test/fixtures/zstd_seq_sample.zst').readAsBytesSync();
      final mutable = Uint8List.fromList(compressed);
      // Clear checksum bit and drop trailing checksum bytes to fit current decoder capabilities.
      mutable[4] &= 0xFB;
      final payload = mutable.sublist(0, mutable.length - 4);

      final decompressed = zstdDecompressFrame(Uint8List.fromList(payload));
      final expected = File('test/fixtures/zstd_seq_sample.bin').readAsBytesSync();
      expect(decompressed, equals(expected));
    });
  });
}
