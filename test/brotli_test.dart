
import 'dart:io';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/src/utils/brotlidecpy/brotli_input_stream.dart';
import 'package:tlslite/src/utils/brotlidecpy/state.dart';

void main() {
  group('Brotli Decompression', () {
    test('quickfox', () {
      final compressed = File('brotli-google/tests/testdata/quickfox.compressed').readAsBytesSync();
      final expected = File('brotli-google/tests/testdata/quickfox').readAsBytesSync();

      final input = ByteArrayInputStream(compressed);
      final brotliInput = BrotliInputStream(input);

      final output = BytesBuilder();
      final buffer = Uint8List(1024);
      int len;
      while ((len = brotliInput.read(buffer, 0, buffer.length)) != -1) {
        output.add(buffer.sublist(0, len));
      }

      expect(output.toBytes(), equals(expected));
    });

    test('alice29', () {
      final compressed = File('brotli-google/tests/testdata/alice29.txt.compressed').readAsBytesSync();
      final expected = File('brotli-google/tests/testdata/alice29.txt').readAsBytesSync();

      final input = ByteArrayInputStream(compressed);
      final brotliInput = BrotliInputStream(input);

      final output = BytesBuilder();
      final buffer = Uint8List(4096);
      int len;
      while ((len = brotliInput.read(buffer, 0, buffer.length)) != -1) {
        output.add(buffer.sublist(0, len));
      }

      expect(output.toBytes(), equals(expected));
    });
    
    test('empty', () {
      final compressed = File('brotli-google/tests/testdata/empty.compressed').readAsBytesSync();
      final expected = File('brotli-google/tests/testdata/empty').readAsBytesSync();

      final input = ByteArrayInputStream(compressed);
      final brotliInput = BrotliInputStream(input);

      final output = BytesBuilder();
      final buffer = Uint8List(1024);
      int len;
      while ((len = brotliInput.read(buffer, 0, buffer.length)) != -1) {
        output.add(buffer.sublist(0, len));
      }

      expect(output.toBytes(), equals(expected));
    });
  });
}
