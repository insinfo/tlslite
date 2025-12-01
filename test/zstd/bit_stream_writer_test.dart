import 'package:test/test.dart';

import 'package:tlslite/src/zstd/bit_stream_writer.dart';

void main() {
  group('BitStreamWriter', () {
    test('emits bytes in little-endian order', () {
      final writer = BitStreamWriter();
      writer.writeBits(0xAB, 8);
      writer.writeBits(0xCD, 8);
      final bytes = writer.takeBytes();
      expect(bytes, equals([0xAB, 0xCD]));
      expect(writer.pendingBitCount, equals(0));
    });

    test('aligns with zero padding by default', () {
      final writer = BitStreamWriter();
      writer.writeBits(0x0F, 4);
      writer.alignToByte();
      writer.writeBits(0xA5, 8);
      final bytes = writer.takeBytes();
      expect(bytes, equals([0x0F, 0xA5]));
    });

    test('supports non-zero padding when aligning', () {
      final writer = BitStreamWriter();
      writer.writeBits(0x01, 1);
      writer.alignToByte(1);
      final bytes = writer.takeBytes();
      expect(bytes, equals([0xFF]));
    });

    test('can flush full bytes while keeping partial bits pending', () {
      final writer = BitStreamWriter();
      writer.writeBits(0x34, 8);
      writer.writeBits(0x5, 4);
      final head = writer.takeBytes(includePartialByte: false);
      expect(head, equals([0x34]));
      expect(writer.pendingBitCount, equals(4));

      writer.writeBits(0x2, 4);
      final tail = writer.takeBytes();
      expect(tail, equals([0x25]));
      expect(writer.pendingBitCount, equals(0));
    });

    test('closeWithTerminator appends sentinel bit', () {
      final writer = BitStreamWriter();
      writer.writeBits(0x0, 3);
      final bytes = writer.closeWithTerminator();
      expect(bytes.isNotEmpty, isTrue);
      expect(bytes.last, isNot(equals(0)));
    });
  });
}
