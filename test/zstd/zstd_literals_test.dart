import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/zstd/byte_reader.dart';
import 'package:tlslite/src/utils/zstd/frame_header.dart';
import 'package:tlslite/src/utils/zstd/block.dart';
import 'package:tlslite/src/utils/zstd/literals.dart';

void main() {
  group('Literals header parsing', () {
    test('parses raw 1-byte header', () {
      final reader = ZstdByteReader(Uint8List.fromList([0x28]));
      final header = parseLiteralsSectionHeader(reader);
      expect(header.type, equals(LiteralsBlockType.raw));
      expect(header.regeneratedSize, equals(5));
      expect(header.headerSize, equals(1));
      expect(header.streamCount, equals(1));
      expect(header.compressedSize, isNull);
      expect(reader.offset, equals(1));
    });

    test('parses raw 2-byte header', () {
      final headerBytes = [0x44, 0x06];
      final reader = ZstdByteReader(Uint8List.fromList(headerBytes));
      final header = parseLiteralsSectionHeader(reader);
      expect(header.headerSize, equals(2));
      expect(header.regeneratedSize, equals(100));
      expect(reader.offset, equals(2));
    });

    test('parses RLE 3-byte header', () {
      final val = (1000 << 4) | (3 << 2) | 1;
      final bytes = [val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF];
      final reader = ZstdByteReader(Uint8List.fromList(bytes));
      final header = parseLiteralsSectionHeader(reader);
      expect(header.type, equals(LiteralsBlockType.rle));
      expect(header.regeneratedSize, equals(1000));
      expect(header.headerSize, equals(3));
    });

    test('parses compressed single-stream header', () {
      final headerBytes = _buildCompressedHeader(
        type: LiteralsBlockType.compressed,
        sizeFormat: 0,
        regeneratedSize: 20,
        compressedSize: 10,
      );
      final reader = ZstdByteReader(Uint8List.fromList(headerBytes));
      final header = parseLiteralsSectionHeader(reader);
      expect(header.type, equals(LiteralsBlockType.compressed));
      expect(header.regeneratedSize, equals(20));
      expect(header.compressedSize, equals(10));
      expect(header.streamCount, equals(1));
      expect(header.headerSize, equals(3));
    });

    test('parses compressed four-stream header', () {
      final headerBytes = _buildCompressedHeader(
        type: LiteralsBlockType.repeat,
        sizeFormat: 1,
        regeneratedSize: 30,
        compressedSize: 12,
      );
      final reader = ZstdByteReader(Uint8List.fromList(headerBytes));
      final header = parseLiteralsSectionHeader(reader);
      expect(header.type, equals(LiteralsBlockType.repeat));
      expect(header.streamCount, equals(4));
      expect(header.compressedSize, equals(12));
      expect(header.headerSize, equals(3));
    });
  });

  group('Raw Literals', () {
    test('decodes 1-byte header raw literals (small)', () {
      // Type = 0 (raw), lhlCode = 0 => lhSize = 1
      // litSize encoded in bits [3..7] of byte0
      // litSize = 5 => byte0 = (5 << 3) | 0 = 0x28
      final literalData = [0x01, 0x02, 0x03, 0x04, 0x05];
      final input = Uint8List.fromList([0x28, ...literalData]);
      final reader = ZstdByteReader(input);
      final result = decodeLiteralsBlock(reader);
      expect(result.literals, equals(Uint8List.fromList(literalData)));
      expect(result.bytesConsumed, equals(6)); // 1 header + 5 data
    });

    test('decodes 2-byte header raw literals', () {
      // Type = 0 (raw), lhlCode = 1 => lhSize = 2
      // litSize encoded in bits [4..15] of LE16
      // litSize = 100 => value = (100 << 4) | (1 << 2) | 0 = 0x0644
      // little endian: [0x44, 0x06]
      final literalData = List<int>.generate(100, (i) => i & 0xFF);
      final header = [(100 << 4) | (1 << 2), (100 << 4) >> 8];
      final input = Uint8List.fromList([...header, ...literalData]);
      final reader = ZstdByteReader(input);
      final result = decodeLiteralsBlock(reader);
      expect(result.literals, equals(Uint8List.fromList(literalData)));
      expect(result.bytesConsumed, equals(2 + 100));
    });

    test('decodes 3-byte header raw literals', () {
      // Type = 0 (raw), lhlCode = 3 => lhSize = 3
      // litSize encoded in bits [4..23] of LE24
      // litSize = 1000 => value = (1000 << 4) | (3 << 2) | 0 = 0x3E8C
      // Need 24-bit value
      final litSize = 1000;
      final val = (litSize << 4) | (3 << 2) | 0; // 0x3E8C
      final header = [val & 0xFF, (val >> 8) & 0xFF, (val >> 16) & 0xFF];
      final literalData = List<int>.generate(litSize, (i) => i & 0xFF);
      final input = Uint8List.fromList([...header, ...literalData]);
      final reader = ZstdByteReader(input);
      final result = decodeLiteralsBlock(reader);
      expect(result.literals.length, equals(litSize));
      expect(result.bytesConsumed, equals(3 + litSize));
    });
  });

  group('RLE Literals', () {
    test('decodes 1-byte header RLE literals', () {
      // Type = 1 (rle), lhlCode = 0 => lhSize = 1
      // litSize = 10 => byte0 = (10 << 3) | 1 = 0x51
      // RLE byte follows header
      final rleByte = 0xAB;
      final input = Uint8List.fromList([0x51, rleByte]);
      final reader = ZstdByteReader(input);
      final result = decodeLiteralsBlock(reader);
      expect(result.literals, equals(Uint8List(10)..fillRange(0, 10, rleByte)));
      expect(result.bytesConsumed, equals(2)); // 1 header + 1 RLE byte
    });

    test('decodes 2-byte header RLE literals', () {
      // Type = 1 (rle), lhlCode = 1 => lhSize = 2
      // litSize = 200 => value = (200 << 4) | (1 << 2) | 1 = 0x0C85
      final litSize = 200;
      final val = (litSize << 4) | (1 << 2) | 1;
      final header = [val & 0xFF, (val >> 8) & 0xFF];
      final rleByte = 0x55;
      final input = Uint8List.fromList([...header, rleByte]);
      final reader = ZstdByteReader(input);
      final result = decodeLiteralsBlock(reader);
      expect(result.literals.length, equals(litSize));
      expect(result.literals.every((b) => b == rleByte), isTrue);
      expect(result.bytesConsumed, equals(3)); // 2 header + 1 RLE byte
    });
  });

  group('Compressed Literals', () {
    test('decodes Huffman literals from fixture block', () {
      final data = File('test/fixtures/zstd_seq_sample.zst').readAsBytesSync();
      final reader = ZstdByteReader(Uint8List.fromList(data));

      final frameHeader = parseFrameHeader(reader);
      expect(frameHeader.windowSize, greaterThan(0));

      final blockHeader = readBlockHeader(reader);
      expect(blockHeader.type, equals(ZstdBlockType.compressed));

      final literalsStart = reader.offset;
      final peekReader = ZstdByteReader(reader.buffer)..offset = literalsStart;
      final header = parseLiteralsSectionHeader(peekReader);

      final result = decodeLiteralsBlock(reader);
      expect(result.literals.length, equals(header.regeneratedSize));
      expect(result.huffmanTable, isNotNull);
      expect(header.compressedSize, isNotNull);
      expect(result.bytesConsumed, equals(header.headerSize + header.compressedSize!));
    });
  });
}

List<int> _buildCompressedHeader({
  required LiteralsBlockType type,
  required int sizeFormat,
  required int regeneratedSize,
  required int compressedSize,
}) {
  assert(type == LiteralsBlockType.compressed || type == LiteralsBlockType.repeat);
  assert(sizeFormat >= 0 && sizeFormat <= 3);
  final base = (type.index & 0x3) | ((sizeFormat & 0x3) << 2);
  int value;
  late final int headerSize;
  switch (sizeFormat) {
    case 0:
    case 1:
      headerSize = 3;
      value = base | ((regeneratedSize & 0x3FF) << 4) | ((compressedSize & 0x3FF) << 14);
      break;
    case 2:
      headerSize = 4;
      value = base | ((regeneratedSize & 0x3FFF) << 4) | ((compressedSize & 0x3FFF) << 18);
      break;
    case 3:
      headerSize = 5;
      final low = base | ((regeneratedSize & 0x3FFFF) << 4) | (((compressedSize & 0x3FFFF) & 0x3FF) << 22);
      return [
        low & 0xFF,
        (low >> 8) & 0xFF,
        (low >> 16) & 0xFF,
        (low >> 24) & 0xFF,
        (compressedSize >> 10) & 0xFF,
      ];
    default:
      throw ArgumentError('Invalid sizeFormat $sizeFormat');
  }

  return List<int>.generate(headerSize, (i) => (value >> (8 * i)) & 0xFF);
}
