import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/zstd/block.dart';
import 'package:tlslite/src/utils/zstd/byte_reader.dart';
import 'package:tlslite/src/utils/zstd/frame_header.dart';
import 'package:tlslite/src/utils/zstd/literals.dart';
import 'package:tlslite/src/utils/zstd/zstd_decoder.dart';

Uint8List _buildFrame({
  required List<int> payload,
  bool useRle = false,
}) {
  final builder = BytesBuilder(copy: false);
  builder.add([0x28, 0xB5, 0x2F, 0xFD]);
  final fcsId = payload.length > 255 ? 1 : 0;
  final descriptor = (fcsId << 6) | 0x20; // single segment, no checksum, dict=0
  builder.add([descriptor]);
  if (fcsId == 0) {
    builder.add([payload.length]);
  } else {
    final size = payload.length - 256;
    builder.add([size & 0xFF, (size >> 8) & 0xFF]);
  }

  final blockSize = useRle ? payload.length : payload.length;
  final blockType = useRle ? 1 : 0;
  final header = (blockSize << 3) | (blockType << 1) | 1; // last block
  builder.add([header & 0xFF, (header >> 8) & 0xFF, (header >> 16) & 0xFF]);
  if (useRle) {
    builder.add([payload.first]);
  } else {
    builder.add(payload);
  }
  return builder.takeBytes();
}

void main() {
  test('decodes raw block frame', () {
    final payload = List<int>.generate(32, (i) => i);
    final frame = _buildFrame(payload: payload);
    final result = zstdDecompressFrame(Uint8List.fromList(frame));
    expect(result, equals(Uint8List.fromList(payload)));
  });

  test('decodes RLE block frame', () {
    final payload = List<int>.filled(12, 0xAB);
    final frame = _buildFrame(payload: payload, useRle: true);
    final result = zstdDecompressFrame(Uint8List.fromList(frame));
    expect(result, equals(Uint8List.fromList(payload)));
  });

  test('throws on checksum flag', () {
    final badFrame = Uint8List.fromList([
      0x28,
      0xB5,
      0x2F,
      0xFD,
      0x24, // checksum flag set
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
    ]);
    expect(() => zstdDecompressFrame(badFrame), throwsA(isA<ZstdDecodingError>()));
  });

  test('decompresses Huffman literal-only frame', () {
    final source = File('test/fixtures/zstd_seq_sample.zst').readAsBytesSync();
    final reader = ZstdByteReader(Uint8List.fromList(source));
    parseFrameHeader(reader);
    final blockHeader = readBlockHeader(reader);
    expect(blockHeader.type, equals(ZstdBlockType.compressed));

    final literalsResult = decodeLiteralsBlock(reader);
    final literalEnd = reader.offset;
    final literalStart = literalEnd - literalsResult.bytesConsumed;
    final literalSectionBytes = Uint8List.fromList(source.sublist(literalStart, literalEnd));
    final literals = literalsResult.literals;

    final sequencesSectionSize = 1; // nbSeq = 0
    final compressedSize = literalSectionBytes.length + sequencesSectionSize;

    final builder = BytesBuilder(copy: false);
    builder.add([0x28, 0xB5, 0x2F, 0xFD]);
    final fcsId = literals.length > 255 ? 1 : 0;
    final descriptor = (fcsId << 6) | 0x20;
    builder.add([descriptor]);
    if (fcsId == 0) {
      builder.add([literals.length]);
    } else {
      final size = literals.length - 256;
      builder.add([size & 0xFF, (size >> 8) & 0xFF]);
    }

    const blockType = 2; // compressed
    final blockHeaderValue = (compressedSize << 3) | (blockType << 1) | 1;
    builder.add([
      blockHeaderValue & 0xFF,
      (blockHeaderValue >> 8) & 0xFF,
      (blockHeaderValue >> 16) & 0xFF,
    ]);

    builder.add(literalSectionBytes);
    builder.add([0x00]); // zero sequences

    final frame = builder.takeBytes();
    final result = zstdDecompressFrame(Uint8List.fromList(frame));
    expect(result, equals(literals));
  });
}
