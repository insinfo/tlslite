import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/zstd/block.dart';
import 'package:tlslite/src/utils/zstd/byte_reader.dart';
import 'package:tlslite/src/utils/zstd/constants.dart';
import 'package:tlslite/src/utils/zstd/frame_header.dart';
import 'package:tlslite/src/utils/zstd/literals.dart';
import 'package:tlslite/src/utils/zstd/zstd_decoder.dart';
import 'package:tlslite/src/utils/zstd/zstd_encoder.dart';

void main() {
  test('wraps empty payload into valid frame', () {
    final frame = zstdCompress(Uint8List(0));
    final result = zstdDecompressFrame(frame);
    expect(result, equals(Uint8List(0)));
  });

  test('round-trips multi-block payload', () {
    final size = zstdBlockSizeMax + 17;
    final payload = Uint8List.fromList(List<int>.generate(size, (i) => i & 0xFF));
    final frame = zstdCompress(payload);
    final result = zstdDecompressFrame(frame);
    expect(result, equals(payload));
  });

  test('emits optional checksum when requested', () {
    final payload = Uint8List.fromList(List<int>.generate(128, (i) => i));
    final frame = zstdCompress(payload, includeChecksum: true);
    final result = zstdDecompressFrame(frame);
    expect(result, equals(payload));

    final corrupted = Uint8List.fromList(frame);
    corrupted[corrupted.length - 1] ^= 0xFF;
    expect(() => zstdDecompressFrame(corrupted), throwsA(isA<ZstdDecodingError>()));
  });

  test('collapses repeated bytes into single RLE block', () {
    final payload = Uint8List.fromList(List<int>.filled(512, 0x7F));
    final frame = zstdCompress(payload);
    final reader = ZstdByteReader(frame);
    parseFrameHeader(reader);
    final blockHeader = readBlockHeader(reader);
    expect(blockHeader.type, equals(ZstdBlockType.rle));
    expect(blockHeader.rleOriginalSize, equals(payload.length));
    expect(reader.readUint8(), equals(0x7F));
    expect(zstdDecompressFrame(frame), equals(payload));
  });

  test('splits long runs across multiple RLE blocks', () {
    final payload = Uint8List.fromList(List<int>.filled(zstdBlockSizeMax + 99, 0x01));
    final frame = zstdCompress(payload);
    final reader = ZstdByteReader(frame);
    parseFrameHeader(reader);

    final first = readBlockHeader(reader);
    expect(first.type, equals(ZstdBlockType.rle));
    expect(first.rleOriginalSize, equals(zstdBlockSizeMax));
    expect(reader.readUint8(), equals(0x01));

    final second = readBlockHeader(reader);
    expect(second.type, equals(ZstdBlockType.rle));
    expect(second.rleOriginalSize, equals(99));
    expect(reader.readUint8(), equals(0x01));

    expect(zstdDecompressFrame(frame), equals(payload));
  });

  test('emits literal-only compressed block when chunk fits payload budget', () {
    final payload = Uint8List.fromList(
      List<int>.generate(zstdBlockSizeMax + 2048, (i) => i & 0xFF),
    );
    final frame = zstdCompress(payload);

    final reader = ZstdByteReader(frame);
    parseFrameHeader(reader);

    final firstBlock = readBlockHeader(reader);
    expect(firstBlock.type, equals(ZstdBlockType.raw));
    reader.skip(firstBlock.compressedSize);

    final secondBlock = readBlockHeader(reader);
    expect(secondBlock.type, equals(ZstdBlockType.compressed));

    final blockReader = ZstdByteReader(reader.readBytes(secondBlock.compressedSize));
    final litHeader = parseLiteralsSectionHeader(blockReader);
    expect(litHeader.type, equals(LiteralsBlockType.raw));
    expect(litHeader.regeneratedSize, equals(2048));

    final literals = blockReader.readBytes(2048);
    expect(literals, equals(payload.sublist(payload.length - 2048)));

    final seqHeader = blockReader.readUint8();
    expect(seqHeader, equals(0));
    expect(blockReader.isEOF, isTrue);
    expect(zstdDecompressFrame(frame), equals(payload));
  });
}
