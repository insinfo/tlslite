import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/zstd/block.dart';
import 'package:tlslite/src/utils/zstd/byte_reader.dart';
import 'package:tlslite/src/utils/zstd/constants.dart';
import 'package:tlslite/src/utils/zstd/dictionary.dart';
import 'package:tlslite/src/utils/zstd/encoder_match_finder.dart';
import 'package:tlslite/src/utils/zstd/frame_header.dart';
import 'package:tlslite/src/utils/zstd/literals.dart';
import 'package:tlslite/src/utils/zstd/sequences.dart';
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
    final frame = zstdCompress(payload, enableMatchPlanner: false);

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

  test('emits Huffman-compressed literal section for skewed data', () {
    final prefix = List<int>.generate(zstdBlockSizeMax, (i) => i & 0xFF);
    final skewed = List<int>.generate(4096, (i) {
      if (i % 9 == 0) {
        return 213;
      }
      if (i % 5 == 0) {
        return 180;
      }
      return i & 0x3F;
    });
    final payload = Uint8List.fromList([...prefix, ...skewed]);

    final frame = zstdCompress(payload, enableMatchPlanner: false);

    final reader = ZstdByteReader(frame);
    parseFrameHeader(reader);

    final firstBlock = readBlockHeader(reader);
    expect(firstBlock.type, equals(ZstdBlockType.raw));
    reader.skip(firstBlock.compressedSize);

    final secondBlock = readBlockHeader(reader);
    expect(secondBlock.type, equals(ZstdBlockType.compressed));

    final blockReader = ZstdByteReader(reader.readBytes(secondBlock.compressedSize));
    final literalHeader = parseLiteralsSectionHeader(blockReader);
    expect(literalHeader.type, equals(LiteralsBlockType.compressed));
    expect(literalHeader.regeneratedSize, equals(skewed.length));
  });

  test('invokes match planner hook when repeats exist', () {
    final payload = Uint8List.fromList(
      'abcabcabcabcabcabcabcabcabcabcabcabcabcabcabcabc'.codeUnits,
    );
    ZstdMatchPlan? observed;
    final frame = zstdCompress(
      payload,
      onMatchPlan: (plan) => observed = plan,
    );
    expect(observed, isNotNull);
    expect(observed!.hasMatches, isTrue);
    expect(zstdDecompressFrame(frame), equals(payload));
  });

  test('emits sequence section when planner finds reusable ranges', () {
    final seed = 'match-sequence-demo-1234';
    final pattern = seed.codeUnits;
    final buffer = <int>[];
    for (var i = 0; i < 64; i++) {
      buffer.addAll(pattern);
    }
    final payload = Uint8List.fromList([...buffer, ...buffer]);

    final frame = zstdCompress(payload);
    final reader = ZstdByteReader(frame);
    parseFrameHeader(reader);

    final blockHeader = readBlockHeader(reader);
    expect(blockHeader.type, equals(ZstdBlockType.compressed));

    final blockReader = ZstdByteReader(reader.readBytes(blockHeader.compressedSize));
    final literalHeader = parseLiteralsSectionHeader(blockReader);
    expect(literalHeader.type, equals(LiteralsBlockType.raw));
    final literalBytes = blockReader.readBytes(literalHeader.regeneratedSize);
    expect(literalBytes.length, equals(literalHeader.regeneratedSize));

    final sequencesHeader = parseSequencesHeader(blockReader);
    expect(sequencesHeader.nbSeq, greaterThan(0));
    expect(sequencesHeader.llEncoding.type, isNot(equals(SymbolEncodingType.predefined)));
    expect(sequencesHeader.ofEncoding.type, isNot(equals(SymbolEncodingType.predefined)));
    expect(sequencesHeader.mlEncoding.type, isNot(equals(SymbolEncodingType.predefined)));
    expect(blockReader.remaining, greaterThan(0));

    expect(zstdDecompressFrame(frame), equals(payload));
  });

  test('planner exposes repeat-offset usage via block stats', () {
    final pattern = 'abcd'.codeUnits;
    final payloadBuffer = <int>[];
    for (var i = 0; i < 80; i++) {
      payloadBuffer.addAll(pattern);
    }
    final payload = Uint8List.fromList(payloadBuffer);

    ZstdEncoderBlockStats? stats;
    final frame = zstdCompress(
      payload,
      onBlockEncoded: (event) {
        if (event.blockType == ZstdBlockType.compressed && event.sequenceCount > 0) {
          stats = event;
        }
      },
    );

    expect(stats, isNotNull, reason: 'Expected compressed block with sequences');
    expect(stats!.usedRepeatOffsets, isTrue,
        reason: 'Planner should leverage repeat-offset encoding for tight loops');
    expect(zstdDecompressFrame(frame), equals(payload));
  });

  test('reuses sequence tables when histograms match across blocks', () {
    final pattern = 'repeat-sequence-histogram-demo-'.codeUnits;
    final blockBytes = List<int>.generate(
      zstdBlockSizeMax,
      (index) => pattern[index % pattern.length],
    );
    final payload = Uint8List.fromList([...blockBytes, ...blockBytes]);

    final frame = zstdCompress(payload);
    final reader = ZstdByteReader(frame);
    parseFrameHeader(reader);

    final firstBlock = readBlockHeader(reader);
    expect(firstBlock.type, equals(ZstdBlockType.compressed));
    final firstBlockReader = ZstdByteReader(reader.readBytes(firstBlock.compressedSize));
    final firstLiteralHeader = parseLiteralsSectionHeader(firstBlockReader);
    _skipLiteralSection(firstBlockReader, firstLiteralHeader);
    final firstSequences = parseSequencesHeader(firstBlockReader);
    expect(firstSequences.llEncoding.type, isNot(equals(SymbolEncodingType.predefined)));
    expect(firstSequences.ofEncoding.type, isNot(equals(SymbolEncodingType.predefined)));
    expect(firstSequences.mlEncoding.type, isNot(equals(SymbolEncodingType.predefined)));

    final secondBlock = readBlockHeader(reader);
    expect(secondBlock.type, equals(ZstdBlockType.compressed));
    final secondBlockReader = ZstdByteReader(reader.readBytes(secondBlock.compressedSize));
    final secondLiteralHeader = parseLiteralsSectionHeader(secondBlockReader);
    _skipLiteralSection(secondBlockReader, secondLiteralHeader);
    final secondSequences = parseSequencesHeader(secondBlockReader);
    expect(secondSequences.llEncoding.type, equals(SymbolEncodingType.repeat));
    expect(secondSequences.mlEncoding.type, equals(SymbolEncodingType.repeat));
    expect(secondSequences.ofEncoding.type, isNot(equals(SymbolEncodingType.predefined)));

    expect(zstdDecompressFrame(frame), equals(payload));
  });

  test('emits dictionary id and reuses dictionary history for matches', () {
    final dictionary = ZstdDictionary.raw(
      dictId: 0xC011EC7,
      content: Uint8List.fromList(
        'shared-dictionary-segment-lorem-ipsum-1234'.codeUnits,
      ),
    );
    final payload = Uint8List.fromList(
      'shared-dictionary-segment-lorem-ipsum-1234::payload-body-unique'
          .codeUnits,
    );

    final frame = zstdCompress(payload, dictionary: dictionary);
    final reader = ZstdByteReader(frame);
    final header = parseFrameHeader(reader);
    expect(header.dictId, equals(dictionary.dictId));

    final blockHeader = readBlockHeader(reader);
    expect(blockHeader.type, equals(ZstdBlockType.compressed));

    final blockReader = ZstdByteReader(reader.readBytes(blockHeader.compressedSize));
    final literalHeader = parseLiteralsSectionHeader(blockReader);
    _skipLiteralSection(blockReader, literalHeader);
    final sequencesHeader = parseSequencesHeader(blockReader);
    expect(sequencesHeader.nbSeq, greaterThan(0));

    final decoded = zstdDecompressFrame(
      frame,
      dictionaries: {dictionary.dictId: dictionary},
    );
    expect(decoded, equals(payload));
  });
}

void _skipLiteralSection(ZstdByteReader reader, LiteralsSectionHeader header) {
  switch (header.type) {
    case LiteralsBlockType.raw:
      reader.skip(header.regeneratedSize);
      return;
    case LiteralsBlockType.rle:
      reader.skip(1);
      return;
    case LiteralsBlockType.compressed:
    case LiteralsBlockType.repeat:
      final payloadSize = header.compressedSize;
      expect(payloadSize, isNotNull,
          reason: 'Compressed/repeat literal headers must define payload size');
      reader.skip(payloadSize!);
      return;
  }
}
