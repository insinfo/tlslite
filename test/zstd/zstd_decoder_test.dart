import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/zstd/xxhash64.dart';
import 'package:tlslite/src/zstd/bit_stream.dart' show bitContainerSize;
import 'package:tlslite/src/zstd/block.dart';
import 'package:tlslite/src/zstd/byte_reader.dart';
import 'package:tlslite/src/zstd/dictionary.dart';
import 'package:tlslite/src/zstd/frame_header.dart';
import 'package:tlslite/src/zstd/literals.dart';
import 'package:tlslite/src/zstd/sequences.dart';
import 'package:tlslite/src/zstd/zstd_decoder.dart';
import 'package:tlslite/src/zstd/zstd_encoder.dart';

import 'zstd_test_utils.dart';

Uint8List _buildFrame({
  required List<int> payload,
  bool useRle = false,
  bool includeChecksum = false,
}) {
  final builder = BytesBuilder(copy: false);
  builder.add([0x28, 0xB5, 0x2F, 0xFD]);
  final fcsId = payload.length > 255 ? 1 : 0;
  var descriptor = (fcsId << 6) | 0x20; // single segment, dict=0
  if (includeChecksum) {
    descriptor |= 0x04;
  }
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
  if (includeChecksum) {
    final checksum = xxHash64(Uint8List.fromList(payload)).toUnsigned(32).toInt();
    builder.add([
      checksum & 0xFF,
      (checksum >> 8) & 0xFF,
      (checksum >> 16) & 0xFF,
      (checksum >> 24) & 0xFF,
    ]);
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

  test('validates content checksum flag', () {
    final payload = List<int>.generate(10, (i) => i + 1);
    final frame = _buildFrame(payload: payload, includeChecksum: true);
    final result = zstdDecompressFrame(Uint8List.fromList(frame));
    expect(result, equals(Uint8List.fromList(payload)));

    final corrupted = Uint8List.fromList(frame);
    corrupted[corrupted.length - 1] ^= 0xFF;
    expect(() => zstdDecompressFrame(corrupted), throwsA(isA<ZstdDecodingError>()));
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

  test('decoder seeds dictionary tables for repeat literal blocks', () {
    final dictionary = buildSeededDictionary();
    final payload = Uint8List.fromList(
      'XYZXYZXYZXYZXYZXYZXYZXYZXYZXYZXYZXYZ'.codeUnits,
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
    expect(sequencesHeader.llEncoding.type, equals(SymbolEncodingType.repeat));
    expect(sequencesHeader.ofEncoding.type, equals(SymbolEncodingType.repeat));
    expect(sequencesHeader.mlEncoding.type, equals(SymbolEncodingType.repeat));

    final decoded = zstdDecompressFrame(
      frame,
      dictionaries: {dictionary.dictId: dictionary},
    );
    expect(decoded, equals(payload));
  });

  test('formatted dictionary fixture handles multi-frame streams', () {
    final dictBytes = File('test/fixtures/http-dict-missing-symbols').readAsBytesSync();
    final dictionary = parseZstdDictionary(Uint8List.fromList(dictBytes));
    final firstPayload = Uint8List.fromList('GET / HTTP/1.1\r\nHost: example\r\n\r\n'.codeUnits);
    final secondPayload = Uint8List.fromList('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'.codeUnits);

    final firstFrame = zstdCompress(firstPayload, dictionary: dictionary);
    final secondFrame = zstdCompress(secondPayload, dictionary: dictionary);
    final stream = Uint8List.fromList([...firstFrame, ...secondFrame]);

    final decoded = zstdDecompressFrame(
      stream,
      dictionaries: {dictionary.dictId: dictionary},
    );
    expect(
      decoded,
      equals(Uint8List.fromList([...firstPayload, ...secondPayload])),
    );
  });

  test('decompresses frame referencing dictionary history', () {
    final dictId = 0x01020304;
    final dictionaryContent = Uint8List.fromList('hello'.codeUnits);
    final dictionary = ZstdDictionary.raw(dictId: dictId, content: dictionaryContent);
    final frame = _buildDictionaryMatchFrame(
      dictId: dictId,
      sequencesBitstream: _minimalSequenceBitstream(),
    );

    final result = zstdDecompressFrame(
      Uint8List.fromList(frame),
      dictionaries: {dictId: dictionary},
    );

    expect(result, equals(dictionaryContent));
  });

  test('parses formatted dictionary fixtures', () {
    final bytes = File('test/fixtures/http-dict-missing-symbols').readAsBytesSync();
    final dictionary = parseZstdDictionary(Uint8List.fromList(bytes));

    expect(dictionary.dictId, equals(0x52A7275D));
    expect(dictionary.content, isNotEmpty);
    expect(dictionary.huffmanTable, isNotNull);
    expect(dictionary.sequenceTables, isNotNull);
    expect(dictionary.initialPrevOffsets.length, equals(3));
  });

  test('requires fallback ID for raw dictionary buffers', () {
    final raw = Uint8List.fromList(List<int>.generate(16, (i) => i));
    expect(() => parseZstdDictionary(raw), throwsA(isA<ZstdFrameFormatException>()));

    final dictionary = parseZstdDictionary(raw, fallbackDictId: 42);
    expect(dictionary.dictId, equals(42));
    expect(dictionary.content, equals(raw));
  });

  test('concatenated frames with skippable trailer', () {
    final first = _buildFrame(payload: [1, 2, 3]);
    final second = _buildFrame(payload: [4, 5]);
    final skippable = _buildSkippableChunk([0xAA, 0xBB]);
    final stream = Uint8List.fromList([
      ...first,
      ...skippable,
      ...second,
    ]);
    final result = zstdDecompressFrame(stream);
    expect(result, equals(Uint8List.fromList([1, 2, 3, 4, 5])));
  });

  test('enforces expected output size across frames', () {
    final first = _buildFrame(payload: [1, 2, 3]);
    final second = _buildFrame(payload: [4]);
    final stream = Uint8List.fromList([
      ...first,
      ...second,
    ]);

    final ok = zstdDecompress(
      Uint8List.fromList(stream),
      expectedOutputSize: 4,
    );
    expect(ok, equals(Uint8List.fromList([1, 2, 3, 4])));

    expect(
      () => zstdDecompress(
        Uint8List.fromList(stream),
        expectedOutputSize: 3,
      ),
      throwsA(isA<ZstdDecodingError>()),
    );

    expect(
      () => zstdDecompress(
        Uint8List.fromList(stream),
        expectedOutputSize: 5,
      ),
      throwsA(isA<ZstdDecodingError>()),
    );
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

Uint8List _buildDictionaryMatchFrame({
  required int dictId,
  required Uint8List sequencesBitstream,
}) {
  final literalsHeader = [0x00];
  final sequenceHeader = [0x01, 0x54, 0x00, 0x03, 0x02];
  final blockPayload = <int>[
    ...literalsHeader,
    ...sequenceHeader,
    ...sequencesBitstream,
  ];
  final blockSize = blockPayload.length;
  final blockHeaderValue = (blockSize << 3) | (ZstdBlockType.compressed.index << 1) | 1;

  final builder = BytesBuilder(copy: false);
  builder.add([0x28, 0xB5, 0x2F, 0xFD]);
  builder.add([0x03]);
  builder.add([0x38]);
  builder.add([
    dictId & 0xFF,
    (dictId >> 8) & 0xFF,
    (dictId >> 16) & 0xFF,
    (dictId >> 24) & 0xFF,
  ]);
  builder.add([
    blockHeaderValue & 0xFF,
    (blockHeaderValue >> 8) & 0xFF,
    (blockHeaderValue >> 16) & 0xFF,
  ]);
  builder.add(blockPayload);
  return builder.takeBytes();
}

Uint8List _minimalSequenceBitstream() {
  final data = Uint8List(bitContainerSize);
  data[data.length - 1] = 0x80;
  return data;
}

Uint8List _buildSkippableChunk(List<int> userData) {
  final builder = BytesBuilder(copy: false);
  builder.add([0x50, 0x2A, 0x4D, 0x18]);
  final size = userData.length;
  builder.add([
    size & 0xFF,
    (size >> 8) & 0xFF,
    (size >> 16) & 0xFF,
    (size >> 24) & 0xFF,
  ]);
  builder.add(userData);
  return builder.takeBytes();
}
