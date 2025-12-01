import 'dart:typed_data';

import 'xxhash64.dart';
import 'block.dart';
import 'byte_reader.dart';
import 'dictionary.dart';
import 'frame_header.dart';
import 'literals.dart';
import 'sequences.dart';
import 'window.dart';

class ZstdDecodingError implements Exception {
  ZstdDecodingError(this.message);
  final String message;
  @override
  String toString() => 'ZstdDecodingError: $message';
}

/// Decompresses one or more concatenated Zstd frames contained in [input].
/// Dictionaries can be supplied either through the [dictionaries] map or the
/// [dictionaryProvider] callback. When [expectedOutputSize] is provided the
/// decoder enforces that the total number of produced bytes matches this value
/// to protect higher level callers from zip-bomb style inputs.
Uint8List zstdDecompress(
  Uint8List input, {
  int? expectedOutputSize,
  Map<int, ZstdDictionary>? dictionaries,
  ZstdDictionaryProvider? dictionaryProvider,
}) {
  final reader = ZstdByteReader(input);
  final builder = BytesBuilder(copy: false);
  var totalOutputBytes = 0;
  var decodedFrame = false;
  while (true) {
    final header = tryParseFrameHeader(reader);
    if (header == null) {
      break;
    }
    decodedFrame = true;
    final frame = _decodeFrame(
      reader: reader,
      header: header,
      dictionaries: dictionaries,
      dictionaryProvider: dictionaryProvider,
    );
    totalOutputBytes += frame.length;
    if (expectedOutputSize != null && totalOutputBytes > expectedOutputSize) {
      throw ZstdDecodingError(
        'Decompressed output exceeded expected size $expectedOutputSize',
      );
    }
    builder.add(frame);
  }
  if (!decodedFrame) {
    throw ZstdDecodingError('Input did not contain a valid Zstd frame');
  }

  final result = builder.takeBytes();
  if (expectedOutputSize != null && totalOutputBytes != expectedOutputSize) {
    throw ZstdDecodingError(
      'Decompressed output size mismatch: expected $expectedOutputSize, got $totalOutputBytes',
    );
  }
  return result;
}

/// Backwards-compatible wrapper that decodes every frame inside [input].
Uint8List zstdDecompressFrame(
  Uint8List input, {
  int? expectedOutputSize,
  Map<int, ZstdDictionary>? dictionaries,
  ZstdDictionaryProvider? dictionaryProvider,
}) {
  return zstdDecompress(
    input,
    expectedOutputSize: expectedOutputSize,
    dictionaries: dictionaries,
    dictionaryProvider: dictionaryProvider,
  );
}

Uint8List _decodeFrame({
  required ZstdByteReader reader,
  required ZstdFrameHeader header,
  Map<int, ZstdDictionary>? dictionaries,
  ZstdDictionaryProvider? dictionaryProvider,
}) {
  final output = <int>[];
  final window = ZstdWindow(header.windowSize);

  final dictionary = _resolveDictionary(
    dictId: header.dictId,
    dictionaries: dictionaries,
    dictionaryProvider: dictionaryProvider,
  );
  if (header.dictId != 0 && dictionary == null) {
    throw ZstdDecodingError('Dictionary ${header.dictId} was requested but not provided');
  }
  if (dictionary != null) {
    window.primeHistory(dictionary.content);
  }

  var prevOffsets = List<int>.from(dictionary?.initialPrevOffsets ?? const [1, 4, 8]);
  HuffmanDecodingTable? lastHuffmanTable = dictionary?.huffmanTable;
  final sequenceState = SequenceDecodingState(
    literalLengthTable: dictionary?.sequenceTables?.literalLengthTable,
    offsetTable: dictionary?.sequenceTables?.offsetTable,
    matchLengthTable: dictionary?.sequenceTables?.matchLengthTable,
  );

  var finished = false;
  while (!finished) {
    if (reader.isEOF) {
      throw ZstdDecodingError('Unexpected end of input inside frame');
    }
    final blockHeader = readBlockHeader(reader);
    ensureBlockSizeWithinWindow(header, blockHeader);
    final blockDataStart = reader.offset;
    final blockDataEnd = blockDataStart + blockHeader.compressedSize;
    if (blockDataEnd > reader.buffer.length) {
      throw ZstdDecodingError('Block exceeds input size');
    }

    switch (blockHeader.type) {
      case ZstdBlockType.raw:
        if (reader.remaining < blockHeader.compressedSize) {
          throw ZstdDecodingError('Unexpected end of input while reading RAW block');
        }
        final raw = reader.readBytes(blockHeader.compressedSize);
        window.appendBytes(raw, output);
        break;
      case ZstdBlockType.rle:
        if (reader.remaining < 1) {
          throw ZstdDecodingError('Unexpected end of input while reading RLE block');
        }
        final value = reader.readUint8();
        window.repeatByte(value, blockHeader.rleOriginalSize, output);
        break;
      case ZstdBlockType.compressed:
        final literalsResult = decodeLiteralsBlock(
          reader,
          repeatTable: lastHuffmanTable,
        );
        if (literalsResult.huffmanTable != null) {
          lastHuffmanTable = literalsResult.huffmanTable;
        }
        if (reader.offset > blockDataEnd) {
          throw ZstdDecodingError('Literals section overruns block payload');
        }

        final sequencesHeader = parseSequencesHeader(reader);
        final payloadSize = blockDataEnd - reader.offset;
        if (payloadSize < 0) {
          throw ZstdDecodingError('Sequence payload underflow');
        }
        final sequencesResult = decodeSequencesSection(
          reader,
          sequencesHeader,
          payloadSize: payloadSize,
          initialPrevOffsets: prevOffsets,
          state: sequenceState,
        );
        prevOffsets = List<int>.from(sequencesResult.finalPrevOffsets);

        executeSequences(
          sequences: sequencesResult.sequences,
          literals: literalsResult.literals,
          window: window,
          outputBuffer: output,
        );
        break;
      case ZstdBlockType.reserved:
        throw ZstdDecodingError('Encountered reserved block type');
    }

    if (reader.offset != blockDataEnd) {
      reader.offset = blockDataEnd;
    }

    if (blockHeader.lastBlock) {
      finished = true;
    }
  }

  final result = Uint8List.fromList(output);
  if (header.frameContentSize != null && header.frameContentSize != result.length) {
    throw ZstdDecodingError('Frame content size mismatch: expected ${header.frameContentSize}, got ${result.length}');
  }

  if (header.checksumFlag) {
    if (reader.remaining < 4) {
      throw ZstdDecodingError('Frame declared a checksum but no bytes remain');
    }
    final expected = reader.readUint32LE();
    final actual = xxHash64(result).toUnsigned(32).toInt();
    if (actual != expected) {
      throw ZstdDecodingError('Content checksum mismatch: expected $expected, got $actual');
    }
  }

  return result;
}

ZstdDictionary? _resolveDictionary({
  required int dictId,
  Map<int, ZstdDictionary>? dictionaries,
  ZstdDictionaryProvider? dictionaryProvider,
}) {
  if (dictId == 0) {
    return null;
  }
  final dict = dictionaries != null ? dictionaries[dictId] : null;
  if (dict != null) {
    return dict;
  }
  return dictionaryProvider?.call(dictId);
}
