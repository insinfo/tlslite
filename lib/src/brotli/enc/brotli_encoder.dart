import 'dart:math' as math;
import 'dart:typed_data';

import 'bit_stream_writer.dart';
import 'block_split.dart';
import '../dec/Huffman.dart' show MAX_LENGTH;
import 'huffman_builder.dart';
import 'huffman_writer.dart';
import 'literal_histogram.dart';
import 'match_finder.dart';

/// Maximum payload that fits in a single uncompressed Brotli meta-block.
const int _maxMetaBlockLength = 0xFFFFFF + 1; // 24-bit length + 1
const int brotliRawMaxChunkLength = _maxMetaBlockLength;
const int _minWindowBits = 16;
const int _maxWindowBits = 24;
const int _numInsertAndCopyCodes = 704;
const int _numDistanceShortCodes = 16;
const int _distanceAlphabetSize = 64;
const List<int> _kInsertBase = <int>[
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  8,
  10,
  14,
  18,
  26,
  34,
  50,
  66,
  98,
  130,
  194,
  322,
  578,
  1090,
  2114,
  6210,
  22594,
];
const List<int> _kInsertExtra = <int>[
  0,
  0,
  0,
  0,
  0,
  0,
  1,
  1,
  2,
  2,
  3,
  3,
  4,
  4,
  5,
  5,
  6,
  7,
  8,
  9,
  10,
  12,
  14,
  24,
];
const List<int> _kCopyBase = <int>[
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  12,
  14,
  18,
  22,
  30,
  38,
  54,
  70,
  102,
  134,
  198,
  326,
  582,
  1094,
  2118,
];
const List<int> _kCopyExtra = <int>[
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  1,
  1,
  2,
  2,
  3,
  3,
  4,
  4,
  5,
  5,
  6,
  7,
  8,
  9,
  10,
  24,
];

int _log2FloorNonZero(int value) {
  var result = 0;
  var n = value;
  while (n > 1) {
    n >>= 1;
    result++;
  }
  return result;
}

int _getInsertLengthCode(int length) {
  if (length < 6) {
    return length;
  } else if (length < 130) {
    final nbits = _log2FloorNonZero(length - 2) - 1;
    return (nbits << 1) + ((length - 2) >> nbits) + 2;
  } else if (length < 2114) {
    return _log2FloorNonZero(length - 66) + 10;
  } else if (length < 6210) {
    return 21;
  } else if (length < 22594) {
    return 22;
  }
  return 23;
}

int _getCopyLengthCode(int length) {
  if (length < 10) {
    return length - 2;
  } else if (length < 134) {
    final nbits = _log2FloorNonZero(length - 6) - 1;
    return (nbits << 1) + ((length - 6) >> nbits) + 4;
  } else if (length < 2118) {
    return _log2FloorNonZero(length - 70) + 12;
  }
  return 23;
}

int _combineLengthCodes(int insertCode, int copyCode, bool useLastDistance) {
  final bits = (copyCode & 0x7) | ((insertCode & 0x7) << 3);
  if (useLastDistance && insertCode < 8 && copyCode < 16) {
    if (copyCode < 8) {
      return bits;
    }
    return bits | 64;
  }
  var offset = 2 * ((copyCode >> 3) + 3 * (insertCode >> 3));
  offset = (offset << 5) + 0x40 + ((0x520D40 >> offset) & 0xC0);
  return offset | bits;
}

/// LZ77 match emitted by the Brotli encoder.
///
/// Mirrors the shape returned by `matchfinder.Match` in the brotli-go
/// reference while avoiding a name clash with `dart:core`'s [Match].
class BrotliMatch {
  const BrotliMatch({
    required this.unmatchedLength,
    required this.matchLength,
    required this.distance,
  })  : assert(unmatchedLength >= 0),
        assert(matchLength >= 0),
        assert(distance >= 0);

  final int unmatchedLength;
  final int matchLength;
  final int distance;

  int get totalLength => unmatchedLength + matchLength;
}

class _DistanceCode {
  const _DistanceCode({
    required this.code,
    required this.extraBits,
    required this.extraValue,
  });

  final int code;
  final int extraBits;
  final int extraValue;

  static const zero = _DistanceCode(code: 0, extraBits: 0, extraValue: 0);
}

class _HistogramStats {
  const _HistogramStats({
    required this.literalCount,
    required this.commandCount,
    required this.distanceCount,
  });

  final int literalCount;
  final int commandCount;
  final int distanceCount;
}

/// Streaming Brotli encoder that mirrors `brotli-go/encoder.go`.
class BrotliEncoder {
  BrotliEncoder({this.windowBits = _maxWindowBits}) {
    if (windowBits < _minWindowBits || windowBits > _maxWindowBits) {
      throw ArgumentError.value(
        windowBits,
        'windowBits',
        'Brotli encoder supports window bits in the range $_minWindowBits-$_maxWindowBits.',
      );
    }
  }

  final int windowBits;
  final BitStreamWriter _writer = BitStreamWriter();
  final BlockStructureWriter _blockStructureWriter =
      const BlockStructureWriter();
  bool _windowBitsWritten = false;
  final List<_DistanceCode> _distanceCache = <_DistanceCode>[];

  void reset() {
    _writer.reset();
    _distanceCache.clear();
    _windowBitsWritten = false;
  }

  Uint8List encodeChunk(
    Uint8List chunk,
    List<BrotliMatch> matches, {
    bool isLastChunk = false,
  }) {
    _ensureWindowBitsWritten();
    if (chunk.isEmpty) {
      if (matches.isNotEmpty) {
        throw ArgumentError('Matches must be empty when chunk length is zero.');
      }
      if (isLastChunk) {
        _writeStreamTerminator(_writer);
        _writer.alignToByte();
        return _writer.takeBytes();
      }
      return Uint8List(0);
    }
    if (chunk.length > _maxMetaBlockLength) {
      throw ArgumentError(
          'Chunk length ${chunk.length} exceeds $_maxMetaBlockLength bytes.');
    }
    if (matches.isEmpty) {
      throw ArgumentError('Non-empty chunks require at least one BrotliMatch.');
    }
    if (_distanceCache.length < matches.length) {
      final deficit = matches.length - _distanceCache.length;
      _distanceCache
          .addAll(List<_DistanceCode>.filled(deficit, _DistanceCode.zero));
    }

    final literalHistogram = BrotliLiteralHistogram();
    final commandHistogram = List<int>.filled(_numInsertAndCopyCodes, 0);
    final distanceHistogram = List<int>.filled(_distanceAlphabetSize, 0);

    final histogramStats = _buildHistograms(
      chunk,
      matches,
      literalHistogram,
      commandHistogram,
      distanceHistogram,
    );

    _writeCompressedMetaBlockHeader(_writer, chunk.length);
    final literalSplit = BlockSplit.single(histogramStats.literalCount);
    final commandSplit = BlockSplit.single(histogramStats.commandCount);
    final distanceSplit = BlockSplit.single(histogramStats.distanceCount);
    _blockStructureWriter.writeTrivialSplits(
      _writer,
      literal: literalSplit,
      command: commandSplit,
      distance: distanceSplit,
    );

    final literalCodeLengths = _buildLiteralTree(literalHistogram);
    final literalCodes = convertBitDepthsToSymbols(literalCodeLengths);

    final commandCodeLengths =
        _buildCodeLengths(commandHistogram, _numInsertAndCopyCodes);
    final commandCodes = convertBitDepthsToSymbols(commandCodeLengths);

    final distanceCodeLengths =
        _buildCodeLengths(distanceHistogram, _distanceAlphabetSize);
    final distanceCodes = convertBitDepthsToSymbols(distanceCodeLengths);

    _writeFullHuffmanTree(_writer, literalCodeLengths);
    _writeFullHuffmanTree(_writer, commandCodeLengths);
    _writeFullHuffmanTree(_writer, distanceCodeLengths);

    _writeCommandStream(
      chunk,
      matches,
      literalCodeLengths,
      literalCodes,
      commandCodeLengths,
      commandCodes,
      distanceCodeLengths,
      distanceCodes,
    );

    if (isLastChunk) {
      _writeStreamTerminator(_writer);
      _writer.alignToByte();
      return _writer.takeBytes();
    }

    return _writer.takeBytes(includePartialByte: false);
  }

  void _ensureWindowBitsWritten() {
    if (_windowBitsWritten) {
      return;
    }
    _writeWindowBits(_writer, windowBits);
    _windowBitsWritten = true;
  }

  _HistogramStats _buildHistograms(
    Uint8List chunk,
    List<BrotliMatch> matches,
    BrotliLiteralHistogram literalHistogram,
    List<int> commandHistogram,
    List<int> distanceHistogram,
  ) {
    final recentDistances = <int>[-10, -10, -10, -10];
    var cursor = 0;
    var literalCount = 0;
    var commandCount = 0;
    var distanceCount = 0;
    for (var i = 0; i < matches.length; i++) {
      final match = matches[i];
      final unmatched = match.unmatchedLength;
      final copyLength = match.matchLength;
      if (unmatched < 0 || copyLength < 0) {
        throw ArgumentError('Match lengths must be non-negative.');
      }
      final literalEnd = cursor + unmatched;
      if (literalEnd > chunk.length) {
        throw StateError(
            'Match literals exceed chunk length (${chunk.length}).');
      }
      if (unmatched > 0) {
        literalHistogram.addSlice(chunk, cursor, literalEnd);
        literalCount += unmatched;
      }

      final insertCode = _getInsertLengthCode(unmatched);
      var copyCode = _getCopyLengthCode(copyLength);
      if (copyLength == 0) {
        copyCode = 2; // Dummy copy used when ending with literals.
      }
      final useLastDistance =
          i > 0 && match.distance == matches[i - 1].distance;
      final command =
          _combineLengthCodes(insertCode, copyCode, useLastDistance);
      commandHistogram[command]++;
        commandCount++;

      if (command >= 128 && copyLength != 0) {
        if (match.distance <= 0) {
          throw ArgumentError('Copy matches must provide a positive distance.');
        }
        final distCode = _selectDistanceCode(match.distance, recentDistances);
        _distanceCache[i] = distCode;
        distanceHistogram[distCode.code]++;
        distanceCount++;
        if (distCode.code != 0) {
          recentDistances
            ..[0] = recentDistances[1]
            ..[1] = recentDistances[2]
            ..[2] = recentDistances[3]
            ..[3] = match.distance;
        }
      } else {
        _distanceCache[i] = _DistanceCode.zero;
      }

      cursor = literalEnd + copyLength;
      if (cursor > chunk.length) {
        throw StateError('Matches exceed chunk length (${chunk.length}).');
      }
    }

    if (cursor != chunk.length) {
      throw StateError('Matches do not cover chunk: $cursor/${chunk.length}');
    }

    return _HistogramStats(
      literalCount: literalCount,
      commandCount: commandCount,
      distanceCount: distanceCount,
    );
  }

  Uint8List _buildLiteralTree(BrotliLiteralHistogram histogram) {
    final counts = histogram.counts;
    _ensureHistogramHasSymbol(counts);
    return buildLimitedHuffmanCodeLengths(counts, counts.length, MAX_LENGTH);
  }

  Uint8List _buildCodeLengths(List<int> histogram, int alphabetSize) {
    _ensureHistogramHasSymbol(histogram);
    _ensureHistogramHasMultipleSymbols(histogram);
    return buildLimitedHuffmanCodeLengths(histogram, alphabetSize, MAX_LENGTH);
  }

  void _writeCommandStream(
    Uint8List chunk,
    List<BrotliMatch> matches,
    Uint8List literalCodeLengths,
    Uint16List literalCodes,
    Uint8List commandCodeLengths,
    Uint16List commandCodes,
    Uint8List distanceCodeLengths,
    Uint16List distanceCodes,
  ) {
    var cursor = 0;
    for (var i = 0; i < matches.length; i++) {
      final match = matches[i];
      final insertCode = _getInsertLengthCode(match.unmatchedLength);
      var copyCode = _getCopyLengthCode(match.matchLength);
      if (match.matchLength == 0) {
        copyCode = 2;
      }
      final useLastDistance =
          i > 0 && match.distance == matches[i - 1].distance;
      final command =
          _combineLengthCodes(insertCode, copyCode, useLastDistance);

      final commandBits = commandCodeLengths[command];
      if (commandBits == 0) {
        throw StateError('Missing Huffman depth for command $command');
      }
      _writer.writeBits(commandCodes[command], commandBits);

      final insertExtraBits = _kInsertExtra[insertCode];
      if (insertExtraBits > 0) {
        final insertExtraValue =
            match.unmatchedLength - _kInsertBase[insertCode];
        _writer.writeBits(insertExtraValue, insertExtraBits);
      }
      final copyExtraBits = _kCopyExtra[copyCode];
      if (copyExtraBits > 0) {
        final copyExtraValue = match.matchLength - _kCopyBase[copyCode];
        _writer.writeBits(copyExtraValue, copyExtraBits);
      }

      final literalEnd = cursor + match.unmatchedLength;
      for (var j = cursor; j < literalEnd; j++) {
        final literal = chunk[j];
        final literalBits = literalCodeLengths[literal];
        if (literalBits == 0) {
          throw StateError('Missing Huffman depth for literal $literal');
        }
        _writer.writeBits(literalCodes[literal], literalBits);
      }
      cursor = literalEnd;

      if (command >= 128 && match.matchLength != 0) {
        final distCode = _distanceCache[i];
        final distBits = distanceCodeLengths[distCode.code];
        if (distBits == 0) {
          throw StateError(
              'Missing Huffman depth for distance ${distCode.code}');
        }
        _writer.writeBits(distanceCodes[distCode.code], distBits);
        if (distCode.extraBits > 0) {
          _writer.writeBits(distCode.extraValue, distCode.extraBits);
        }
      }

      cursor += match.matchLength;
    }

    if (cursor != chunk.length) {
      throw StateError(
          'Meta-block literals not fully covered: $cursor/${chunk.length}');
    }
  }

  _DistanceCode _selectDistanceCode(int distance, List<int> recentDistances) {
    if (distance == recentDistances[3]) {
      return const _DistanceCode(code: 0, extraBits: 0, extraValue: 0);
    }
    if (distance == recentDistances[2]) {
      return const _DistanceCode(code: 1, extraBits: 0, extraValue: 0);
    }
    if (distance == recentDistances[1]) {
      return const _DistanceCode(code: 2, extraBits: 0, extraValue: 0);
    }
    if (distance == recentDistances[0]) {
      return const _DistanceCode(code: 3, extraBits: 0, extraValue: 0);
    }

    final last = recentDistances[3];
    if (distance == last - 1) {
      return const _DistanceCode(code: 4, extraBits: 0, extraValue: 0);
    }
    if (distance == last + 1) {
      return const _DistanceCode(code: 5, extraBits: 0, extraValue: 0);
    }
    if (distance == last - 2) {
      return const _DistanceCode(code: 6, extraBits: 0, extraValue: 0);
    }
    if (distance == last + 2) {
      return const _DistanceCode(code: 7, extraBits: 0, extraValue: 0);
    }
    if (distance == last - 3) {
      return const _DistanceCode(code: 8, extraBits: 0, extraValue: 0);
    }
    if (distance == last + 3) {
      return const _DistanceCode(code: 9, extraBits: 0, extraValue: 0);
    }

    return _encodeDistanceCode(distance);
  }

  _DistanceCode _encodeDistanceCode(int distance) {
    final adjusted = distance + 3;
    final nbits = _log2FloorNonZero(adjusted) - 1;
    final prefix = (adjusted >> nbits) & 1;
    final offset = (2 + prefix) << nbits;
    final code = 2 * (nbits - 1) + prefix + _numDistanceShortCodes;
    final extra = adjusted - offset;
    return _DistanceCode(code: code, extraBits: nbits, extraValue: extra);
  }

  void _ensureHistogramHasSymbol(List<int> histogram) {
    for (final value in histogram) {
      if (value != 0) {
        return;
      }
    }
    histogram[0] = 1;
  }

  void _ensureHistogramHasMultipleSymbols(List<int> histogram) {
    var firstIndex = -1;
    var nonZeroCount = 0;
    for (var i = 0; i < histogram.length; i++) {
      if (histogram[i] == 0) {
        continue;
      }
      nonZeroCount++;
      if (nonZeroCount == 1) {
        firstIndex = i;
      } else {
        return;
      }
    }
    if (nonZeroCount == 1) {
      final fallbackIndex = (firstIndex + 1) % histogram.length;
      histogram[fallbackIndex] = 1;
    }
  }
}

/// Emits a Brotli stream composed exclusively of uncompressed meta-blocks.
///
/// The encoder produces a standards-compliant bitstream that mirrors the
/// decode pipeline in `lib/src/utils/brotlidecpy`. The payload is chunked into
/// meta-blocks capped at 16,777,216 bytes so the length header fits in six
/// nibbles. Each chunk is flagged as "uncompressed" and a terminating empty
/// meta-block closes the stream.
Uint8List brotliCompressRaw(
  Uint8List input, {
  int windowBits = 16,
}) {
  if (windowBits < _minWindowBits || windowBits > _maxWindowBits) {
    throw ArgumentError.value(
      windowBits,
      'windowBits',
      'Brotli raw encoder supports window bits in the range $_minWindowBits-$_maxWindowBits.',
    );
  }

  final builder = BytesBuilder(copy: false);
  final writer = BitStreamWriter();
  _writeWindowBits(writer, windowBits);

  var offset = 0;
  while (offset < input.length) {
    final remaining = input.length - offset;
    final chunkLength =
        remaining > _maxMetaBlockLength ? _maxMetaBlockLength : remaining;
    _writeUncompressedMetaBlockHeader(writer, chunkLength);
    writer.alignToByte();
    final headerBytes = writer.takeBytes(includePartialByte: false);
    if (headerBytes.isNotEmpty) {
      builder.add(headerBytes);
    }
    builder.add(Uint8List.sublistView(input, offset, offset + chunkLength));
    offset += chunkLength;
  }

  _writeStreamTerminator(writer);
  writer.alignToByte();
  builder.add(writer.takeBytes());

  return builder.takeBytes();
}

/// Emits Brotli compressed meta-blocks that consist solely of literal
/// insertions described by a Huffman tree built from the payload.
///
/// Each meta-block creates a single InsertCopy command covering the entire
/// literal span and relies on the shared Huffman builder/writer to serialize
/// the literal, insert/copy and distance trees. When the payload is empty the
/// encoder falls back to [brotliCompressRaw].
Uint8List brotliCompressLiteral(Uint8List input, {int windowBits = 16}) {
  if (input.isEmpty) {
    return brotliCompressRaw(input, windowBits: windowBits);
  }
  if (windowBits < _minWindowBits || windowBits > _maxWindowBits) {
    throw ArgumentError.value(
      windowBits,
      'windowBits',
      'Brotli literal encoder supports window bits in the range $_minWindowBits-$_maxWindowBits.',
    );
  }

  final encoder = BrotliEncoder(windowBits: windowBits);
  final matchFinder = BrotliMatchFinder(maxDistance: 1 << windowBits);
  final matchesBuffer = <BrotliMatch>[];
  final builder = BytesBuilder(copy: false);

  var offset = 0;
  while (offset < input.length) {
    final remaining = input.length - offset;
    final chunkLength = math.min(_maxMetaBlockLength, remaining);
    final chunk = Uint8List.sublistView(input, offset, offset + chunkLength);
    matchFinder.reset();
    final matches = matchFinder.findMatches(chunk, reuse: matchesBuffer);
    final chunkBytes = encoder.encodeChunk(
      chunk,
      matches,
      isLastChunk: (offset + chunkLength) == input.length,
    );
    if (chunkBytes.isNotEmpty) {
      builder.add(chunkBytes);
    }
    offset += chunkLength;
  }
  return builder.takeBytes();
}

void _writeWindowBits(BitStreamWriter writer, int windowBits) {
  if (windowBits == 16) {
    writer.writeBits(0, 1);
    return;
  }

  writer.writeBits(1, 1);

  if (windowBits == 17) {
    // Special case: 17 bits is encoded as 1 + 000 + 000 = 1000000 (7 bits)
    writer.writeBits(0, 3); // first group of 3 zeros
    writer.writeBits(0, 3); // second group of 3 zeros
    return;
  }

  // For windowBits 18-24, encode as (windowBits - 17) in 3 bits after the leading 1
  // windowBits 18 => 1, windowBits 19 => 2, ... windowBits 24 => 7
  final adjusted = windowBits - 17;
  if (adjusted < 1 || adjusted > 7) {
    throw ArgumentError.value(windowBits, 'windowBits',
        'Unsupported window bits for Brotli header (must be 16-24)');
  }
  writer.writeBits(adjusted, 3);
}

void _writeUncompressedMetaBlockHeader(BitStreamWriter writer, int length) {
  if (length <= 0) {
    throw ArgumentError.value(
        length, 'length', 'Meta-block length must be positive');
  }
  if (length > _maxMetaBlockLength) {
    throw ArgumentError(
        'Meta-block length $length exceeds $_maxMetaBlockLength bytes');
  }

  writer.writeBool(false); // isLast
  final lengthMinusOne = length - 1;
  final sizeNibbles = _sizeNibblesFor(lengthMinusOne);
  writer.writeBits(sizeNibbles - 4, 2);
  for (var i = 0; i < sizeNibbles; i++) {
    final nibble = (lengthMinusOne >> (i * 4)) & 0xF;
    writer.writeBits(nibble, 4);
  }
  writer.writeBool(true); // isUncompressed
}

void _writeCompressedMetaBlockHeader(BitStreamWriter writer, int length) {
  if (length <= 0) {
    throw ArgumentError.value(
        length, 'length', 'Meta-block length must be positive');
  }
  if (length > _maxMetaBlockLength) {
    throw ArgumentError(
        'Meta-block length $length exceeds $_maxMetaBlockLength bytes');
  }

  writer.writeBool(false); // isLast
  final lengthMinusOne = length - 1;
  final sizeNibbles = _sizeNibblesFor(lengthMinusOne);
  writer.writeBits(sizeNibbles - 4, 2);
  for (var i = 0; i < sizeNibbles; i++) {
    final nibble = (lengthMinusOne >> (i * 4)) & 0xF;
    writer.writeBits(nibble, 4);
  }
  writer.writeBool(false); // isUncompressed
}

int _sizeNibblesFor(int value) {
  if (value <= 0xFFFF) {
    return 4;
  }
  if (value <= 0xFFFFF) {
    return 5;
  }
  if (value <= 0xFFFFFF) {
    return 6;
  }
  throw ArgumentError('Value $value does not fit in Brotli meta-block header');
}

void _writeStreamTerminator(BitStreamWriter writer) {
  writer.writeBool(true); // isLast = 1
  writer.writeBool(true); // isEmpty = 1 (marks end of stream)
}

void _writeFullHuffmanTree(BitStreamWriter writer, Uint8List codeLengths) {
  BrotliHuffmanTreeWriter.writeTree(codeLengths, writer);
}
