import 'dart:math' as math;
import 'dart:typed_data';

import 'bit_stream_writer.dart';
import '../dec/Huffman.dart' show MAX_LENGTH;
import 'huffman_builder.dart';
import 'huffman_writer.dart';
import 'literal_histogram.dart';

/// Maximum payload that fits in a single uncompressed Brotli meta-block.
const int _maxMetaBlockLength = 0xFFFFFF + 1; // 24-bit length + 1
const int brotliRawMaxChunkLength = _maxMetaBlockLength;
const int _minWindowBits = 16;
const int _maxWindowBits = 24;
const int _numInsertAndCopyCodes = 704;
const int _numDistanceShortCodes = 16;
const int _maxSimpleDistanceAlphabetSize = 140;
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

void _storeCommandExtra(BitStreamWriter writer, _Command command) {
  final insertExtraBits = _kInsertExtra[command.insertLenCode];
  final copyExtraBits = _kCopyExtra[command.copyLenCode];
  if (insertExtraBits == 0 && copyExtraBits == 0) {
    return;
  }
  final insertExtraValue = command.insertLength - _kInsertBase[command.insertLenCode];
  final copyExtraValue = copyExtraBits == 0
      ? 0
      : command.copyLengthCodeValue - _kCopyBase[command.copyLenCode];
  
 
  final combinedBits = insertExtraValue | (copyExtraValue << insertExtraBits);
  writer.writeBits(combinedBits, insertExtraBits + copyExtraBits);
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
    final chunkLength = remaining > _maxMetaBlockLength ? _maxMetaBlockLength : remaining;
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

  final writer = BitStreamWriter();
  _writeWindowBits(writer, windowBits);

  var offset = 0;
  while (offset < input.length) {
    final remaining = input.length - offset;
    final chunkLength = math.min(_maxMetaBlockLength, remaining);
    final chunk = Uint8List.sublistView(input, offset, offset + chunkLength);
    _storeMetaBlockTrivial(writer, chunk);
    offset += chunkLength;
  }

  _writeStreamTerminator(writer);
  writer.alignToByte();
  return writer.takeBytes();
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
    throw ArgumentError.value(windowBits, 'windowBits', 'Unsupported window bits for Brotli header (must be 16-24)');
  }
  writer.writeBits(adjusted, 3);
}

void _writeUncompressedMetaBlockHeader(BitStreamWriter writer, int length) {
  if (length <= 0) {
    throw ArgumentError.value(length, 'length', 'Meta-block length must be positive');
  }
  if (length > _maxMetaBlockLength) {
    throw ArgumentError('Meta-block length $length exceeds $_maxMetaBlockLength bytes');
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
    throw ArgumentError.value(length, 'length', 'Meta-block length must be positive');
  }
  if (length > _maxMetaBlockLength) {
    throw ArgumentError('Meta-block length $length exceeds $_maxMetaBlockLength bytes');
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

void _storeMetaBlockTrivial(BitStreamWriter writer, Uint8List chunk) {
  if (chunk.isEmpty) {
    throw ArgumentError('Compressed meta-block chunk must be non-empty');
  }

  _writeCompressedMetaBlockHeader(writer, chunk.length);

  final commands = <_Command>[_makeInsertCommand(chunk.length)];
  final literalHistogram = BrotliLiteralHistogram();
  final commandHistogram = List<int>.filled(_numInsertAndCopyCodes, 0);
  final distanceHistogram = List<int>.filled(_maxSimpleDistanceAlphabetSize, 0);

  _buildHistograms(chunk, commands, literalHistogram, commandHistogram, distanceHistogram);

  // Single block type per tree category, no context maps, no distance postfix/direct codes.
  writer.writeBits(0, 13);

  final literalCodeLengths = buildLiteralCodeLengths(literalHistogram);
  final literalCodes = convertBitDepthsToSymbols(literalCodeLengths);

  final commandCodeLengths = buildLimitedHuffmanCodeLengths(
    commandHistogram,
    _numInsertAndCopyCodes,
    MAX_LENGTH,
  );
  final commandCodes = convertBitDepthsToSymbols(commandCodeLengths);

  if (distanceHistogram.every((value) => value == 0)) {
    distanceHistogram[0] = 1;
  }
  final distanceCodeLengths = buildLimitedHuffmanCodeLengths(
    distanceHistogram,
    _maxSimpleDistanceAlphabetSize,
    MAX_LENGTH,
  );
  final distanceCodes = convertBitDepthsToSymbols(distanceCodeLengths);

  _writeFullHuffmanTree(writer, literalCodeLengths);
  _writeFullHuffmanTree(writer, commandCodeLengths);
  _writeFullHuffmanTree(writer, distanceCodeLengths);

  _storeDataWithHuffmanCodes(
    writer,
    chunk,
    commands,
    literalCodeLengths,
    literalCodes,
    commandCodeLengths,
    commandCodes,
    distanceCodeLengths,
    distanceCodes,
  );
}

void _writeFullHuffmanTree(BitStreamWriter writer, Uint8List codeLengths) {
  BrotliHuffmanTreeWriter.writeTree(codeLengths, writer);
}

void _buildHistograms(
  Uint8List chunk,
  List<_Command> commands,
  BrotliLiteralHistogram literalHistogram,
  List<int> commandHistogram,
  List<int> distanceHistogram,
) {
  var cursor = 0;
  for (final command in commands) {
    if (command.cmdPrefix < 0 || command.cmdPrefix >= commandHistogram.length) {
      throw StateError('Command prefix ${command.cmdPrefix} out of range');
    }
    commandHistogram[command.cmdPrefix]++;

    final end = cursor + command.insertLength;
    if (end > chunk.length) {
      throw StateError('Command literals exceed chunk length (${chunk.length})');
    }
    literalHistogram.addSlice(chunk, cursor, end);
    cursor = end;

    if (command.actualCopyLength > 0 && command.cmdPrefix >= 128) {
      if (command.distanceCode < 0 || command.distanceCode >= distanceHistogram.length) {
        throw StateError('Distance code ${command.distanceCode} out of range');
      }
      distanceHistogram[command.distanceCode]++;
    }
  }

  if (cursor != chunk.length) {
    throw StateError('Meta-block literals not fully covered: $cursor/${chunk.length}');
  }
}

void _storeDataWithHuffmanCodes(
  BitStreamWriter writer,
  Uint8List chunk,
  List<_Command> commands,
  Uint8List literalCodeLengths,
  Uint16List literalCodes,
  Uint8List commandCodeLengths,
  Uint16List commandCodes,
  Uint8List distanceCodeLengths,
  Uint16List distanceCodes,
) {
  var cursor = 0;
  for (final command in commands) {
    final commandBits = commandCodeLengths[command.cmdPrefix];
    if (commandBits == 0) {
      throw StateError('Missing Huffman depth for command ${command.cmdPrefix}');
    }
    writer.writeBits(commandCodes[command.cmdPrefix], commandBits);
    _storeCommandExtra(writer, command);

    final end = cursor + command.insertLength;
    for (var i = cursor; i < end; i++) {
      final literal = chunk[i];
      final literalBits = literalCodeLengths[literal];
      if (literalBits == 0) {
        throw StateError('Missing Huffman depth for literal $literal');
      }
      writer.writeBits(literalCodes[literal], literalBits);
    }
    cursor = end;

    if (command.actualCopyLength > 0 && command.cmdPrefix >= 128) {
      final distBits = distanceCodeLengths[command.distanceCode];
      if (distBits == 0) {
        throw StateError('Missing Huffman depth for distance ${command.distanceCode}');
      }
      writer.writeBits(distanceCodes[command.distanceCode], distBits);
      if (command.distanceExtraBits > 0) {
        writer.writeBits(command.distanceExtraValue, command.distanceExtraBits);
      }
    }
  }

  if (cursor != chunk.length) {
    throw StateError('Meta-block literals not fully covered: $cursor/${chunk.length}');
  }
}

class _Command {
  const _Command({
    required this.insertLength,
    required this.insertLenCode,
    required this.copyLengthCodeValue,
    required this.copyLenCode,
    required this.cmdPrefix,
    required this.distanceCode,
    required this.distanceExtraBits,
    required this.distanceExtraValue,
    required this.actualCopyLength,
  });

  final int insertLength;
  final int insertLenCode;
  final int copyLengthCodeValue;
  final int copyLenCode;
  final int cmdPrefix;
  final int distanceCode;
  final int distanceExtraBits;
  final int distanceExtraValue;
  final int actualCopyLength;
}

_Command _makeInsertCommand(int length) {
  if (length <= 0) {
    throw ArgumentError.value(length, 'length', 'Must be positive');
  }
  const copyLengthValue = 4;
  final insertLenCode = _getInsertLengthCode(length);
  final copyLenCode = _getCopyLengthCode(copyLengthValue);
  final cmdPrefix = _combineLengthCodes(insertLenCode, copyLenCode, false);
  return _Command(
    insertLength: length,
    insertLenCode: insertLenCode,
    copyLengthCodeValue: copyLengthValue,
    copyLenCode: copyLenCode,
    cmdPrefix: cmdPrefix,
    distanceCode: _numDistanceShortCodes,
    distanceExtraBits: 0,
    distanceExtraValue: 0,
    actualCopyLength: 0,
  );
}

