import 'dart:math' as math;
import 'dart:typed_data';

import '../bit_stream_writer.dart';
import 'huffman.dart' show MAX_LENGTH;
import 'huffman_builder.dart';
import 'huffman_writer.dart';
import 'literal_histogram.dart';
import 'prefix.dart';

/// Maximum payload that fits in a single uncompressed Brotli meta-block.
const int _maxMetaBlockLength = 0xFFFFFF + 1; // 24-bit length + 1
const int brotliRawMaxChunkLength = _maxMetaBlockLength;
const int _minWindowBits = 16;
const int _maxWindowBits = 24;
const int _numInsertAndCopyCodes = 704;
const int _numDistanceShortCodes = 16;
const int _distanceAlphabetTail = 48;

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
    _writeCompressedMetaBlock(writer, chunk);
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

void _writeCompressedMetaBlock(BitStreamWriter writer, Uint8List chunk) {
  _writeCompressedMetaBlockHeader(writer, chunk.length);
  for (var i = 0; i < 3; i++) {
    storeVarLenUint8(writer, 0); // single block type per tree category
  }

  writer.writeBits(0, 2); // distancePostfixBits
  writer.writeBits(0, 4); // additional direct distance codes

  writer.writeBits(0, 2); // literal context mode (0 => literal)
  storeVarLenUint8(writer, 0); // literal context map uses one tree
  storeVarLenUint8(writer, 0); // distance context map uses one tree

  final histogram = BrotliLiteralHistogram()..addSlice(chunk);
  final literalCodeLengths = buildLiteralCodeLengths(histogram);
  final literalCodes = convertBitDepthsToSymbols(literalCodeLengths);

  final insertCommand = _InsertOnlyCommand.forLength(chunk.length);
  final commandCounts = List<int>.filled(_numInsertAndCopyCodes, 0);
  commandCounts[insertCommand.commandCode] = 1;
  final commandCodeLengths = buildLimitedHuffmanCodeLengths(
    commandCounts,
    _numInsertAndCopyCodes,
    MAX_LENGTH,
  );
  final commandCodes = convertBitDepthsToSymbols(commandCodeLengths);

  const distanceAlphabetSize = _numDistanceShortCodes + _distanceAlphabetTail;
  final distanceCounts = List<int>.filled(distanceAlphabetSize, 0);
  distanceCounts[0] = 1;
  final distanceCodeLengths = buildLimitedHuffmanCodeLengths(
    distanceCounts,
    distanceAlphabetSize,
    MAX_LENGTH,
  );

  _writeFullHuffmanTree(writer, literalCodeLengths);
  _writeFullHuffmanTree(writer, commandCodeLengths);
  _writeFullHuffmanTree(writer, distanceCodeLengths);

  final commandBitLength = commandCodeLengths[insertCommand.commandCode];
  if (commandBitLength == 0) {
    throw StateError('Command Huffman code length missing for ${insertCommand.commandCode}');
  }
  writer.writeBits(
    commandCodes[insertCommand.commandCode],
    commandBitLength,
  );

  if (insertCommand.insertExtraBits > 0) {
    writer.writeBits(insertCommand.insertExtraValue, insertCommand.insertExtraBits);
  }
  if (insertCommand.copyExtraBits > 0) {
    writer.writeBits(insertCommand.copyExtraValue, insertCommand.copyExtraBits);
  }

  for (var i = 0; i < chunk.length; i++) {
    final literal = chunk[i];
    final bitLength = literalCodeLengths[literal];
    if (bitLength == 0) {
      throw StateError('Literal $literal missing code length');
    }
    writer.writeBits(literalCodes[literal], bitLength);
  }
}

void _writeFullHuffmanTree(BitStreamWriter writer, Uint8List codeLengths) {
  BrotliHuffmanTreeWriter.writeTree(codeLengths, writer);
}

class _InsertOnlyCommand {
  _InsertOnlyCommand(
    this.commandCode,
    this.insertLenCode,
    this.insertExtraValue,
    this.insertExtraBits,
    this.copyLenCode,
    this.copyExtraValue,
    this.copyExtraBits,
  );

  final int commandCode;
  final int insertLenCode;
  final int insertExtraValue;
  final int insertExtraBits;
  final int copyLenCode;
  final int copyExtraValue;
  final int copyExtraBits;

  static _InsertOnlyCommand forLength(int length) {
    if (length <= 0) {
      throw ArgumentError.value(length, 'length', 'Must be positive');
    }
    final insertLenCode = _findInsertLengthCode(length);
    final insertPrefix = kInsertLengthPrefixCode[insertLenCode];
    final insertExtraBits = insertPrefix.nbits;
    final insertExtraValue = length - insertPrefix.offset;
    final rangeIndex = _rangeIndexForInsertCode(insertLenCode);
    final insertBase = Prefix.kInsertRangeLut[rangeIndex];
    final insertOffset = insertLenCode - insertBase;
    const copyOffset = 0;
    final copyLenCode = Prefix.kCopyRangeLut[rangeIndex] + copyOffset;
    final copyPrefix = kCopyLengthPrefixCode[copyLenCode];
    final copyExtraBits = copyPrefix.nbits;
    final copyExtraValue = 0;
    final commandCode = (rangeIndex << 6) | (insertOffset << 3) | copyOffset;
    return _InsertOnlyCommand(
      commandCode,
      insertLenCode,
      insertExtraValue,
      insertExtraBits,
      copyLenCode,
      copyExtraValue,
      copyExtraBits,
    );
  }
}

int _findInsertLengthCode(int length) {
  for (var i = 0; i < kInsertLengthPrefixCode.length; i++) {
    final prefix = kInsertLengthPrefixCode[i];
    final maxValue = prefix.offset + ((prefix.nbits == 0) ? 0 : ((1 << prefix.nbits) - 1));
    if (length >= prefix.offset && length <= maxValue) {
      return i;
    }
  }
  throw ArgumentError('Insert length $length outside supported ranges');
}

int _rangeIndexForInsertCode(int insertLenCode) {
  if (insertLenCode < 8) {
    return 0;
  }
  if (insertLenCode < 16) {
    return 2;
  }
  return 5;
}
