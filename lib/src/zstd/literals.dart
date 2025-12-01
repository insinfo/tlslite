import 'dart:math' as math;
import 'dart:typed_data';

import 'byte_reader.dart';
import 'frame_header.dart'; // For ZstdFrameFormatException
import 'fse.dart';

enum LiteralsBlockType { raw, rle, compressed, repeat }

const int _huffmanMaxTableLog = 12;
const int _huffmanMaxSymbol = 255;
const int _huffmanMaxSymbolCount = _huffmanMaxSymbol + 1;
const int _huffmanMinTableLog = 5;
const int _huffmanMaxFseTableLog = 6;
const int _huffmanJumpTableSize = 6;
const int _sizeOfLong = 8;
const int _bitContainerMask = 0xFFFFFFFFFFFFFFFF;

class HuffmanDecodingTable {
  HuffmanDecodingTable({
    required this.tableLog,
    required this.symbols,
    required this.numberOfBits,
  });

  final int tableLog;
  final Uint8List symbols;
  final Uint8List numberOfBits;
}

class LiteralsResult {
  LiteralsResult(this.literals, this.bytesConsumed, {this.huffmanTable});

  final Uint8List literals;
  final int bytesConsumed;
  final HuffmanDecodingTable? huffmanTable;
}
class LiteralsSectionHeader {
  const LiteralsSectionHeader({
    required this.type,
    required this.regeneratedSize,
    required this.headerSize,
    required this.streamCount,
    this.compressedSize,
  });

  final LiteralsBlockType type;
  final int regeneratedSize;
  final int headerSize;
  final int streamCount;
  final int? compressedSize;

  bool get isCompressed =>
      type == LiteralsBlockType.compressed || type == LiteralsBlockType.repeat;
  bool get isSingleStream => streamCount == 1;
}

LiteralsSectionHeader parseLiteralsSectionHeader(ZstdByteReader reader) {
  final startOffset = reader.offset;
  final peek = reader.readUint8();
  final type = LiteralsBlockType.values[peek & 0x3];
  final sizeFormat = (peek >> 2) & 0x3;

  int headerSize;
  int regenSize;
  int? compressedSize;
  int streamCount = 1;

  switch (type) {
    case LiteralsBlockType.raw:
    case LiteralsBlockType.rle:
      headerSize = _rawRleHeaderSize(sizeFormat);
      reader.offset = startOffset;
      final headerBytes = reader.readBytes(headerSize);
      regenSize = _decodeRawRleSize(headerBytes);
      break;
    case LiteralsBlockType.compressed:
    case LiteralsBlockType.repeat:
      final _CompressedHeader parsed = _decodeCompressedHeader(
        reader: reader,
        startOffset: startOffset,
        sizeFormat: sizeFormat,
      );
      headerSize = parsed.headerSize;
      regenSize = parsed.regeneratedSize;
      compressedSize = parsed.compressedSize;
      streamCount = parsed.streamCount;
      break;
  }

  if (regenSize < 0) {
    throw ZstdFrameFormatException('Negative literal size decoded: $regenSize');
  }

  return LiteralsSectionHeader(
    type: type,
    regeneratedSize: regenSize,
    headerSize: headerSize,
    streamCount: streamCount,
    compressedSize: compressedSize,
  );
}

LiteralsResult decodeLiteralsBlock(
  ZstdByteReader reader, {
  HuffmanDecodingTable? repeatTable,
}) {
  final header = parseLiteralsSectionHeader(reader);
  switch (header.type) {
    case LiteralsBlockType.raw:
      return _decodeRawLiterals(reader, header);
    case LiteralsBlockType.rle:
      return _decodeRleLiterals(reader, header);
    case LiteralsBlockType.compressed:
    case LiteralsBlockType.repeat:
      return _decodeCompressedLiterals(reader, header, repeatTable: repeatTable);
  }
}

LiteralsResult _decodeRawLiterals(
  ZstdByteReader reader,
  LiteralsSectionHeader header,
) {
  if (reader.remaining < header.regeneratedSize) {
    throw ZstdFrameFormatException(
      'Not enough bytes for raw literals: need ${header.regeneratedSize}, have ${reader.remaining}',
    );
  }
  final literals = reader.readBytes(header.regeneratedSize);
  final bytesConsumed = header.headerSize + header.regeneratedSize;
  return LiteralsResult(literals, bytesConsumed);
}

LiteralsResult _decodeRleLiterals(
  ZstdByteReader reader,
  LiteralsSectionHeader header,
) {
  if (reader.remaining < 1) {
    throw ZstdFrameFormatException('Missing RLE literal value');
  }
  final value = reader.readUint8();
  final literals = Uint8List(header.regeneratedSize)
    ..fillRange(0, header.regeneratedSize, value);
  final bytesConsumed = header.headerSize + 1;
  return LiteralsResult(literals, bytesConsumed);
}

LiteralsResult _decodeCompressedLiterals(
  ZstdByteReader reader,
  LiteralsSectionHeader header, {
  HuffmanDecodingTable? repeatTable,
}) {
  final payloadSize = header.compressedSize;
  if (payloadSize == null) {
    throw ZstdFrameFormatException('Compressed literals missing payload size');
  }
  if (reader.remaining < payloadSize) {
    throw ZstdFrameFormatException(
      'Not enough bytes for compressed literals: need $payloadSize, have ${reader.remaining}',
    );
  }

  final payload = reader.readBytes(payloadSize);
  late final HuffmanDecodingTable table;
  int payloadOffset = 0;

  if (header.type == LiteralsBlockType.compressed) {
    final tableResult = readHuffmanTable(payload);
    table = tableResult.table;
    payloadOffset = tableResult.bytesConsumed;
  } else {
    final repeated = repeatTable;
    if (repeated == null) {
      throw ZstdFrameFormatException('Repeat literal block without prior Huffman table');
    }
    table = repeated;
  }

  final literals = _decodeHuffmanStreams(
    payload,
    payloadOffset,
    header,
    table,
  );

  return LiteralsResult(
    literals,
    header.headerSize + payloadSize,
    huffmanTable: table,
  );
}

int _rawRleHeaderSize(int sizeFormat) {
  switch (sizeFormat) {
    case 0:
    case 2:
      return 1;
    case 1:
      return 2;
    case 3:
      return 3;
    default:
      throw ZstdFrameFormatException('Invalid literals header size format $sizeFormat');
  }
}

int _decodeRawRleSize(Uint8List headerBytes) {
  switch (headerBytes.length) {
    case 1:
      return headerBytes[0] >> 3;
    case 2:
      final value = headerBytes[0] | (headerBytes[1] << 8);
      return value >> 4;
    case 3:
      final value = headerBytes[0] | (headerBytes[1] << 8) | (headerBytes[2] << 16);
      return value >> 4;
    default:
      throw ZstdFrameFormatException('Unsupported raw/rle header size ${headerBytes.length}');
  }
}

class _CompressedHeader {
  const _CompressedHeader({
    required this.headerSize,
    required this.regeneratedSize,
    required this.compressedSize,
    required this.streamCount,
  });

  final int headerSize;
  final int regeneratedSize;
  final int compressedSize;
  final int streamCount;
}

_CompressedHeader _decodeCompressedHeader({
  required ZstdByteReader reader,
  required int startOffset,
  required int sizeFormat,
}) {
  late final int headerSize;
  late final int regenSize;
  late final int compSize;
  late final int streamCount;

  switch (sizeFormat) {
    case 0:
    case 1:
      headerSize = 3;
      streamCount = sizeFormat == 0 ? 1 : 4;
      break;
    case 2:
      headerSize = 4;
      streamCount = 4;
      break;
    case 3:
      headerSize = 5;
      streamCount = 4;
      break;
    default:
      throw ZstdFrameFormatException('Invalid compressed literals size format $sizeFormat');
  }

  reader.offset = startOffset;
  final headerBytes = reader.readBytes(headerSize);

  switch (sizeFormat) {
    case 0:
    case 1:
      final value = headerBytes[0] | (headerBytes[1] << 8) | (headerBytes[2] << 16);
      regenSize = (value >> 4) & 0x3FF;
      compSize = (value >> 14) & 0x3FF;
      break;
    case 2:
      final value = headerBytes[0] |
          (headerBytes[1] << 8) |
          (headerBytes[2] << 16) |
          (headerBytes[3] << 24);
      regenSize = (value >> 4) & 0x3FFF;
      compSize = value >> 18;
      break;
    case 3:
      final low = headerBytes[0] |
          (headerBytes[1] << 8) |
          (headerBytes[2] << 16) |
          (headerBytes[3] << 24);
      final extra = headerBytes[4];
      regenSize = (low >> 4) & 0x3FFFF;
      compSize = (low >> 22) + (extra << 10);
      break;
    default:
      throw StateError('Unreachable size format $sizeFormat');
  }

  return _CompressedHeader(
    headerSize: headerSize,
    regeneratedSize: regenSize,
    compressedSize: compSize,
    streamCount: streamCount,
  );
}

/// Result of decoding a Huffman table payload.
class HuffmanTableReadResult {
  HuffmanTableReadResult({
    required this.table,
    required this.bytesConsumed,
    required this.codeLengths,
    required this.maxSymbol,
  });

  final HuffmanDecodingTable table;
  final int bytesConsumed;
  final Uint8List codeLengths;
  final int maxSymbol;
}

class _BitStreamInitializer {
  _BitStreamInitializer(this.buffer, this.start, this.end);

  final Uint8List buffer;
  final int start;
  final int end;
  late int bits;
  late int current;
  late int bitsConsumed;

  void initialize() {
    if (end - start < 1) {
      throw ZstdFrameFormatException('Bitstream is empty');
    }
    final lastByte = buffer[end - 1];
    if (lastByte == 0) {
      throw ZstdFrameFormatException('Bitstream end mark not present');
    }
    bitsConsumed = _sizeOfLong - _highestBit(lastByte);
    final inputSize = end - start;
    if (inputSize >= _sizeOfLong) {
      current = end - _sizeOfLong;
      bits = _readUint64LE(buffer, current);
    } else {
      current = start;
      bits = _readTail(buffer, start, inputSize);
      bitsConsumed += (_sizeOfLong - inputSize) * 8;
    }
  }
}

class _BitStreamLoader {
  _BitStreamLoader({
    required this.buffer,
    required this.start,
    required this.current,
    required this.bits,
    required this.bitsConsumed,
  });

  final Uint8List buffer;
  final int start;
  int current;
  int bits;
  int bitsConsumed;
  bool overflow = false;

  bool load() {
    if (bitsConsumed > 64) {
      overflow = true;
      return true;
    } else if (current == start) {
      return true;
    }

    final bytes = bitsConsumed >> 3;
    if (current >= start + _sizeOfLong) {
      if (bytes > 0) {
        current -= bytes;
        bits = _readUint64LE(buffer, current);
      }
      bitsConsumed &= 0x7;
    } else if (current - bytes < start) {
      final consumedBytes = current - start;
      current = start;
      bitsConsumed -= consumedBytes * _sizeOfLong;
      bits = _readUint64LE(buffer, current);
      return true;
    } else {
      current -= bytes;
      bitsConsumed -= bytes * _sizeOfLong;
      bits = _readUint64LE(buffer, current);
    }

    return false;
  }
}

class _HuffmanFseTable {
  _HuffmanFseTable({
    required this.symbol,
    required this.numberOfBits,
    required this.newState,
    required this.log2Size,
  });

  final List<int> symbol;
  final List<int> numberOfBits;
  final List<int> newState;
  final int log2Size;
}

HuffmanTableReadResult readHuffmanTable(Uint8List payload) {
  if (payload.isEmpty) {
    throw ZstdFrameFormatException('Huffman table payload is empty');
  }

  final weights = List<int>.filled(_huffmanMaxSymbolCount + 1, 0);
  final ranks = List<int>.filled(_huffmanMaxTableLog + 1, 0);

  int offset = 0;
  int inputSize = payload[offset++];
  int outputSize;

  if (inputSize >= 128) {
    outputSize = inputSize - 127;
    final bytesForWeights = (outputSize + 1) >> 1;
    if (offset + bytesForWeights > payload.length) {
      throw ZstdFrameFormatException('Not enough bytes for Huffman weight table');
    }
    for (int i = 0; i < outputSize; i += 2) {
      final value = payload[offset + (i >> 1)];
      weights[i] = value >> 4;
      if (i + 1 < weights.length) {
        weights[i + 1] = value & 0xF;
      }
    }
    offset += bytesForWeights;
  } else {
    if (offset + inputSize > payload.length) {
      throw ZstdFrameFormatException('Corrupted Huffman table (size mismatch)');
    }
    final tableSlice = Uint8List.sublistView(payload, offset, offset + inputSize);
    final reader = ZstdByteReader(tableSlice);
    final descriptor = readFseTable(reader, _huffmanMaxSymbol);
    final bytesRead = reader.offset;
    if (bytesRead > inputSize) {
      throw ZstdFrameFormatException('FSE table overruns Huffman payload');
    }
    final weightStream = Uint8List.sublistView(tableSlice, bytesRead);
    outputSize = _decompressHuffmanWeights(descriptor, weightStream, weights);
    offset += inputSize;
  }

  final table = _buildHuffmanDecodingTable(weights, outputSize, ranks);
  final codeLengths = Uint8List(_huffmanMaxSymbolCount);
  final maxSymbol = outputSize;
  for (var i = 0; i <= maxSymbol && i < weights.length && i < codeLengths.length; i++) {
    codeLengths[i] = weights[i] & 0xFF;
  }
  return HuffmanTableReadResult(
    table: table,
    bytesConsumed: offset,
    codeLengths: codeLengths,
    maxSymbol: maxSymbol,
  );
}

HuffmanDecodingTable buildHuffmanTableFromCodeLengths(
  Uint8List codeLengths,
  int maxSymbol,
) {
  if (codeLengths.isEmpty) {
    throw ZstdFrameFormatException('Cannot build Huffman table from empty code lengths');
  }
  if (maxSymbol < 0) {
    throw ZstdFrameFormatException('Invalid maximum symbol index $maxSymbol');
  }
  final cappedMaxSymbol = maxSymbol >= codeLengths.length ? codeLengths.length - 1 : maxSymbol;
  if (cappedMaxSymbol < 0) {
    throw ZstdFrameFormatException('No symbols available to build Huffman table');
  }

  final weights = List<int>.filled(_huffmanMaxSymbolCount + 1, 0);
  final ranks = List<int>.filled(_huffmanMaxTableLog + 1, 0);
  for (var i = 0; i <= cappedMaxSymbol; i++) {
    final weight = codeLengths[i];
    if (weight > _huffmanMaxTableLog) {
      throw ZstdFrameFormatException('Huffman code length $weight exceeds max table log $_huffmanMaxTableLog');
    }
    weights[i] = weight;
  }
  return _buildHuffmanDecodingTable(weights, cappedMaxSymbol + 1, ranks);
}

HuffmanDecodingTable _buildHuffmanDecodingTable(
  List<int> weights,
  int numberOfWeights,
  List<int> ranks,
) {
  if (numberOfWeights <= 0 || numberOfWeights > _huffmanMaxSymbolCount) {
    throw ZstdFrameFormatException('Invalid number of Huffman symbols $numberOfWeights');
  }

  int totalWeight = 0;
  for (int i = 0; i < numberOfWeights; i++) {
    final weight = weights[i];
    if (weight < 0 || weight > _huffmanMaxTableLog) {
      throw ZstdFrameFormatException('Invalid Huffman weight $weight');
    }
    if (weight < ranks.length) {
      ranks[weight]++;
    }
    totalWeight += (1 << weight) >> 1;
  }

  if (totalWeight == 0) {
    throw ZstdFrameFormatException('Invalid Huffman table (zero total weight)');
  }

  final tableLog = _highestBit(totalWeight) + 1;
  if (tableLog < _huffmanMinTableLog || tableLog > _huffmanMaxTableLog) {
    throw ZstdFrameFormatException('Huffman tableLog $tableLog out of range');
  }
  final total = 1 << tableLog;
  final rest = total - totalWeight;
  if (!_isPowerOfTwo(rest)) {
    throw ZstdFrameFormatException('Huffman table has invalid remainder $rest');
  }
  final lastWeight = _highestBit(rest) + 1;
  weights[numberOfWeights] = lastWeight;
  ranks[lastWeight]++;
  final symbolCount = numberOfWeights + 1;

  int nextRankStart = 0;
  for (int i = 1; i < tableLog + 1; ++i) {
    final current = nextRankStart;
    nextRankStart += ranks[i] << (i - 1);
    ranks[i] = current;
  }

  final tableSize = 1 << tableLog;
  final symbols = Uint8List(tableSize);
  final numbersOfBits = Uint8List(tableSize);

  for (int n = 0; n < symbolCount; n++) {
    final weight = weights[n];
    if (weight <= 0) {
      continue;
    }
    final length = (1 << weight) >> 1;
    final nbBits = tableLog + 1 - weight;
    final start = ranks[weight];
    final end = start + length;
    if (end > tableSize) {
      throw ZstdFrameFormatException('Huffman table overflow while assigning ranks');
    }
    for (int i = start; i < end; i++) {
      symbols[i] = n;
      numbersOfBits[i] = nbBits;
    }
    ranks[weight] = end;
  }

  if (ranks[1] < 2 || (ranks[1] & 1) != 0) {
    throw ZstdFrameFormatException('Invalid Huffman ranks for weight=1');
  }

  return HuffmanDecodingTable(
    tableLog: tableLog,
    symbols: symbols,
    numberOfBits: numbersOfBits,
  );
}

int _decompressHuffmanWeights(
  FseTableDescriptor descriptor,
  Uint8List input,
  List<int> output,
) {
  if (input.isEmpty) {
    throw ZstdFrameFormatException('Missing Huffman weight stream');
  }

  final table = _buildHuffmanFseTable(descriptor);
  final initializer = _BitStreamInitializer(input, 0, input.length);
  initializer.initialize();

  var bits = initializer.bits;
  var bitsConsumed = initializer.bitsConsumed;
  var current = initializer.current;

  int state1 = _peekBits(bitsConsumed, bits, table.log2Size);
  bitsConsumed += table.log2Size;

  var loader = _BitStreamLoader(
    buffer: input,
    start: 0,
    current: current,
    bits: bits,
    bitsConsumed: bitsConsumed,
  );
  loader.load();
  bits = loader.bits;
  bitsConsumed = loader.bitsConsumed;
  current = loader.current;

  int state2 = _peekBits(bitsConsumed, bits, table.log2Size);
  bitsConsumed += table.log2Size;

  loader = _BitStreamLoader(
    buffer: input,
    start: 0,
    current: current,
    bits: bits,
    bitsConsumed: bitsConsumed,
  );
  loader.load();
  bits = loader.bits;
  bitsConsumed = loader.bitsConsumed;
  current = loader.current;

  final symbols = table.symbol;
  final numbersOfBits = table.numberOfBits;
  final newStates = table.newState;

  int outputIndex = 0;
  final outputLimit = output.length;

  while (outputIndex <= outputLimit - 4) {
    output[outputIndex++] = symbols[state1];
    int nbBits = numbersOfBits[state1];
    state1 = newStates[state1] + _peekBits(bitsConsumed, bits, nbBits);
    bitsConsumed += nbBits;

    output[outputIndex++] = symbols[state2];
    nbBits = numbersOfBits[state2];
    state2 = newStates[state2] + _peekBits(bitsConsumed, bits, nbBits);
    bitsConsumed += nbBits;

    output[outputIndex++] = symbols[state1];
    nbBits = numbersOfBits[state1];
    state1 = newStates[state1] + _peekBits(bitsConsumed, bits, nbBits);
    bitsConsumed += nbBits;

    output[outputIndex++] = symbols[state2];
    nbBits = numbersOfBits[state2];
    state2 = newStates[state2] + _peekBits(bitsConsumed, bits, nbBits);
    bitsConsumed += nbBits;

    loader = _BitStreamLoader(
      buffer: input,
      start: 0,
      current: current,
      bits: bits,
      bitsConsumed: bitsConsumed,
    );
    final done = loader.load();
    bits = loader.bits;
    bitsConsumed = loader.bitsConsumed;
    current = loader.current;
    if (done) {
      break;
    }
  }

  while (true) {
    if (outputIndex > outputLimit - 2) {
      throw ZstdFrameFormatException('Huffman weight buffer too small');
    }
    output[outputIndex++] = symbols[state1];
    int nbBits = numbersOfBits[state1];
    state1 = newStates[state1] + _peekBits(bitsConsumed, bits, nbBits);
    bitsConsumed += nbBits;

    loader = _BitStreamLoader(
      buffer: input,
      start: 0,
      current: current,
      bits: bits,
      bitsConsumed: bitsConsumed,
    );
    loader.load();
    bits = loader.bits;
    bitsConsumed = loader.bitsConsumed;
    current = loader.current;

    if (loader.overflow) {
      output[outputIndex++] = symbols[state2];
      break;
    }

    output[outputIndex++] = symbols[state2];
    nbBits = numbersOfBits[state2];
    state2 = newStates[state2] + _peekBits(bitsConsumed, bits, nbBits);
    bitsConsumed += nbBits;

    loader = _BitStreamLoader(
      buffer: input,
      start: 0,
      current: current,
      bits: bits,
      bitsConsumed: bitsConsumed,
    );
    loader.load();
    bits = loader.bits;
    bitsConsumed = loader.bitsConsumed;
    current = loader.current;

    if (loader.overflow) {
      output[outputIndex++] = symbols[state1];
      break;
    }
  }

  return outputIndex;
}

_HuffmanFseTable _buildHuffmanFseTable(FseTableDescriptor descriptor) {
  final tableLog = descriptor.tableLog;
  if (tableLog <= 0 || tableLog > _huffmanMaxFseTableLog) {
    throw ZstdFrameFormatException('Invalid Huffman FSE tableLog $tableLog');
  }
  final tableSize = 1 << tableLog;
  final counts = descriptor.normalizedCounts;
  if (counts.length < descriptor.maxSymbol + 1) {
    throw ZstdFrameFormatException('FSE normalized counts too small');
  }

  final symbolNext = List<int>.filled(descriptor.maxSymbol + 1, 0);
  final tableSymbols = List<int>.filled(tableSize, 0);
  final largeLimit = 1 << (tableLog - 1);
  int highThreshold = tableSize - 1;

  for (int symbol = 0; symbol <= descriptor.maxSymbol; symbol++) {
    final count = counts[symbol];
    if (count == -1) {
      if (highThreshold < 0) {
        throw ZstdFrameFormatException('FSE table overflow for Huffman weights');
      }
      tableSymbols[highThreshold--] = symbol;
      symbolNext[symbol] = 1;
    } else if (count > 0) {
      if (count >= largeLimit) {
        // Fast mode flag ignored.
      }
      symbolNext[symbol] = count;
    }
  }

  final tableMask = tableSize - 1;
  final step = _fseTableStep(tableSize);
  int position = 0;
  for (int symbol = 0; symbol <= descriptor.maxSymbol; symbol++) {
    final count = counts[symbol];
    if (count <= 0) continue;
    for (int i = 0; i < count; i++) {
      tableSymbols[position] = symbol;
      position = (position + step) & tableMask;
      while (position > highThreshold) {
        position = (position + step) & tableMask;
      }
    }
  }
  if (position != 0) {
    throw ZstdFrameFormatException('Invalid FSE distribution for Huffman weights');
  }

  final symbols = List<int>.filled(tableSize, 0);
  final numbersOfBits = List<int>.filled(tableSize, 0);
  final newStates = List<int>.filled(tableSize, 0);

  for (int tableIndex = 0; tableIndex < tableSize; tableIndex++) {
    final symbol = tableSymbols[tableIndex];
    final nextState = symbolNext[symbol]++;
    final nbBits = tableLog - _highestBit(nextState);
    symbols[tableIndex] = symbol;
    numbersOfBits[tableIndex] = nbBits;
    newStates[tableIndex] = (nextState << nbBits) - tableSize;
  }

  return _HuffmanFseTable(
    symbol: symbols,
    numberOfBits: numbersOfBits,
    newState: newStates,
    log2Size: tableLog,
  );
}

Uint8List _decodeHuffmanStreams(
  Uint8List payload,
  int payloadOffset,
  LiteralsSectionHeader header,
  HuffmanDecodingTable table,
) {
  final output = Uint8List(header.regeneratedSize);
  if (header.streamCount == 1) {
    _decodeStreamSegment(
      buffer: payload,
      start: payloadOffset,
      end: payload.length,
      table: table,
      output: output,
      outputStart: 0,
      outputEnd: output.length,
    );
  } else if (header.streamCount == 4) {
    _decodeFourStreams(
      payload: payload,
      start: payloadOffset,
      end: payload.length,
      table: table,
      output: output,
    );
  } else {
    throw ZstdFrameFormatException('Unsupported literal stream count ${header.streamCount}');
  }
  return output;
}

void _decodeFourStreams({
  required Uint8List payload,
  required int start,
  required int end,
  required HuffmanDecodingTable table,
  required Uint8List output,
}) {
  if (end - start < _huffmanJumpTableSize) {
    throw ZstdFrameFormatException('Not enough bytes for Huffman jump table');
  }
  final size1 = payload[start] | (payload[start + 1] << 8);
  final size2 = payload[start + 2] | (payload[start + 3] << 8);
  final size3 = payload[start + 4] | (payload[start + 5] << 8);

  final stream1Start = start + _huffmanJumpTableSize;
  final stream2Start = stream1Start + size1;
  final stream3Start = stream2Start + size2;
  final stream4Start = stream3Start + size3;

  if (!(stream1Start <= stream2Start &&
      stream2Start <= stream3Start &&
      stream3Start <= stream4Start &&
      stream4Start <= end)) {
    throw ZstdFrameFormatException('Invalid Huffman stream layout');
  }

  final segmentSize = (output.length + 3) >> 2;
  final firstEnd = math.min(segmentSize, output.length);
  final secondEnd = math.min(firstEnd + segmentSize, output.length);
  final thirdEnd = math.min(secondEnd + segmentSize, output.length);
  final fourthEnd = output.length;

  _decodeStreamSegment(
    buffer: payload,
    start: stream1Start,
    end: stream2Start,
    table: table,
    output: output,
    outputStart: 0,
    outputEnd: firstEnd,
  );
  _decodeStreamSegment(
    buffer: payload,
    start: stream2Start,
    end: stream3Start,
    table: table,
    output: output,
    outputStart: firstEnd,
    outputEnd: secondEnd,
  );
  _decodeStreamSegment(
    buffer: payload,
    start: stream3Start,
    end: stream4Start,
    table: table,
    output: output,
    outputStart: secondEnd,
    outputEnd: thirdEnd,
  );
  _decodeStreamSegment(
    buffer: payload,
    start: stream4Start,
    end: end,
    table: table,
    output: output,
    outputStart: thirdEnd,
    outputEnd: fourthEnd,
  );
}

void _decodeStreamSegment({
  required Uint8List buffer,
  required int start,
  required int end,
  required HuffmanDecodingTable table,
  required Uint8List output,
  required int outputStart,
  required int outputEnd,
}) {
  if (start >= end) {
    throw ZstdFrameFormatException('Empty Huffman bitstream segment');
  }
  final initializer = _BitStreamInitializer(buffer, start, end);
  initializer.initialize();
  _decodeWithInitializer(
    buffer: buffer,
    start: start,
    initializer: initializer,
    table: table,
    output: output,
    outputStart: outputStart,
    outputEnd: outputEnd,
  );
}

void _decodeWithInitializer({
  required Uint8List buffer,
  required int start,
  required _BitStreamInitializer initializer,
  required HuffmanDecodingTable table,
  required Uint8List output,
  required int outputStart,
  required int outputEnd,
}) {
  var bits = initializer.bits;
  var bitsConsumed = initializer.bitsConsumed;
  var current = initializer.current;

  final tableLog = table.tableLog;
  final symbols = table.symbols;
  final numbersOfBits = table.numberOfBits;

  var index = outputStart;
  final fastLimit = outputEnd - 4;

  while (index <= fastLimit) {
    final loader = _BitStreamLoader(
      buffer: buffer,
      start: start,
      current: current,
      bits: bits,
      bitsConsumed: bitsConsumed,
    );
    final done = loader.load();
    bits = loader.bits;
    bitsConsumed = loader.bitsConsumed;
    current = loader.current;
    if (done) {
      break;
    }

    bitsConsumed = _decodeSymbol(
      output,
      index,
      bits,
      bitsConsumed,
      tableLog,
      symbols,
      numbersOfBits,
    );
    bitsConsumed = _decodeSymbol(output, index + 1, bits, bitsConsumed, tableLog, symbols, numbersOfBits);
    bitsConsumed = _decodeSymbol(output, index + 2, bits, bitsConsumed, tableLog, symbols, numbersOfBits);
    bitsConsumed = _decodeSymbol(output, index + 3, bits, bitsConsumed, tableLog, symbols, numbersOfBits);
    index += 4;
  }

  while (index < outputEnd) {
    final loader = _BitStreamLoader(
      buffer: buffer,
      start: start,
      current: current,
      bits: bits,
      bitsConsumed: bitsConsumed,
    );
    final done = loader.load();
    bits = loader.bits;
    bitsConsumed = loader.bitsConsumed;
    current = loader.current;
    if (done) {
      break;
    }
    bitsConsumed = _decodeSymbol(output, index++, bits, bitsConsumed, tableLog, symbols, numbersOfBits);
  }

  while (index < outputEnd) {
    bitsConsumed = _decodeSymbol(output, index++, bits, bitsConsumed, tableLog, symbols, numbersOfBits);
  }

  if (!_isEndOfStream(start, current, bitsConsumed)) {
    throw ZstdFrameFormatException('Huffman bitstream not fully consumed');
  }
}

int _decodeSymbol(
  Uint8List output,
  int outputIndex,
  int bitContainer,
  int bitsConsumed,
  int tableLog,
  Uint8List symbols,
  Uint8List numbersOfBits,
) {
  final value = _peekBitsFast(bitsConsumed, bitContainer, tableLog);
  output[outputIndex] = symbols[value];
  return bitsConsumed + numbersOfBits[value];
}

int _peekBitsFast(int bitsConsumed, int bitContainer, int numberOfBits) {
  final shifted = ((bitContainer & _bitContainerMask) << bitsConsumed) & _bitContainerMask;
  final result = shifted >> (64 - numberOfBits);
  return result & ((1 << numberOfBits) - 1);
}

int _peekBits(int bitsConsumed, int bitContainer, int numberOfBits) {
  final shifted = ((bitContainer & _bitContainerMask) << bitsConsumed) & _bitContainerMask;
  final trimmed = (shifted >> 1) & _bitContainerMask;
  final result = trimmed >> (63 - numberOfBits);
  return result & ((1 << numberOfBits) - 1);
}

bool _isEndOfStream(int start, int current, int bitsConsumed) {
  return start == current && bitsConsumed == 64;
}

int _readUint64LE(Uint8List buffer, int offset) {
  int value = 0;
  for (int i = 0; i < 8; i++) {
    value |= (buffer[offset + i] & 0xFF) << (8 * i);
  }
  return value & _bitContainerMask;
}

int _readTail(Uint8List buffer, int offset, int length) {
  if (length <= 0) {
    return 0;
  }
  int bits = buffer[offset] & 0xFF;
  if (length >= 2) {
    bits |= (buffer[offset + 1] & 0xFF) << 8;
  }
  if (length >= 3) {
    bits |= (buffer[offset + 2] & 0xFF) << 16;
  }
  if (length >= 4) {
    bits |= (buffer[offset + 3] & 0xFF) << 24;
  }
  if (length >= 5) {
    bits |= (buffer[offset + 4] & 0xFF) << 32;
  }
  if (length >= 6) {
    bits |= (buffer[offset + 5] & 0xFF) << 40;
  }
  if (length >= 7) {
    bits |= (buffer[offset + 6] & 0xFF) << 48;
  }
  return bits & _bitContainerMask;
}

int _highestBit(int value) {
  if (value <= 0) {
    return -1;
  }
  return value.bitLength - 1;
}

bool _isPowerOfTwo(int value) => value > 0 && (value & (value - 1)) == 0;

int _fseTableStep(int tableSize) => (tableSize >> 1) + (tableSize >> 3) + 3;
