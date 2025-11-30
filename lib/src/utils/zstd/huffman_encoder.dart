import 'dart:math' as math;
import 'dart:typed_data';

import '../bit_stream_writer.dart';
import 'literals.dart';

final Uint8List _emptyHuffmanTableBytes = Uint8List(0);


class HuffmanLiteralEncodingResult {
  HuffmanLiteralEncodingResult({
    required this.bytes,
    required this.type,
    required this.regeneratedSize,
    required this.compressedSize,
    required this.streamCount,
    required this.usedRepeatTable,
  });

  final Uint8List bytes;
  final LiteralsBlockType type;
  final int regeneratedSize;
  final int compressedSize;
  final int streamCount;
  final bool usedRepeatTable;
}

class HuffmanCompressionContext {
  HuffmanCompressionContext()
      : table = HuffmanCompressionTable(HuffmanCompressionTable.maxSymbolCount),
        tableWriterWorkspace = HuffmanTableWriterWorkspace(),
        repeatState = _HuffmanRepeatTableState();

  final HuffmanCompressionTable table;
  final HuffmanTableWriterWorkspace tableWriterWorkspace;
  final _HuffmanRepeatTableState repeatState;

  bool _pendingSeededTable = false;

  void seedFromDictionary(Uint8List codeLengths, int maxSymbol) {
    if (!table.initializeFromCodeLengths(codeLengths, maxSymbol)) {
      _pendingSeededTable = false;
      return;
    }
    repeatState.seedFromCodeLengths(codeLengths, maxSymbol);
    _pendingSeededTable = true;
  }

  _SeededHuffmanEncodingHandle? takeSeededTable() {
    if (!_pendingSeededTable) {
      return null;
    }
    _pendingSeededTable = false;
    return _SeededHuffmanEncodingHandle(table: table);
  }
}

class _SeededHuffmanEncodingHandle {
  const _SeededHuffmanEncodingHandle({
    required this.table,
  });

  final HuffmanCompressionTable table;
}

HuffmanLiteralEncodingResult? tryEncodeLiterals(
  Uint8List literals,
  HuffmanCompressionContext context,
) {
  final literalCount = literals.length;
  if (literalCount == 0) {
    return null;
  }

  const minCompressibleSize = 64;
  if (literalCount < minCompressibleSize) {
    return null;
  }

  final seededHandle = context.takeSeededTable();
  if (seededHandle != null) {
    return _encodeWithTable(
      literals: literals,
      table: seededHandle.table,
      literalType: LiteralsBlockType.repeat,
      usedRepeatTable: true,
      tableBytes: _emptyHuffmanTableBytes,
    );
  }

  final counts = Histogram.count(literals);
  final maxSymbol = Histogram.findMaxSymbol(counts, HuffmanCompressionTable.maxSymbol);
  if (maxSymbol < 0) {
    return null;
  }

  final largestCount = Histogram.findLargestCount(counts, maxSymbol);
  if (largestCount == literalCount) {
    return null;
  }
  if (largestCount <= (literalCount >> 7) + 4) {
    return null;
  }

  final table = context.table;
  final maxBits = HuffmanCompressionTable.optimalNumberOfBits(
    HuffmanCompressionTable.maxTableLog,
    literalCount,
    maxSymbol,
  );

  final built = table.initialize(counts, maxSymbol, maxBits);
  if (!built) {
    return null;
  }
  final tableBytes = table.write(context.tableWriterWorkspace);
  final repeatState = context.repeatState;
  final useRepeatTable = repeatState.canReuse(table, maxSymbol);
  final literalType = useRepeatTable ? LiteralsBlockType.repeat : LiteralsBlockType.compressed;
  final result = _encodeWithTable(
    literals: literals,
    table: table,
    literalType: literalType,
    usedRepeatTable: useRepeatTable,
    tableBytes: useRepeatTable ? _emptyHuffmanTableBytes : tableBytes,
  );
  if (result != null && !useRepeatTable) {
    repeatState.save(table, maxSymbol);
  }
  return result;
}

HuffmanLiteralEncodingResult? _encodeWithTable({
  required Uint8List literals,
  required HuffmanCompressionTable table,
  required LiteralsBlockType literalType,
  required bool usedRepeatTable,
  required Uint8List tableBytes,
}) {
  final literalCount = literals.length;
  if (literalCount == 0) {
    return null;
  }

  var useSingleStream = literalCount < 256;
  if (literalCount > 0x3FF) {
    useSingleStream = false;
  }

  Uint8List? literalStreams = useSingleStream
      ? HuffmanCompressor.compressSingleStream(literals, table)
      : HuffmanCompressor.compressFourStreams(literals, table);
  if (literalStreams == null || literalStreams.isEmpty) {
    return null;
  }

  var streamCount = useSingleStream ? 1 : 4;
  var compressedSize = (usedRepeatTable ? 0 : tableBytes.length) + literalStreams.length;
  if (compressedSize >= literalCount) {
    return null;
  }

  var header = _LiteralHeaderBuilder.buildCompressed(
    type: literalType,
    regeneratedSize: literalCount,
    compressedSize: compressedSize,
    streamCount: streamCount,
  );

  if (header == null && useSingleStream) {
    useSingleStream = false;
    literalStreams = HuffmanCompressor.compressFourStreams(literals, table);
    if (literalStreams == null || literalStreams.isEmpty) {
      return null;
    }
    streamCount = 4;
    compressedSize = (usedRepeatTable ? 0 : tableBytes.length) + literalStreams.length;
    if (compressedSize >= literalCount) {
      return null;
    }
    header = _LiteralHeaderBuilder.buildCompressed(
      type: literalType,
      regeneratedSize: literalCount,
      compressedSize: compressedSize,
      streamCount: streamCount,
    );
  }

  if (header == null) {
    return null;
  }

  final builder = BytesBuilder(copy: false)
    ..add(header);
  if (!usedRepeatTable && tableBytes.isNotEmpty) {
    builder.add(tableBytes);
  }
  builder.add(literalStreams);

  return HuffmanLiteralEncodingResult(
    bytes: builder.takeBytes(),
    type: literalType,
    regeneratedSize: literalCount,
    compressedSize: compressedSize,
    streamCount: streamCount,
    usedRepeatTable: usedRepeatTable,
  );
}

class Histogram {
  static List<int> count(Uint8List input) {
    final counts = List<int>.filled(HuffmanCompressionTable.maxSymbolCount, 0);
    for (final value in input) {
      counts[value & 0xFF]++;
    }
    return counts;
  }

  static int findLargestCount(List<int> counts, int maxSymbol) {
    var maxCount = 0;
    for (var i = 0; i <= maxSymbol; i++) {
      if (counts[i] > maxCount) {
        maxCount = counts[i];
      }
    }
    return maxCount;
  }

  static int findMaxSymbol(List<int> counts, int maxSymbol) {
    var symbol = maxSymbol;
    while (symbol >= 0) {
      if (counts[symbol] != 0) {
        return symbol;
      }
      symbol--;
    }
    return -1;
  }
}

class HuffmanCompressor {
  static Uint8List? compressSingleStream(Uint8List input, HuffmanCompressionTable table) {
    final writer = BitStreamWriter();
    final remainder = input.length & 3;
    final aligned = input.length - remainder;
    switch (remainder) {
      case 3:
        _encodeSymbol(writer, table, input[aligned + 2]);
        _encodeSymbol(writer, table, input[aligned + 1]);
        _encodeSymbol(writer, table, input[aligned]);
        break;
      case 2:
        _encodeSymbol(writer, table, input[aligned + 1]);
        _encodeSymbol(writer, table, input[aligned]);
        break;
      case 1:
        _encodeSymbol(writer, table, input[aligned]);
        break;
    }

    for (var index = aligned; index > 0; index -= 4) {
      _encodeSymbol(writer, table, input[index - 1]);
      _encodeSymbol(writer, table, input[index - 2]);
      _encodeSymbol(writer, table, input[index - 3]);
      _encodeSymbol(writer, table, input[index - 4]);
    }

    return writer.closeWithTerminator();
  }

  static Uint8List? compressFourStreams(Uint8List input, HuffmanCompressionTable table) {
    final inputSize = input.length;
    if (inputSize == 0) {
      return null;
    }

    final segmentSize = (inputSize + 3) >> 2; // ceil(inputSize / 4)
    final lengths = List<int>.filled(4, segmentSize);
    lengths[3] = math.max(0, inputSize - segmentSize * 3);

    final streams = <Uint8List>[];
    var position = 0;
    for (var streamIndex = 0; streamIndex < 4; streamIndex++) {
      final chunkLength = streamIndex < 3 ? lengths[streamIndex] : lengths[3];
      if (chunkLength <= 0) {
        streams.add(Uint8List(0));
        continue;
      }
      final end = position + chunkLength;
      final chunk = input.sublist(position, end);
      final compressed = compressSingleStream(chunk, table);
      if (compressed == null || compressed.isEmpty) {
        return null;
      }
      streams.add(compressed);
      position = end;
    }

    if (streams.length != 4) {
      return null;
    }

    final jumpTable = Uint8List(6);
    _writeUint16(jumpTable, 0, streams[0].length);
    _writeUint16(jumpTable, 2, streams[1].length);
    _writeUint16(jumpTable, 4, streams[2].length);

    final builder = BytesBuilder(copy: false)
      ..add(jumpTable)
      ..add(streams[0])
      ..add(streams[1])
      ..add(streams[2])
      ..add(streams[3]);
    return builder.takeBytes();
  }

  static void _encodeSymbol(BitStreamWriter writer, HuffmanCompressionTable table, int value) {
    final symbol = value & 0xFF;
    final bits = table.numberOfBits[symbol];
    if (bits == 0) {
      throw StateError('Missing Huffman code for symbol $symbol');
    }
    writer.writeBits(table.values[symbol], bits);
  }

  static void _writeUint16(Uint8List buffer, int offset, int value) {
    buffer[offset] = value & 0xFF;
    buffer[offset + 1] = (value >> 8) & 0xFF;
  }
}

class _LiteralHeaderBuilder {
  static Uint8List? buildCompressed({
    required LiteralsBlockType type,
    required int regeneratedSize,
    required int compressedSize,
    required int streamCount,
  }) {
    if (streamCount == 1) {
      if (regeneratedSize > 0x3FF || compressedSize > 0x3FF) {
        return null;
      }
      return _buildShortHeader(type, 0, regeneratedSize, compressedSize);
    }

    if (regeneratedSize <= 0x3FF && compressedSize <= 0x3FF) {
      return _buildShortHeader(type, 1, regeneratedSize, compressedSize);
    }
    if (regeneratedSize <= 0x3FFF && compressedSize <= 0x3FFF) {
      return _buildMediumHeader(type, regeneratedSize, compressedSize);
    }
    if (regeneratedSize <= 0x3FFFF && compressedSize <= 0x3FFFF) {
      return _buildLongHeader(type, regeneratedSize, compressedSize);
    }
    return null;
  }

  static Uint8List _buildShortHeader(
    LiteralsBlockType type,
    int sizeFormat,
    int regeneratedSize,
    int compressedSize,
  ) {
    final value = type.index |
        (sizeFormat << 2) |
        (regeneratedSize << 4) |
        (compressedSize << 14);
    final header = Uint8List(3);
    header[0] = value & 0xFF;
    header[1] = (value >> 8) & 0xFF;
    header[2] = (value >> 16) & 0xFF;
    return header;
  }

  static Uint8List _buildMediumHeader(
    LiteralsBlockType type,
    int regeneratedSize,
    int compressedSize,
  ) {
    final value = type.index |
        (2 << 2) |
        (regeneratedSize << 4) |
        (compressedSize << 18);
    final header = Uint8List(4);
    header[0] = value & 0xFF;
    header[1] = (value >> 8) & 0xFF;
    header[2] = (value >> 16) & 0xFF;
    header[3] = (value >> 24) & 0xFF;
    return header;
  }

  static Uint8List _buildLongHeader(
    LiteralsBlockType type,
    int regeneratedSize,
    int compressedSize,
  ) {
    final compLow = compressedSize & 0x3FF;
    final compHigh = compressedSize >> 10;
    final value = type.index | (3 << 2) | (regeneratedSize << 4) | (compLow << 22);
    final header = Uint8List(5);
    header[0] = value & 0xFF;
    header[1] = (value >> 8) & 0xFF;
    header[2] = (value >> 16) & 0xFF;
    header[3] = (value >> 24) & 0xFF;
    header[4] = compHigh & 0xFF;
    return header;
  }
}

class HuffmanCompressionTable {
  HuffmanCompressionTable(int capacity)
      : values = List<int>.filled(capacity, 0),
        numberOfBits = List<int>.filled(capacity, 0);

  static const int maxSymbol = 255;
  static const int maxSymbolCount = maxSymbol + 1;
  static const int maxTableLog = 12;
  static const int minTableLog = 5;
  static const int maxFseTableLog = 6;

  final List<int> values;
  final List<int> numberOfBits;
  int _maxSymbol = 0;
  int _maxNumberOfBits = minTableLog;

  bool initialize(List<int> counts, int maxSymbol, int maxAllowedBits) {
    final nodes = <_HuffmanNode>[];
    for (var symbol = 0; symbol <= maxSymbol; symbol++) {
      final count = counts[symbol];
      if (count <= 0) {
        continue;
      }
      nodes.add(_HuffmanNode.leaf(symbol, count));
    }

    if (nodes.isEmpty) {
      return false;
    }

    nodes.sort(_compareNodes);
    while (nodes.length > 1) {
      final left = nodes.removeAt(0);
      final right = nodes.removeAt(0);
      nodes.add(_HuffmanNode.internal(left, right));
      nodes.sort(_compareNodes);
    }

    final root = nodes.first;
    final lengths = List<int>.filled(maxSymbol + 1, 0);
    _assignLengths(root, 0, lengths);

    final longest = lengths.fold<int>(0, math.max);
    if (longest > maxAllowedBits || longest > maxTableLog) {
      return false;
    }
    if (longest < minTableLog) {
      return false;
    }

    final symbolLengths = <_SymbolLength>[];
    for (var symbol = 0; symbol <= maxSymbol; symbol++) {
      final length = lengths[symbol];
      if (length > 0) {
        symbolLengths.add(_SymbolLength(symbol, length));
      } else {
        values[symbol] = 0;
        numberOfBits[symbol] = 0;
      }
    }

    symbolLengths.sort((a, b) {
      final diff = a.length - b.length;
      if (diff != 0) {
        return diff;
      }
      return a.symbol - b.symbol;
    });

    var code = 0;
    var currentLength = symbolLengths.isEmpty ? 0 : symbolLengths.first.length;
    for (final entry in symbolLengths) {
      if (entry.length > currentLength) {
        code <<= (entry.length - currentLength);
        currentLength = entry.length;
      }
      values[entry.symbol] = code;
      numberOfBits[entry.symbol] = entry.length;
      code++;
    }

    _maxSymbol = maxSymbol;
    _maxNumberOfBits = longest;
    return true;
  }

  bool initializeFromCodeLengths(Uint8List codeLengths, int maxSymbol) {
    if (maxSymbol < 0 || maxSymbol >= codeLengths.length) {
      return false;
    }
    final symbolLengths = <_SymbolLength>[];
    var longest = 0;
    for (var symbol = 0; symbol <= maxSymbol; symbol++) {
      final length = codeLengths[symbol];
      if (length == 0) {
        values[symbol] = 0;
        numberOfBits[symbol] = 0;
        continue;
      }
      if (length > maxTableLog) {
        return false;
      }
      symbolLengths.add(_SymbolLength(symbol, length));
      if (length > longest) {
        longest = length;
      }
    }
    if (symbolLengths.isEmpty) {
      return false;
    }
    _maxSymbol = maxSymbol;
    _maxNumberOfBits = longest;
    symbolLengths.sort((a, b) {
      final diff = a.length - b.length;
      return diff != 0 ? diff : a.symbol - b.symbol;
    });

    var code = 0;
    var currentLength = symbolLengths.first.length;
    for (final entry in symbolLengths) {
      if (entry.length > currentLength) {
        code <<= (entry.length - currentLength);
        currentLength = entry.length;
      }
      values[entry.symbol] = code;
      numberOfBits[entry.symbol] = entry.length;
      code++;
    }
    return true;
  }

  static int optimalNumberOfBits(int maxNumberOfBits, int inputSize, int maxSymbol) {
    if (inputSize <= 1) {
      throw ArgumentError('Input too small for Huffman table');
    }
    var result = maxNumberOfBits;
    result = math.min(result, _highestBit(inputSize - 1) - 1);
    result = math.max(result, _minTableLog(inputSize, maxSymbol));
    result = math.max(result, minTableLog);
    result = math.min(result, maxTableLog);
    return result;
  }

  Uint8List write(HuffmanTableWriterWorkspace workspace) {
    final weights = workspace.weights;
    final entryCount = _maxSymbol;
    for (var symbol = 0; symbol < entryCount; symbol++) {
      final bits = numberOfBits[symbol];
      weights[symbol] = bits == 0 ? 0 : (_maxNumberOfBits + 1 - bits);
    }
    if (entryCount >= 0) {
      weights[entryCount] = 0;
    }

    final fsePayload = _buildFseWeightPayload(weights, entryCount, workspace);
    if (fsePayload != null) {
      return fsePayload;
    }
    return _buildRawWeightPayload(weights, entryCount);
  }

  Uint8List _buildRawWeightPayload(Uint8List weights, int entryCount) {
    final size = (entryCount + 1) >> 1;
    final buffer = Uint8List(size + 1);
    buffer[0] = (127 + entryCount) & 0xFF;
    if (entryCount == 0) {
      return buffer;
    }
    for (var i = 0; i < entryCount; i += 2) {
      final first = weights[i] & 0xF;
      final second = weights[i + 1] & 0xF;
      buffer[1 + (i >> 1)] = (first << 4) | second;
    }
    return buffer;
  }

  Uint8List? _buildFseWeightPayload(
    Uint8List weights,
    int entryCount,
    HuffmanTableWriterWorkspace workspace,
  ) {
    if (entryCount <= 1) {
      return null;
    }

    final counts = workspace.counts;
    _WeightHistogram.count(weights, entryCount, counts);
    final maxWeightSymbol = _WeightHistogram.findMaxSymbol(counts, maxTableLog);
    final maxCount = _WeightHistogram.findLargestCount(counts, maxWeightSymbol);
    if (maxCount == entryCount || maxCount <= 1) {
      return null;
    }

    final normalizedCounts = workspace.normalizedCounts;
    for (var i = 0; i < normalizedCounts.length; i++) {
      normalizedCounts[i] = 0;
    }

    final tableLog = FiniteStateEntropyEncoder.optimalTableLog(
      maxFseTableLog,
      entryCount,
      maxWeightSymbol,
    );
    FiniteStateEntropyEncoder.normalizeCounts(
      normalizedCounts,
      tableLog,
      counts,
      entryCount,
      maxWeightSymbol,
    );

    final normalizedHeader = FiniteStateEntropyEncoder.writeNormalizedCounts(
      normalizedCounts,
      maxWeightSymbol,
      tableLog,
    );
    final compressionTable = workspace.fseTable;
    compressionTable.initialize(normalizedCounts, maxWeightSymbol, tableLog);
    final bitstream = FiniteStateEntropyEncoder.compressWeights(
      weights,
      entryCount,
      compressionTable,
    );
    if (bitstream == null || bitstream.isEmpty) {
      return null;
    }

    final payloadBuilder = BytesBuilder(copy: false)
      ..add(normalizedHeader)
      ..add(bitstream);
    final body = payloadBuilder.takeBytes();

    if (body.length <= 1 || body.length > 127) {
      return null;
    }
    final rawHeaderSupported = entryCount <= 127;
    if (rawHeaderSupported && entryCount > 0 && body.length >= entryCount ~/ 2) {
      return null;
    }

    final result = Uint8List(body.length + 1);
    result[0] = body.length;
    result.setRange(1, result.length, body);
    return result;
  }

  static void _assignLengths(_HuffmanNode node, int depth, List<int> lengths) {
    if (node.isLeaf) {
      lengths[node.symbol] = depth == 0 ? 1 : depth;
      return;
    }
    _assignLengths(node.left!, depth + 1, lengths);
    _assignLengths(node.right!, depth + 1, lengths);
  }
}

class _HuffmanNode {
  _HuffmanNode._(this.symbol, this.weight, this.left, this.right);

  factory _HuffmanNode.leaf(int symbol, int weight) => _HuffmanNode._(symbol, weight, null, null);

  factory _HuffmanNode.internal(_HuffmanNode left, _HuffmanNode right) =>
      _HuffmanNode._(math.min(left.symbol, right.symbol), left.weight + right.weight, left, right);

  final int symbol;
  final int weight;
  final _HuffmanNode? left;
  final _HuffmanNode? right;

  bool get isLeaf => left == null && right == null;
}

int _compareNodes(_HuffmanNode a, _HuffmanNode b) {
  final diff = a.weight - b.weight;
  if (diff != 0) {
    return diff;
  }
  return a.symbol - b.symbol;
}

class _SymbolLength {
  _SymbolLength(this.symbol, this.length);

  final int symbol;
  final int length;
}

class HuffmanTableWriterWorkspace {
  HuffmanTableWriterWorkspace()
      : weights = Uint8List(HuffmanCompressionTable.maxSymbolCount + 1),
        counts = List<int>.filled(HuffmanCompressionTable.maxTableLog + 1, 0),
        normalizedCounts = List<int>.filled(HuffmanCompressionTable.maxTableLog + 1, 0),
        fseTable = FseCompressionTable(
          HuffmanCompressionTable.maxFseTableLog,
          HuffmanCompressionTable.maxTableLog,
        );

  final Uint8List weights;
  final List<int> counts;
  final List<int> normalizedCounts;
  final FseCompressionTable fseTable;
}

class _HuffmanRepeatTableState {
  Uint8List? _lengths;
  int _maxSymbol = -1;

  bool canReuse(HuffmanCompressionTable table, int maxSymbol) {
    final cached = _lengths;
    if (cached == null) {
      return false;
    }
    if (_maxSymbol != maxSymbol) {
      return false;
    }
    for (var symbol = 0; symbol <= maxSymbol; symbol++) {
      if (cached[symbol] != table.numberOfBits[symbol]) {
        return false;
      }
    }
    return true;
  }

  void save(HuffmanCompressionTable table, int maxSymbol) {
    final snapshot = Uint8List(maxSymbol + 1);
    for (var symbol = 0; symbol <= maxSymbol; symbol++) {
      snapshot[symbol] = table.numberOfBits[symbol];
    }
    _lengths = snapshot;
    _maxSymbol = maxSymbol;
  }

  void seedFromCodeLengths(Uint8List lengths, int maxSymbol) {
    if (maxSymbol < 0 || maxSymbol >= lengths.length) {
      _lengths = null;
      _maxSymbol = -1;
      return;
    }
    final snapshot = Uint8List(maxSymbol + 1);
    for (var symbol = 0; symbol <= maxSymbol; symbol++) {
      snapshot[symbol] = lengths[symbol];
    }
    _lengths = snapshot;
    _maxSymbol = maxSymbol;
  }
}

class _WeightHistogram {
  static void count(Uint8List input, int length, List<int> counts) {
    for (var i = 0; i < counts.length; i++) {
      counts[i] = 0;
    }
    for (var i = 0; i < length; i++) {
      final value = input[i] & 0xFF;
      if (value < counts.length) {
        counts[value]++;
      }
    }
  }

  static int findMaxSymbol(List<int> counts, int maxSymbol) {
    var symbol = math.min(maxSymbol, counts.length - 1);
    while (symbol > 0 && counts[symbol] == 0) {
      symbol--;
    }
    return symbol;
  }

  static int findLargestCount(List<int> counts, int maxSymbol) {
    final limit = math.min(maxSymbol, counts.length - 1);
    var largest = 0;
    for (var i = 0; i <= limit; i++) {
      if (counts[i] > largest) {
        largest = counts[i];
      }
    }
    return largest;
  }
}

class FiniteStateEntropyEncoder {
  static const int _minTableLog = 5;
  static const List<int> _restToBeat = <int>[
    0,
    473195,
    504333,
    520860,
    550000,
    700000,
    750000,
    830000,
  ];

  static int optimalTableLog(int maxTableLog, int inputSize, int maxSymbol) {
    if (inputSize <= 1) {
      throw ArgumentError('Input too small for FSE normalization');
    }
    var result = maxTableLog;
    result = math.min(result, _highestBit(inputSize - 1) - 2);
    result = math.max(result, _minTableLogValue(inputSize, maxSymbol));
    result = math.max(result, _minTableLog);
    return math.min(result, maxTableLog);
  }

  static void normalizeCounts(
    List<int> normalizedCounts,
    int tableLog,
    List<int> counts,
    int total,
    int maxSymbol,
  ) {
    final scale = 62 - tableLog;
    final step = (1 << 62) ~/ total;
    final vstep = 1 << (scale - 20);

    var stillToDistribute = 1 << tableLog;
    var largest = 0;
    var largestProbability = 0;
    final lowThreshold = total >> tableLog;

    for (var symbol = 0; symbol <= maxSymbol; symbol++) {
      final count = counts[symbol];
      if (count == 0) {
        normalizedCounts[symbol] = 0;
        continue;
      }
      if (count == total) {
        throw StateError('Symbol frequency should be emitted as RLE');
      }
      if (count <= lowThreshold) {
        normalizedCounts[symbol] = -1;
        stillToDistribute--;
        continue;
      }

      var probability = ((count * step) >> scale).toInt();
      if (probability < 8) {
        final restToBeat = vstep * _restToBeat[probability];
        final delta = count * step - (probability << scale);
        if (delta > restToBeat) {
          probability++;
        }
      }

      if (probability > largestProbability) {
        largestProbability = probability;
        largest = symbol;
      }

      normalizedCounts[symbol] = probability;
      stillToDistribute -= probability;
    }

    if (-stillToDistribute >= (normalizedCounts[largest] >> 1)) {
      _normalizeCountsFallback(normalizedCounts, tableLog, counts, total, maxSymbol);
      return;
    }

    normalizedCounts[largest] += stillToDistribute;
  }

  static void _normalizeCountsFallback(
    List<int> normalizedCounts,
    int tableLog,
    List<int> counts,
    int total,
    int maxSymbol,
  ) {
    const int unassigned = -2;
    var distributed = 0;
    final lowThreshold = total >> tableLog;
    var lowOne = (total * 3) >> (tableLog + 1);

    for (var symbol = 0; symbol <= maxSymbol; symbol++) {
      final count = counts[symbol];
      if (count == 0) {
        normalizedCounts[symbol] = 0;
      } else if (count <= lowThreshold) {
        normalizedCounts[symbol] = -1;
        distributed++;
        total -= count;
      } else if (count <= lowOne) {
        normalizedCounts[symbol] = 1;
        distributed++;
        total -= count;
      } else {
        normalizedCounts[symbol] = unassigned;
      }
    }

    final normalizationFactor = 1 << tableLog;
    var toDistribute = normalizationFactor - distributed;

    if ((total / toDistribute) > lowOne) {
      lowOne = (total * 3) ~/ (toDistribute * 2);
      for (var symbol = 0; symbol <= maxSymbol; symbol++) {
        if (normalizedCounts[symbol] == unassigned && counts[symbol] <= lowOne) {
          normalizedCounts[symbol] = 1;
          distributed++;
          total -= counts[symbol];
        }
      }
      toDistribute = normalizationFactor - distributed;
    }

    if (distributed == maxSymbol + 1) {
      var maxValue = 0;
      var maxCount = 0;
      for (var symbol = 0; symbol <= maxSymbol; symbol++) {
        if (counts[symbol] > maxCount) {
          maxValue = symbol;
          maxCount = counts[symbol];
        }
      }
      normalizedCounts[maxValue] += toDistribute;
      return;
    }

    if (total == 0) {
      for (var symbol = 0; toDistribute > 0; symbol = (symbol + 1) % (maxSymbol + 1)) {
        if (normalizedCounts[symbol] > 0) {
          normalizedCounts[symbol]++;
          toDistribute--;
        }
      }
      return;
    }

    final vStepLog = 62 - tableLog;
    final mid = (1 << (vStepLog - 1)) - 1;
    final rStep = (((1 << vStepLog) * toDistribute) + mid) ~/ total;
    var tmpTotal = mid;
    for (var symbol = 0; symbol <= maxSymbol; symbol++) {
      if (normalizedCounts[symbol] == unassigned) {
        final end = tmpTotal + (counts[symbol] * rStep);
        final sStart = (tmpTotal >> vStepLog);
        final sEnd = (end >> vStepLog);
        final weight = sEnd - sStart;
        if (weight < 1) {
          throw StateError('Invalid normalized weight');
        }
        normalizedCounts[symbol] = weight;
        tmpTotal = end;
      }
    }
  }

  static Uint8List writeNormalizedCounts(
    List<int> normalizedCounts,
    int maxSymbol,
    int tableLog,
  ) {
    final buffer = BytesBuilder(copy: false);
    var bitStream = tableLog - _minTableLog;
    var bitCount = 4;
    var remaining = (1 << tableLog) + 1;
    var threshold = 1 << tableLog;
    var tableBitCount = tableLog + 1;
    var symbol = 0;
    var previousWasZero = false;

    void flush16() {
      buffer.add([bitStream & 0xFF, (bitStream >> 8) & 0xFF]);
      bitStream = bitStream >> 16;
      bitCount -= 16;
    }

    while (remaining > 1 && symbol <= maxSymbol) {
      if (previousWasZero) {
        final start = symbol;
        while (symbol <= maxSymbol && normalizedCounts[symbol] == 0) {
          symbol++;
        }
        var runLength = symbol - start;
        while (runLength >= 24) {
          bitStream |= 0xFFFF << bitCount;
          bitCount += 16;
          flush16();
          runLength -= 24;
        }
        while (runLength >= 3) {
          bitStream |= 0x3 << bitCount;
          bitCount += 2;
          runLength -= 3;
        }
        bitStream |= runLength << bitCount;
        bitCount += 2;
        if (bitCount > 16) {
          flush16();
        }
      }

      if (symbol > maxSymbol) {
        break;
      }

      var count = normalizedCounts[symbol++];
      final max = (2 * threshold - 1) - remaining;
      remaining -= count < 0 ? -count : count;
      count++;
      if (count >= threshold) {
        count += max;
      }
      bitStream |= count << bitCount;
      bitCount += tableBitCount;
      if (count < max) {
        bitCount--;
      }
      previousWasZero = count == 1;

      while (remaining < threshold) {
        tableBitCount--;
        threshold >>= 1;
      }

      if (bitCount > 16) {
        flush16();
      }
    }

    while (bitCount > 0) {
      buffer.add([bitStream & 0xFF]);
      bitStream >>= 8;
      bitCount -= 8;
    }

    return buffer.takeBytes();
  }

  static Uint8List? compressWeights(
    Uint8List input,
    int inputSize,
    FseCompressionTable table,
  ) {
    if (inputSize <= 2) {
      return null;
    }

    final writer = BitStreamWriter();
    var index = inputSize;
    var state1 = 0;
    var state2 = 0;

    if ((inputSize & 1) != 0) {
      index--;
      state1 = table.begin(input[index]);
      if (index == 0) {
        return null;
      }
      index--;
      state2 = table.begin(input[index]);
      if (index == 0) {
        return null;
      }
      index--;
      state1 = table.encode(writer, state1, input[index]);
    } else {
      index--;
      state2 = table.begin(input[index]);
      if (index == 0) {
        return null;
      }
      index--;
      state1 = table.begin(input[index]);
    }

    while (index > 0) {
      index--;
      state2 = table.encode(writer, state2, input[index]);
      if (index == 0) {
        break;
      }
      index--;
      state1 = table.encode(writer, state1, input[index]);
    }

    table.finish(writer, state2);
    table.finish(writer, state1);
    return writer.closeWithTerminator();
  }

  static int _minTableLogValue(int inputSize, int maxSymbol) {
    return math.min(_highestBit(inputSize - 1) + 1, _highestBit(maxSymbol) + 2);
  }

  static int _calculateStep(int tableSize) => (tableSize >> 1) + (tableSize >> 3) + 3;
}

class FseCompressionTable {
  FseCompressionTable(int maxTableLog, int maxSymbol)
      : nextState = List<int>.filled(1 << maxTableLog, 0),
        deltaNumberOfBits = List<int>.filled(maxSymbol + 1, 0),
        deltaFindState = List<int>.filled(maxSymbol + 1, 0);

  final List<int> nextState;
  final List<int> deltaNumberOfBits;
  final List<int> deltaFindState;
  int log2Size = 0;

  void initialize(List<int> normalizedCounts, int maxSymbol, int tableLog) {
    final tableSize = 1 << tableLog;
    final table = List<int>.filled(tableSize, 0);
    var highThreshold = tableSize - 1;
    log2Size = tableLog;

    final cumulative = List<int>.filled(HuffmanCompressionTable.maxSymbol + 2, 0);
    cumulative[0] = 0;
    for (var i = 1; i <= maxSymbol + 1; i++) {
      final previous = normalizedCounts[i - 1];
      if (previous == -1) {
        cumulative[i] = cumulative[i - 1] + 1;
        table[highThreshold--] = i - 1;
      } else {
        cumulative[i] = cumulative[i - 1] + previous;
      }
    }
    cumulative[maxSymbol + 1] = tableSize + 1;

    final position = _spreadSymbols(normalizedCounts, maxSymbol, tableSize, highThreshold, table);
    if (position != 0) {
      throw StateError('Failed to spread symbols');
    }

    for (var i = 0; i < tableSize; i++) {
      final symbol = table[i];
      nextState[cumulative[symbol]++] = tableSize + i;
    }

    var total = 0;
    for (var symbol = 0; symbol <= maxSymbol; symbol++) {
      final count = normalizedCounts[symbol];
      if (count == 0) {
        deltaNumberOfBits[symbol] = ((tableLog + 1) << 16) - tableSize;
      } else if (count == -1 || count == 1) {
        deltaNumberOfBits[symbol] = (tableLog << 16) - tableSize;
        deltaFindState[symbol] = total - 1;
        total++;
      } else {
        final maxBitsOut = tableLog - _highestBit(count - 1);
        final minStatePlus = count << maxBitsOut;
        deltaNumberOfBits[symbol] = (maxBitsOut << 16) - minStatePlus;
        deltaFindState[symbol] = total - count;
        total += count;
      }
    }
  }

  int begin(int symbol) {
    final outputBits = (deltaNumberOfBits[symbol] + (1 << 15)) >> 16;
    final base = ((outputBits << 16) - deltaNumberOfBits[symbol]) >> outputBits;
    return nextState[base + deltaFindState[symbol]];
  }

  int encode(BitStreamWriter writer, int state, int symbol) {
    final outputBits = (state + deltaNumberOfBits[symbol]) >> 16;
    writer.writeBits(state, outputBits);
    return nextState[(state >> outputBits) + deltaFindState[symbol]];
  }

  void finish(BitStreamWriter writer, int state) {
    writer.writeBits(state, log2Size);
    writer.flush();
  }

  static int _spreadSymbols(
    List<int> normalizedCounts,
    int maxSymbol,
    int tableSize,
    int highThreshold,
    List<int> symbols,
  ) {
    final mask = tableSize - 1;
    final step = FiniteStateEntropyEncoder._calculateStep(tableSize);
    var position = 0;
    for (var symbol = 0; symbol <= maxSymbol; symbol++) {
      final count = normalizedCounts[symbol];
      if (count <= 0) {
        continue;
      }
      for (var i = 0; i < count; i++) {
        symbols[position] = symbol;
        do {
          position = (position + step) & mask;
        } while (position > highThreshold);
      }
    }
    return position;
  }
}

int _highestBit(int value) {
  if (value <= 0) {
    return 0;
  }
  return value.bitLength - 1;
}

int _minTableLog(int inputSize, int maxSymbolValue) {
  if (inputSize <= 1) {
    throw ArgumentError('Input too small');
  }
  final minBitsSrc = _highestBit(inputSize - 1) + 1;
  final minBitsSymbols = _highestBit(maxSymbolValue) + 2;
  return math.min(minBitsSrc, minBitsSymbols);
}
