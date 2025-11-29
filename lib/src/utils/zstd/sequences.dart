import 'dart:typed_data';

import 'bit_stream.dart';
import 'byte_reader.dart';
import 'frame_header.dart';
import 'fse.dart';
import 'window.dart';

/// Sequence header result
class SequencesHeader {
  SequencesHeader({
    required this.nbSeq,
    required this.llEncoding,
    required this.ofEncoding,
    required this.mlEncoding,
    required this.headerSize,
  });

  final int nbSeq;
  final SymbolEncodingDescriptor llEncoding;
  final SymbolEncodingDescriptor ofEncoding;
  final SymbolEncodingDescriptor mlEncoding;
  final int headerSize;
}

/// Symbol encoding type as per Zstd spec
enum SymbolEncodingType {
  predefined,  // 0 (set_basic)
  rle,         // 1 (set_rle)
  compressed,  // 2 (set_compressed)
  repeat,      // 3 (set_repeat)
}

class SymbolEncodingDescriptor {
  const SymbolEncodingDescriptor({
    required this.type,
    this.rleSymbol,
    this.fseTable,
  });

  final SymbolEncodingType type;
  final int? rleSymbol;
  final FseTableDescriptor? fseTable;

  bool get isRle => type == SymbolEncodingType.rle;
  bool get isPredefined => type == SymbolEncodingType.predefined;
  bool get isCompressed => type == SymbolEncodingType.compressed;
}

class SequenceDecodingTables {
  SequenceDecodingTables({
    required this.literalLengthTable,
    required this.offsetTable,
    required this.matchLengthTable,
  });

  final SequenceDecodingTable literalLengthTable;
  final SequenceDecodingTable offsetTable;
  final SequenceDecodingTable matchLengthTable;
}

class SequenceDecodingResult {
  SequenceDecodingResult({
    required this.sequences,
    required this.bytesConsumed,
    required this.finalPrevOffsets,
  });

  final List<Sequence> sequences;
  final int bytesConsumed;
  final List<int> finalPrevOffsets;
}

void executeSequences({
  required List<Sequence> sequences,
  required Uint8List literals,
  required ZstdWindow window,
  required List<int> outputBuffer,
}) {
  var litIndex = 0;
  for (final sequence in sequences) {
    final ll = sequence.litLength;
    final ml = sequence.matchLength;
    final offset = sequence.offset;

    if (litIndex + ll > literals.length) {
      throw ZstdFrameFormatException(
        'Literal count exceeds available bytes: need ${litIndex + ll}, have ${literals.length}',
      );
    }

    if (ll > 0) {
      window.appendSlice(literals, litIndex, ll, outputBuffer);
      litIndex += ll;
    }

    if (ml == 0) {
      continue;
    }
    if (offset <= 0) {
      throw ZstdFrameFormatException('Invalid match offset $offset');
    }
    window.copyMatch(offset, ml, outputBuffer);
  }

  if (litIndex < literals.length) {
    window.appendSlice(literals, litIndex, literals.length - litIndex, outputBuffer);
  } else if (litIndex > literals.length) {
    throw ZstdFrameFormatException('Literal pointer exceeded buffer (index $litIndex, size ${literals.length})');
  }
}

SequenceDecodingTables buildSequenceDecodingTables(SequencesHeader header) {
  return SequenceDecodingTables(
    literalLengthTable: _buildTableForDescriptor(header.llEncoding, _llComponent),
    offsetTable: _buildTableForDescriptor(header.ofEncoding, _ofComponent),
    matchLengthTable: _buildTableForDescriptor(header.mlEncoding, _mlComponent),
  );
}

SequenceDecodingResult decodeSequencesFromPayload({
  required SequencesHeader header,
  required Uint8List payload,
  List<int>? initialPrevOffsets,
}) {
  final tables = buildSequenceDecodingTables(header);
  final decoder = SequenceSectionDecoder(
    tables: tables,
    bitstream: payload,
    nbSequences: header.nbSeq,
    initialPrevOffsets: initialPrevOffsets,
  );
  final sequences = decoder.decodeAll();
  return SequenceDecodingResult(
    sequences: sequences,
    bytesConsumed: payload.length,
    finalPrevOffsets: decoder.finalPrevOffsets,
  );
}

SequenceDecodingResult decodeSequencesSection(
  ZstdByteReader reader,
  SequencesHeader header, {
  int? payloadSize,
  List<int>? initialPrevOffsets,
}) {
  final size = payloadSize ?? reader.remaining;
  if (size < 0 || size > reader.remaining) {
    throw ZstdFrameFormatException('Invalid sequences payload size $size (available ${reader.remaining})');
  }
  final payload = reader.readBytes(size);
  return decodeSequencesFromPayload(
    header: header,
    payload: payload,
    initialPrevOffsets: initialPrevOffsets,
  );
}

/// Parse the sequences section header.
/// Returns header info including number of sequences and encoding types.
/// Does NOT parse the FSE tables yet - that requires more infrastructure.
SequencesHeader parseSequencesHeader(ZstdByteReader reader) {
  final startOffset = reader.offset;

  // Number of sequences
  int nbSeq = reader.readUint8();
  if (nbSeq == 0) {
    return SequencesHeader(
      nbSeq: 0,
      llEncoding: const SymbolEncodingDescriptor(type: SymbolEncodingType.predefined),
      ofEncoding: const SymbolEncodingDescriptor(type: SymbolEncodingType.predefined),
      mlEncoding: const SymbolEncodingDescriptor(type: SymbolEncodingType.predefined),
      headerSize: reader.offset - startOffset,
    );
  }

  if (nbSeq > 0x7F) {
    if (nbSeq == 0xFF) {
      // LONGNBSEQ: next 2 bytes + 0x7F00
      final lo = reader.readUint8();
      final hi = reader.readUint8();
      nbSeq = (hi << 8) | lo;
      nbSeq += 0x7F00;
    } else {
      // 2-byte encoding: ((first - 0x80) << 8) + second
      final second = reader.readUint8();
      nbSeq = ((nbSeq - 0x80) << 8) + second;
    }
  }

  // Symbol compression modes byte
  final modesByte = reader.readUint8();
  final llType = SymbolEncodingType.values[(modesByte >> 6) & 3];
  final ofType = SymbolEncodingType.values[(modesByte >> 4) & 3];
  final mlType = SymbolEncodingType.values[(modesByte >> 2) & 3];

  final llEncoding = _parseSymbolEncodingDescriptor(reader, llType, maxSymbol: llBaseline.length - 1);
  final ofEncoding = _parseSymbolEncodingDescriptor(reader, ofType, maxSymbol: ofBaseline.length - 1);
  final mlEncoding = _parseSymbolEncodingDescriptor(reader, mlType, maxSymbol: mlBaseline.length - 1);

  return SequencesHeader(
    nbSeq: nbSeq,
    llEncoding: llEncoding,
    ofEncoding: ofEncoding,
    mlEncoding: mlEncoding,
    headerSize: reader.offset - startOffset,
  );
}

SymbolEncodingDescriptor _parseSymbolEncodingDescriptor(
  ZstdByteReader reader,
  SymbolEncodingType type, {
  required int maxSymbol,
}) {
  switch (type) {
    case SymbolEncodingType.predefined:
      return const SymbolEncodingDescriptor(type: SymbolEncodingType.predefined);
    case SymbolEncodingType.rle:
      if (reader.remaining < 1) {
        throw ZstdFrameFormatException('Unexpected end of input while reading RLE symbol');
      }
      final symbol = reader.readUint8();
      if (symbol > maxSymbol) {
        throw ZstdFrameFormatException('RLE symbol $symbol exceeds max symbol $maxSymbol');
      }
      return SymbolEncodingDescriptor(type: SymbolEncodingType.rle, rleSymbol: symbol);
    case SymbolEncodingType.compressed:
      final table = readFseTable(reader, maxSymbol);
      return SymbolEncodingDescriptor(type: SymbolEncodingType.compressed, fseTable: table);
    case SymbolEncodingType.repeat:
      throw UnimplementedError('Repeat symbol encoding is not supported yet');
  }
}

/// A single decoded sequence
class Sequence {
  const Sequence({
    required this.litLength,
    required this.matchLength,
    required this.offset,
  });

  final int litLength;
  final int matchLength;
  final int offset;
}

/// Baseline values for literal length codes
const List<int> llBaseline = [
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512,
  1024, 2048, 4096, 8192, 16384, 32768, 65536,
];

/// Extra bits for literal length codes
const List<int> llExtraBits = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12,
  13, 14, 15, 16,
];

const List<int> llDefaultNorm = [
  4, 3, 2, 2, 2, 2, 2, 2,
  2, 2, 2, 2, 2, 1, 1, 1,
  2, 2, 2, 2, 2, 2, 2, 2,
  2, 3, 2, 1, 1, 1, 1, 1,
 -1,-1,-1,-1,
];

const int llDefaultNormLog = 6;

/// Baseline values for match length codes  
const List<int> mlBaseline = [
  3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
  19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
  33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131,
  259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539,
];

/// Extra bits for match length codes
const List<int> mlExtraBits = [
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11,
  12, 13, 14, 15, 16,
];

const List<int> mlDefaultNorm = [
  1, 4, 3, 2, 2, 2, 2, 2,
  2, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1,-1,-1,
 -1,-1,-1,-1,-1,
];

const int mlDefaultNormLog = 6;

/// Baseline values for offset codes (see zstd_internal.h)
const List<int> ofBaseline = [
  0, 1, 1, 5, 13, 29, 61, 125,
  253, 509, 1021, 2045, 4093, 8189, 16381, 32765,
  65533, 131069, 262141, 524285, 1048573, 2097149, 4194301, 8388605,
  16777213, 33554429, 67108861, 134217725, 268435453, 536870909, 1073741821, 2147483645,
];

/// Extra bits for offset codes
const List<int> ofExtraBits = [
  0, 1, 2, 3, 4, 5, 6, 7,
  8, 9, 10, 11, 12, 13, 14, 15,
  16, 17, 18, 19, 20, 21, 22, 23,
  24, 25, 26, 27, 28, 29, 30, 31,
];

const List<int> ofDefaultNorm = [
  1, 1, 1, 1, 1, 1, 2, 2,
  2, 1, 1, 1, 1, 1, 1, 1,
  1, 1, 1, 1, 1, 1, 1, 1,
 -1,-1,-1,-1,-1,
];

const int ofDefaultNormLog = 5;

class _SequenceComponent {
  const _SequenceComponent({
    required this.baseValues,
    required this.extraBits,
    required this.defaultNorm,
    required this.defaultNormLog,
  });

  final List<int> baseValues;
  final List<int> extraBits;
  final List<int> defaultNorm;
  final int defaultNormLog;

  int get defaultMaxSymbol => defaultNorm.length - 1;
}

const _SequenceComponent _llComponent = _SequenceComponent(
  baseValues: llBaseline,
  extraBits: llExtraBits,
  defaultNorm: llDefaultNorm,
  defaultNormLog: llDefaultNormLog,
);

const _SequenceComponent _mlComponent = _SequenceComponent(
  baseValues: mlBaseline,
  extraBits: mlExtraBits,
  defaultNorm: mlDefaultNorm,
  defaultNormLog: mlDefaultNormLog,
);

const _SequenceComponent _ofComponent = _SequenceComponent(
  baseValues: ofBaseline,
  extraBits: ofExtraBits,
  defaultNorm: ofDefaultNorm,
  defaultNormLog: ofDefaultNormLog,
);

late final SequenceDecodingTable _llDefaultTable = _buildDefaultSequenceTable(_llComponent);
late final SequenceDecodingTable _mlDefaultTable = _buildDefaultSequenceTable(_mlComponent);
late final SequenceDecodingTable _ofDefaultTable = _buildDefaultSequenceTable(_ofComponent);

SequenceDecodingTable _buildTableForDescriptor(
  SymbolEncodingDescriptor descriptor,
  _SequenceComponent component,
) {
  switch (descriptor.type) {
    case SymbolEncodingType.predefined:
      return _defaultTableForComponent(component);
    case SymbolEncodingType.compressed:
      final table = descriptor.fseTable;
      if (table == null) {
        throw ZstdFrameFormatException('Missing FSE table for compressed descriptor');
      }
      return buildSequenceDecodingTable(
        descriptor: table,
        baseValues: component.baseValues,
        extraBits: component.extraBits,
      );
    case SymbolEncodingType.rle:
      final symbol = descriptor.rleSymbol;
      if (symbol == null) {
        throw ZstdFrameFormatException('Missing symbol for RLE descriptor');
      }
      return _buildRleSequenceTable(symbol, component);
    case SymbolEncodingType.repeat:
      throw UnimplementedError('Repeat symbol encoding is not supported yet');
  }
}

SequenceDecodingTable _defaultTableForComponent(_SequenceComponent component) {
  if (identical(component, _llComponent)) return _llDefaultTable;
  if (identical(component, _mlComponent)) return _mlDefaultTable;
  if (identical(component, _ofComponent)) return _ofDefaultTable;
  return _buildDefaultSequenceTable(component);
}

SequenceDecodingTable _buildDefaultSequenceTable(_SequenceComponent component) {
  return buildSequenceDecodingTable(
    descriptor: FseTableDescriptor(
      tableLog: component.defaultNormLog,
      normalizedCounts: component.defaultNorm,
      maxSymbol: component.defaultMaxSymbol,
      maxSymbolUsed: component.defaultMaxSymbol,
    ),
    baseValues: component.baseValues,
    extraBits: component.extraBits,
  );
}

SequenceDecodingTable _buildRleSequenceTable(int symbol, _SequenceComponent component) {
  if (symbol < 0 || symbol >= component.baseValues.length) {
    throw ZstdFrameFormatException('RLE symbol $symbol exceeds max symbol ${component.baseValues.length - 1}');
  }
  final entry = SequenceDecodingEntry(
    symbol: symbol,
    baseValue: component.baseValues[symbol],
    nbAdditionalBits: component.extraBits[symbol],
    nbBits: 0,
    nextState: 0,
  );
  return SequenceDecodingTable(entries: List<SequenceDecodingEntry>.unmodifiable([entry]), tableLog: 0);
}

/// Stateful decoder for the Sequences section (mirrors Zstd reference and
/// https://github.com/oleg-st/ZstdSharp / https://github.com/klauspost/compress implementations).
class SequenceSectionDecoder {
  SequenceSectionDecoder({
    required this.tables,
    required Uint8List bitstream,
    required this.nbSequences,
    List<int>? initialPrevOffsets,
  })  : _bitstream = bitstream,
        _prevOffsets = List<int>.from(initialPrevOffsets ?? const [1, 4, 8]),
        _bitReloadThreshold = _computeReloadThreshold(tables) {
    if (_prevOffsets.length < 3) {
      throw ArgumentError('initialPrevOffsets must have at least 3 entries');
    }
    if (nbSequences < 0) {
      throw ArgumentError.value(nbSequences, 'nbSequences', 'must be non-negative');
    }
    if (nbSequences == 0) {
      return;
    }
    if (_bitstream.isEmpty) {
      throw ZstdFrameFormatException('Invalid sequence bitstream (empty)');
    }
    final initializer = BitStreamInitializer(_bitstream, 0, _bitstream.length);
    initializer.initialize();
    _bitContainer = initializer.bits;
    _bitsConsumed = initializer.bitsConsumed;
    _currentAddress = initializer.current;

    _llState = _SequenceFseState(
      tables.literalLengthTable,
      _readBits(tables.literalLengthTable.tableLog),
    );
    _ofState = _SequenceFseState(
      tables.offsetTable,
      _readBits(tables.offsetTable.tableLog),
    );
    _mlState = _SequenceFseState(
      tables.matchLengthTable,
      _readBits(tables.matchLengthTable.tableLog),
    );
  }

  final SequenceDecodingTables tables;
  final int nbSequences;
  final Uint8List _bitstream;
  final List<int> _prevOffsets;
  final int _bitReloadThreshold;
  late int _bitContainer;
  late int _bitsConsumed;
  late int _currentAddress;
  bool _bitstreamEnded = false;
  late final _SequenceFseState _llState;
  late final _SequenceFseState _ofState;
  late final _SequenceFseState _mlState;

  List<int> get finalPrevOffsets => List<int>.unmodifiable(_prevOffsets);

  List<Sequence> decodeAll() {
    if (nbSequences == 0) return const [];
    // TODO mudar este codigo para usar um for em vez de List<Sequence>.generate(nbSequences, (index) para o compilador otimizar isso

    final result = List<Sequence>.generate(nbSequences, (index) {
      final isLast = index == nbSequences - 1;
      return _decodeSingle(isLast);
    }, growable: false);
    return result;
  }

  Sequence _decodeSingle(bool isLast) {
    _reloadBitStream(allowOverflow: isLast);

    final llEntry = _llState.currentEntry;
    final mlEntry = _mlState.currentEntry;
    final ofEntry = _ofState.currentEntry;

    final bool llBaseIsZero = llEntry.baseValue == 0;

    final _DecodedValue offsetResult = _readOffset(ofEntry, llBaseIsZero);
    final _DecodedValue matchResult = _readValue(mlEntry);
    final _DecodedValue literalResult = _readValue(llEntry);

    final int totalExtraBits = offsetResult.bitsUsed + matchResult.bitsUsed + literalResult.bitsUsed;
    if (totalExtraBits > _bitReloadThreshold) {
      _reloadBitStream(allowOverflow: isLast);
    }

    if (!isLast) {
      _llState.update(_readBits);
      _mlState.update(_readBits);
      _ofState.update(_readBits);
    }

    return Sequence(
      litLength: literalResult.value,
      matchLength: matchResult.value,
      offset: offsetResult.value,
    );
  }

  _DecodedValue _readValue(SequenceDecodingEntry entry) {
    var value = entry.baseValue;
    final extra = entry.nbAdditionalBits;
    if (extra > 0) {
      value += _readBits(extra);
    }
    return _DecodedValue(value: value, bitsUsed: extra);
  }

  _DecodedValue _readOffset(SequenceDecodingEntry entry, bool llBaseIsZero) {
    var offset = entry.baseValue;
    final extraBits = entry.nbAdditionalBits;
    if (extraBits > 0) {
      offset += _readBits(extraBits);
    }

    if (extraBits > 1) {
      _rotatePrevOffsets(offset);
      return _DecodedValue(value: offset, bitsUsed: extraBits);
    }

    if (extraBits == 0) {
      if (!llBaseIsZero) {
        return _DecodedValue(value: _prevOffsets[0], bitsUsed: 0);
      }
      final value = _prevOffsets[1];
      _prevOffsets[1] = _prevOffsets[0];
      _prevOffsets[0] = value;
      return _DecodedValue(value: value, bitsUsed: 0);
    }

    // extraBits == 1 path (repeat offsets with modifier)
    var updatedOffset = offset + (llBaseIsZero ? 1 : 0);
    // We already consumed one extra bit above.
    final temp = updatedOffset == 3 ? _prevOffsets[0] - 1 : _prevOffsets[updatedOffset];
    final safeTemp = temp == 0 ? 1 : temp;
    if (updatedOffset != 1) {
      _prevOffsets[2] = _prevOffsets[1];
    }
    _prevOffsets[1] = _prevOffsets[0];
    _prevOffsets[0] = safeTemp;
    return _DecodedValue(value: safeTemp, bitsUsed: extraBits);
  }

  void _rotatePrevOffsets(int newOffset) {
    _prevOffsets[2] = _prevOffsets[1];
    _prevOffsets[1] = _prevOffsets[0];
    _prevOffsets[0] = newOffset;
  }

  void _reloadBitStream({required bool allowOverflow}) {
    if (_bitstreamEnded) {
      if (!allowOverflow) {
        throw ZstdFrameFormatException('Sequence bitstream exhausted before decoding all sequences');
      }
      return;
    }
    final loader = BitStreamLoader(
      buffer: _bitstream,
      start: 0,
      current: _currentAddress,
      bits: _bitContainer,
      bitsConsumed: _bitsConsumed,
    );
    loader.load();
    // DEBUG
    // ignore: avoid_print
    print('reload allowOverflow=$allowOverflow current=${loader.current} bitsConsumed=${loader.bitsConsumed} overflow=${loader.overflow}');
    _bitContainer = loader.bits;
    _bitsConsumed = loader.bitsConsumed;
    _currentAddress = loader.current;
    if (loader.overflow) {
      _bitstreamEnded = true;
      if (!allowOverflow) {
        throw ZstdFrameFormatException('Sequence bitstream ended prematurely');
      }
    }
  }

  int _readBits(int count) {
    if (count <= 0) {
      return 0;
    }
    int reloadGuard = 0;
    while (_bitsConsumed + count > bitContainerBits) {
      if (reloadGuard++ > 1024) {
        throw ZstdFrameFormatException('Exceeded bitstream reload attempts while reading sequences');
      }
      _reloadBitStream(allowOverflow: false);
    }
    final value = peekBits(_bitsConsumed, _bitContainer, count);
    _bitsConsumed += count;
    return value;
  }
}

int _computeReloadThreshold(SequenceDecodingTables tables) {
  final sumLogs = tables.literalLengthTable.tableLog +
      tables.matchLengthTable.tableLog +
      tables.offsetTable.tableLog;
  final threshold = bitContainerBits - 7 - sumLogs;
  return threshold < 0 ? 0 : threshold;
}

class _DecodedValue {
  const _DecodedValue({required this.value, required this.bitsUsed});

  final int value;
  final int bitsUsed;
}

class _SequenceFseState {
  _SequenceFseState(this.table, int initialState) : _state = initialState {
    if (_state < 0 || _state >= table.entries.length) {
      throw ZstdFrameFormatException('Invalid initial FSE state $_state');
    }
  }

  final SequenceDecodingTable table;
  int _state;

  SequenceDecodingEntry get currentEntry => table.entries[_state];

  void update(int Function(int) readBits) {
    final entry = table.entries[_state];
    final lowBits = entry.nbBits > 0 ? readBits(entry.nbBits) : 0;
    final nextState = entry.nextState + lowBits;
    if (nextState < 0 || nextState >= table.entries.length) {
      throw ZstdFrameFormatException('Invalid FSE transition to $nextState');
    }
    _state = nextState;
  }
}
