import 'dart:typed_data';

import 'block.dart';
import 'constants.dart';
import 'dictionary.dart';
import 'encoder_match_finder.dart';
import 'fse.dart';
import 'huffman_encoder.dart';
import 'literals.dart';
import 'sequences.dart';
import 'xxhash64.dart';

typedef ZstdMatchPlanCallback = void Function(ZstdMatchPlan plan);
typedef ZstdEncoderBlockCallback = void Function(ZstdEncoderBlockStats stats);

class ZstdEncoderBlockStats {
  ZstdEncoderBlockStats({
    required this.blockType,
    required this.literalBytes,
    required this.sequenceCount,
    required this.usedRepeatOffsets,
  });

  final ZstdBlockType blockType;
  final int literalBytes;
  final int sequenceCount;
  final bool usedRepeatOffsets;
}

class ZstdEncodingError implements Exception {
  ZstdEncodingError(this.message);
  final String message;
  @override
  String toString() => 'ZstdEncodingError: $message';
}

/// Encodes [input] into a single-segment Zstandard frame composed of raw blocks.
///
/// This implementation does not attempt to reduce the size of the payload yet;
/// it merely wraps the provided bytes into a valid frame so existing decoders
/// (including the Dart port) can round-trip the data. The encoder splits the
/// payload into chunks that respect the Zstd maximum block size and can
/// optionally append the 32-bit content checksum emitted by standard encoders.
Uint8List zstdCompress(
  Uint8List input, {
  bool includeChecksum = false,
  bool enableMatchPlanner = true,
  ZstdDictionary? dictionary,
  ZstdMatchPlanCallback? onMatchPlan,
  ZstdEncoderBlockCallback? onBlockEncoded,
}) {
  final builder = BytesBuilder(copy: false);
  builder.add(_zstdMagicBytes);

  final contentSize = input.length;
  final headerBytes = _buildFrameHeader(
    contentSize: contentSize,
    includeChecksum: includeChecksum,
    dictionary: dictionary,
  );
  builder.add(headerBytes);

  final huffmanContext = HuffmanCompressionContext();
  final sequenceContext = SequenceCompressionContext();
  final encoderState = ZstdEncoderState();
  if (dictionary != null) {
    encoderState.seedPrevOffsets(dictionary.initialPrevOffsets);
    final codeLengths = dictionary.huffmanCodeLengths;
    final maxSymbol = dictionary.huffmanMaxSymbol;
    if (codeLengths != null && maxSymbol != null) {
      huffmanContext.seedFromDictionary(codeLengths, maxSymbol);
    }
    final tables = dictionary.sequenceTables;
    if (tables != null) {
      sequenceContext.seedFromDictionary(tables);
    }
  }
  final dictionaryHistory = _selectDictionaryHistory(dictionary);
  final matchHistory =
      dictionaryHistory == null ? <int>[] : List<int>.from(dictionaryHistory);
  final blockSizeLimit = contentSize < zstdBlockSizeMax ? contentSize : zstdBlockSizeMax;
  var offset = 0;
  if (contentSize == 0) {
    _encodeRawBlock(builder, Uint8List(0), isLastBlock: true);
    _emitBlockStats(
      onBlockEncoded,
      type: ZstdBlockType.raw,
      literalBytes: 0,
      sequenceCount: 0,
    );
  } else {
    while (offset < contentSize) {
      final runLength = _countRunLength(input, offset, zstdBlockSizeMax);
      if (runLength >= _minRleRunLength) {
        final isLast = offset + runLength == contentSize;
        final runSlice = Uint8List.sublistView(input, offset, offset + runLength);
        _encodeRleBlock(
          builder,
          input[offset],
          runLength,
          isLastBlock: isLast,
        );
        _emitBlockStats(
          onBlockEncoded,
          type: ZstdBlockType.rle,
          literalBytes: runLength,
          sequenceCount: 0,
        );
        _appendMatchHistory(matchHistory, runSlice);
        offset += runLength;
        continue;
      }

      final remaining = contentSize - offset;
      var chunkSize = remaining > blockSizeLimit && blockSizeLimit > 0 ? blockSizeLimit : remaining;
      if (chunkSize <= 0) {
        chunkSize = remaining;
      }
      final chunk = Uint8List.sublistView(input, offset, offset + chunkSize);
      final isLast = offset + chunkSize == contentSize;

      if (enableMatchPlanner && chunk.length >= _plannerMinBytes) {
        Uint8List? historySlice;
        if (matchHistory.isNotEmpty) {
          historySlice = Uint8List.fromList(matchHistory);
        }
        final plan = planMatches(chunk, history: historySlice);
        if (plan.hasMatches) {
          onMatchPlan?.call(plan);
          final planned = _encodePlannedBlock(
            builder,
            chunk,
            plan,
            blockSizeLimit: blockSizeLimit,
            isLastBlock: isLast,
            huffmanContext: huffmanContext,
            sequenceContext: sequenceContext,
            encoderState: encoderState,
          );
          if (planned != null) {
            _emitBlockStats(
              onBlockEncoded,
              type: ZstdBlockType.compressed,
              literalBytes: chunk.length,
              sequenceCount: planned.sequenceCount,
              usedRepeatOffsets: planned.usedRepeatOffsets,
            );
            _appendMatchHistory(matchHistory, chunk);
            offset += chunkSize;
            continue;
          }
        }
      }

      if (_canUseLiteralOnlyBlock(chunk.length, blockSizeLimit)) {
        _encodeLiteralOnlyBlock(
          builder,
          chunk,
          isLastBlock: isLast,
          huffmanContext: huffmanContext,
        );
        _emitBlockStats(
          onBlockEncoded,
          type: ZstdBlockType.compressed,
          literalBytes: chunk.length,
          sequenceCount: 0,
        );
      } else {
        _encodeRawBlock(builder, chunk, isLastBlock: isLast);
        _emitBlockStats(
          onBlockEncoded,
          type: ZstdBlockType.raw,
          literalBytes: chunk.length,
          sequenceCount: 0,
        );
      }
      _appendMatchHistory(matchHistory, chunk);
      offset += chunkSize;
    }
  }

  if (includeChecksum) {
    final checksum = xxHash64(input).toUnsigned(32).toInt();
    builder.add(Uint8List(4)
      ..buffer.asByteData().setUint32(0, checksum, Endian.little));
  }

  return builder.takeBytes();
}

_PlannedBlockResult? _encodePlannedBlock(
  BytesBuilder builder,
  Uint8List chunk,
  ZstdMatchPlan plan, {
  required int blockSizeLimit,
  required bool isLastBlock,
  required HuffmanCompressionContext huffmanContext,
  required SequenceCompressionContext sequenceContext,
  required ZstdEncoderState encoderState,
}) {
  if (!plan.hasMatches || plan.sequences.isEmpty) {
    return null;
  }

  try {
    final literals = plan.literalBytes;
    final literalSection = _encodeLiteralSection(literals, huffmanContext);
    final sequencesResult = _encodePlannerSequences(
      plan.sequences,
      literals.length,
      encoderState.prevOffsets,
    );
    final sequencesPayload = _buildSequencesSection(
      sequencesResult,
      sequenceContext,
    );
    final payloadSize = literalSection.bytes.length + sequencesPayload.length;
    final limit = blockSizeLimit > 0 ? blockSizeLimit : zstdBlockSizeMax;
    if (payloadSize > limit || payloadSize > zstdBlockSizeMax) {
      return null;
    }

    final headerValue =
        (payloadSize << 3) | (ZstdBlockType.compressed.index << 1) | (isLastBlock ? 1 : 0);
    builder.add([
      headerValue & 0xFF,
      (headerValue >> 8) & 0xFF,
      (headerValue >> 16) & 0xFF,
    ]);
    builder.add(literalSection.bytes);
    builder.add(sequencesPayload);
    encoderState.updatePrevOffsets(sequencesResult.finalPrevOffsets);
    return _PlannedBlockResult(
      sequenceCount: sequencesResult.sequences.length,
      usedRepeatOffsets: sequencesResult.usedRepeatOffsets,
    );
  } on ZstdEncodingError {
    return null;
  }
}

const int _plannerMinBytes = 32;

final Uint8List _zstdMagicBytes = Uint8List.fromList([
  zstdMagicNumber & 0xFF,
  (zstdMagicNumber >> 8) & 0xFF,
  (zstdMagicNumber >> 16) & 0xFF,
  (zstdMagicNumber >> 24) & 0xFF,
]);

Uint8List? _selectDictionaryHistory(ZstdDictionary? dictionary) {
  if (dictionary == null) {
    return null;
  }
  final content = dictionary.content;
  if (content.isEmpty) {
    return null;
  }
  if (content.length <= zstdMatchWindowBytes) {
    return content;
  }
  final start = content.length - zstdMatchWindowBytes;
  return Uint8List.sublistView(content, start, content.length);
}

Uint8List _buildFrameHeader({
  required int contentSize,
  required bool includeChecksum,
  ZstdDictionary? dictionary,
}) {
  if (contentSize < 0) {
    throw ZstdEncodingError('Content size cannot be negative');
  }
  final fcsId = _selectFrameContentSizeId(contentSize);
  final dictId = dictionary?.dictId ?? 0;
  final dictIdFlag = _selectDictIdFlag(dictId);
  final descriptor = _buildFrameDescriptor(
    fcsId: fcsId,
    includeChecksum: includeChecksum,
    dictIdFlag: dictIdFlag,
  );

  final builder = BytesBuilder(copy: false)..add([descriptor]);
  if (dictIdFlag != 0) {
    builder.add(_encodeDictId(dictId, dictIdFlag));
  }
  builder.add(_encodeFrameContentSize(contentSize));
  return builder.takeBytes();
}

int _buildFrameDescriptor({
  required int fcsId,
  required bool includeChecksum,
  required int dictIdFlag,
}) {
  if (fcsId < 0 || fcsId > 3) {
    throw ZstdEncodingError('Invalid frame content size flag: $fcsId');
  }
  if (dictIdFlag < 0 || dictIdFlag > 3) {
    throw ZstdEncodingError('Invalid dictionary id flag: $dictIdFlag');
  }
  var descriptor = (fcsId << 6) | 0x20; // single segment
  if (includeChecksum) {
    descriptor |= 0x04;
  }
  descriptor |= dictIdFlag;
  return descriptor;
}

int _selectDictIdFlag(int dictId) {
  if (dictId == 0) {
    return 0;
  }
  if (dictId <= 0xFF) {
    return 1;
  }
  if (dictId <= 0xFFFF) {
    return 2;
  }
  if (dictId <= 0xFFFFFFFF) {
    return 3;
  }
  throw ZstdEncodingError('Dictionary id $dictId exceeds 32-bit range');
}

Uint8List _encodeDictId(int dictId, int dictIdFlag) {
  switch (dictIdFlag) {
    case 0:
      return _emptyUint8List;
    case 1:
      return Uint8List.fromList([dictId & 0xFF]);
    case 2:
      return Uint8List.fromList([
        dictId & 0xFF,
        (dictId >> 8) & 0xFF,
      ]);
    case 3:
      return Uint8List.fromList([
        dictId & 0xFF,
        (dictId >> 8) & 0xFF,
        (dictId >> 16) & 0xFF,
        (dictId >> 24) & 0xFF,
      ]);
    default:
      throw ZstdEncodingError('Unsupported dictionary flag: $dictIdFlag');
  }
}

int _selectFrameContentSizeId(int contentSize) {
  if (contentSize <= 0xFF) {
    return 0;
  }
  if (contentSize <= (0xFFFF + 256)) {
    return 1;
  }
  if (contentSize <= 0xFFFFFFFF) {
    return 2;
  }
  return 3;
}

List<int> _encodeFrameContentSize(int contentSize) {
  final fcsId = _selectFrameContentSizeId(contentSize);
  switch (fcsId) {
    case 0:
      return [contentSize & 0xFF];
    case 1:
      final adjusted = contentSize - 256;
      if (adjusted < 0 || adjusted > 0xFFFF) {
        throw ZstdEncodingError('Frame size is invalid for fcsId=1');
      }
      return [adjusted & 0xFF, (adjusted >> 8) & 0xFF];
    case 2:
      return [
        contentSize & 0xFF,
        (contentSize >> 8) & 0xFF,
        (contentSize >> 16) & 0xFF,
        (contentSize >> 24) & 0xFF,
      ];
    case 3:
      final bytes = <int>[];
      var value = contentSize;
      for (var i = 0; i < 8; i++) {
        bytes.add(value & 0xFF);
        value = value >> 8;
      }
      return bytes;
    default:
      throw ZstdEncodingError('Unsupported frame content size flag: $fcsId');
  }
}

void _encodeRawBlock(BytesBuilder builder, Uint8List chunk, {required bool isLastBlock}) {
  if (chunk.length > zstdBlockSizeMax) {
    throw ZstdEncodingError('Chunk size ${chunk.length} exceeds block limit $zstdBlockSizeMax');
  }
  final headerValue = (chunk.length << 3) | (isLastBlock ? 1 : 0);
  builder.add([
    headerValue & 0xFF,
    (headerValue >> 8) & 0xFF,
    (headerValue >> 16) & 0xFF,
  ]);
  if (chunk.isNotEmpty) {
    builder.add(chunk);
  }
}

void _encodeRleBlock(BytesBuilder builder, int value, int literalCount, {required bool isLastBlock}) {
  if (literalCount <= 0 || literalCount > zstdBlockSizeMax) {
    throw ZstdEncodingError('Invalid RLE literal count $literalCount');
  }
  final headerValue =
      (literalCount << 3) | (ZstdBlockType.rle.index << 1) | (isLastBlock ? 1 : 0);
  builder.add([
    headerValue & 0xFF,
    (headerValue >> 8) & 0xFF,
    (headerValue >> 16) & 0xFF,
  ]);
  builder.add([value & 0xFF]);
}

const int _minRleRunLength = 2;

int _countRunLength(Uint8List input, int start, int maxLength) {
  if (start >= input.length) {
    return 0;
  }
  final byte = input[start];
  var length = 1;
  final limit = start + maxLength;
  while (start + length < input.length && start + length < limit) {
    if (input[start + length] != byte) {
      break;
    }
    length += 1;
  }
  return length;
}

bool _canUseLiteralOnlyBlock(int literalCount, int blockSizeLimit) {
  if (blockSizeLimit <= 0) {
    return false;
  }
  final headerLength = _literalHeaderLength(literalCount);
  final payloadSize = headerLength + literalCount + _sequencesZeroHeaderSize;
  return payloadSize <= blockSizeLimit;
}

void _encodeLiteralOnlyBlock(
  BytesBuilder builder,
  Uint8List chunk, {
  required bool isLastBlock,
  required HuffmanCompressionContext huffmanContext,
}) {
  final literalSection = _encodeLiteralSection(chunk, huffmanContext);
  final payloadSize = literalSection.bytes.length + _sequencesZeroHeaderSize;
  if (payloadSize > zstdBlockSizeMax) {
    throw ZstdEncodingError('Literal block payload exceeds block limit: $payloadSize');
  }
  final headerValue =
      (payloadSize << 3) | (ZstdBlockType.compressed.index << 1) | (isLastBlock ? 1 : 0);
  builder.add([
    headerValue & 0xFF,
    (headerValue >> 8) & 0xFF,
    (headerValue >> 16) & 0xFF,
  ]);
  builder.add(literalSection.bytes);
  builder.add(const [0x00]);
}

const int _sequencesZeroHeaderSize = 1;

int _literalHeaderLength(int literalCount) {
  if (literalCount <= 0x1F) {
    return 1;
  }
  if (literalCount <= 0x0FFF) {
    return 2;
  }
  return 3;
}

class _LiteralSectionEncoding {
  _LiteralSectionEncoding({
    required this.bytes,
    required this.type,
    required this.regeneratedSize,
  });

  final Uint8List bytes;
  final LiteralsBlockType type;
  final int regeneratedSize;
}

_LiteralSectionEncoding _encodeLiteralSection(
  Uint8List literals,
  HuffmanCompressionContext context,
) {
  final compressed = tryEncodeLiterals(literals, context);
  if (compressed != null) {
    return _LiteralSectionEncoding(
      bytes: compressed.bytes,
      type: compressed.type,
      regeneratedSize: compressed.regeneratedSize,
    );
  }
  return _buildRawLiteralSection(literals);
}

_LiteralSectionEncoding _buildRawLiteralSection(Uint8List literals) {
  final header = _encodeRawLiteralHeader(literals.length);
  final builder = BytesBuilder(copy: false)..add(header);
  if (literals.isNotEmpty) {
    builder.add(literals);
  }
  return _LiteralSectionEncoding(
    bytes: builder.takeBytes(),
    type: LiteralsBlockType.raw,
    regeneratedSize: literals.length,
  );
}

Uint8List _encodeRawLiteralHeader(int literalCount) {
  if (literalCount < 0) {
    throw ZstdEncodingError('Literal count cannot be negative');
  }
  final sizeFormat = switch (_literalHeaderLength(literalCount)) {
    1 => 0,
    2 => 1,
    3 => 3,
    _ => throw StateError('Unsupported literal header length'),
  };
  final length = _literalHeaderLength(literalCount);
  final shift = length == 1 ? 3 : 4;
  final headerValue = (literalCount << shift) | (sizeFormat << 2) | LiteralsBlockType.raw.index;
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = (headerValue >> (8 * i)) & 0xFF;
  }
  return bytes;
}

Uint8List _buildSequencesSection(
  _EncodedSequencesResult encoded,
  SequenceCompressionContext context,
) {
  final sequences = encoded.sequences;
  if (sequences.isEmpty) {
    throw ZstdEncodingError('Sequence planner did not emit any matches');
  }

  final literalCounts = List<int>.filled(llBaseline.length, 0);
  final matchCounts = List<int>.filled(mlBaseline.length, 0);
  final offsetCounts = List<int>.filled(ofBaseline.length, 0);
  for (final sequence in sequences) {
    literalCounts[sequence.literal.symbol]++;
    matchCounts[sequence.match.symbol]++;
    offsetCounts[sequence.offset.symbol]++;
  }

  final llPlan = _buildSymbolEncodingPlan(
    component: _literalEncodingComponent,
    counts: literalCounts,
    totalSequences: sequences.length,
    state: context.literalState,
  );
  final ofPlan = _buildSymbolEncodingPlan(
    component: _offsetEncodingComponent,
    counts: offsetCounts,
    totalSequences: sequences.length,
    state: context.offsetState,
  );
  final mlPlan = _buildSymbolEncodingPlan(
    component: _matchEncodingComponent,
    counts: matchCounts,
    totalSequences: sequences.length,
    state: context.matchState,
  );

  final bitstream = _encodeSequencesBitstream(
    sequences,
    llPlan.encoder,
    mlPlan.encoder,
    ofPlan.encoder,
  );

  final headerBytes = _encodeSequenceCountBytes(sequences.length);
  final modesByte = (llPlan.type.index << 6) |
      (ofPlan.type.index << 4) |
      (mlPlan.type.index << 2);

  final builder = BytesBuilder(copy: false)
    ..add(headerBytes)
    ..add([modesByte]);

  if (llPlan.headerBytes.isNotEmpty) {
    builder.add(llPlan.headerBytes);
  }
  if (ofPlan.headerBytes.isNotEmpty) {
    builder.add(ofPlan.headerBytes);
  }
  if (mlPlan.headerBytes.isNotEmpty) {
    builder.add(mlPlan.headerBytes);
  }

  builder.add(bitstream);
  return builder.takeBytes();
}

_EncodedSequencesResult _encodePlannerSequences(
  List<ZstdEncoderSequence> sequences,
  int literalBudget,
  List<int> initialPrevOffsets,
) {
  if (initialPrevOffsets.length < 3) {
    throw ZstdEncodingError('prevOffsets snapshot must have at least 3 entries');
  }
  var literalCursor = 0;
  final result = <_EncodedSequence>[];
  final prevOffsets = List<int>.from(initialPrevOffsets);
  var usedRepeatOffsets = false;
  for (final sequence in sequences) {
    if (sequence.literalLength < 0) {
      throw ZstdEncodingError('Sequence literal length cannot be negative');
    }
    if (sequence.matchLength < 3) {
      throw ZstdEncodingError('Match length ${sequence.matchLength} is too small');
    }
    if (sequence.offset <= 0 || sequence.offset > _maxWindowDistance) {
      throw ZstdEncodingError('Match offset ${sequence.offset} is out of range');
    }
    if (literalCursor + sequence.literalLength > literalBudget) {
      throw ZstdEncodingError(
        'Planner literal budget exceeded: need ${literalCursor + sequence.literalLength}, have $literalBudget',
      );
    }

    final literalComponent = _encodeSequenceComponent(
      value: sequence.literalLength,
      baselines: llBaseline,
      extraBitsTable: llExtraBits,
      label: 'literal length',
    );
    final matchComponent = _encodeSequenceComponent(
      value: sequence.matchLength,
      baselines: mlBaseline,
      extraBitsTable: mlExtraBits,
      label: 'match length',
    );
    final offsetComponent = _encodeOffsetComponent(
      offset: sequence.offset,
      prevOffsets: prevOffsets,
      literalBaseIsZero: literalComponent.baseValue == 0,
    );
    if (offsetComponent.isRepeatEncoding) {
      usedRepeatOffsets = true;
    }

    result.add(
      _EncodedSequence(
        literal: literalComponent,
        match: matchComponent,
        offset: offsetComponent,
      ),
    );

    literalCursor += sequence.literalLength;
  }

  if (literalCursor > literalBudget) {
    throw ZstdEncodingError('Planner literal cursor exceeded payload size');
  }

  return _EncodedSequencesResult(
    sequences: List<_EncodedSequence>.unmodifiable(result),
    usedRepeatOffsets: usedRepeatOffsets,
    finalPrevOffsets: List<int>.unmodifiable(prevOffsets),
  );
}

_EncodedSequenceComponent _encodeSequenceComponent({
  required int value,
  required List<int> baselines,
  required List<int> extraBitsTable,
  required String label,
}) {
  for (var symbol = 0; symbol < baselines.length; symbol++) {
    final base = baselines[symbol];
    final extraBits = extraBitsTable[symbol];
    final range = extraBits == 0 ? 1 : (1 << extraBits);
    final maxValue = base + range - 1;
    if (value >= base && value <= maxValue) {
      return _EncodedSequenceComponent(
        symbol: symbol,
        extraBits: extraBits,
        extraValue: value - base,
        baseValue: base,
        isRepeatEncoding: false,
      );
    }
  }
  throw ZstdEncodingError('Unable to encode $label value $value');
}

_EncodedSequenceComponent _encodeOffsetComponent({
  required int offset,
  required List<int> prevOffsets,
  required bool literalBaseIsZero,
}) {
  final repeat = _tryEncodeRepeatOffset(
    offset: offset,
    prevOffsets: prevOffsets,
    literalBaseIsZero: literalBaseIsZero,
  );
  if (repeat != null) {
    return repeat;
  }
  return _encodeNumericOffset(
    offset: offset,
    prevOffsets: prevOffsets,
  );
}

_EncodedSequenceComponent? _tryEncodeRepeatOffset({
  required int offset,
  required List<int> prevOffsets,
  required bool literalBaseIsZero,
}) {
  if (!literalBaseIsZero && offset == prevOffsets[0]) {
    return _repeatSymbolZeroComponent();
  }

  if (literalBaseIsZero && offset == prevOffsets[1]) {
    final value = prevOffsets[1];
    prevOffsets[1] = prevOffsets[0];
    prevOffsets[0] = value;
    return _repeatSymbolZeroComponent();
  }

  if (!literalBaseIsZero) {
    if (offset == prevOffsets[1]) {
      _applyRepeatOffsetUpdate(prevOffsets, updatedOffset: 1, newOffset: offset);
      return _repeatSymbolOneComponent(extraValue: 0);
    }
    if (offset == prevOffsets[2]) {
      _applyRepeatOffsetUpdate(prevOffsets, updatedOffset: 2, newOffset: offset);
      return _repeatSymbolOneComponent(extraValue: 1);
    }
  } else {
    if (offset == prevOffsets[2]) {
      _applyRepeatOffsetUpdate(prevOffsets, updatedOffset: 2, newOffset: offset);
      return _repeatSymbolOneComponent(extraValue: 0);
    }
    final candidate = prevOffsets[0] - 1;
    final safeCandidate = candidate <= 0 ? 1 : candidate;
    if (offset == safeCandidate) {
      _applyRepeatOffsetUpdate(prevOffsets, updatedOffset: 3, newOffset: safeCandidate);
      return _repeatSymbolOneComponent(extraValue: 1);
    }
  }

  return null;
}

_EncodedSequenceComponent _encodeNumericOffset({
  required int offset,
  required List<int> prevOffsets,
}) {
  for (var symbol = 0; symbol < ofBaseline.length; symbol++) {
    final extraBits = ofExtraBits[symbol];
    if (extraBits <= 1) {
      continue;
    }
    final base = ofBaseline[symbol];
    final range = 1 << extraBits;
    final maxValue = base + range - 1;
    if (offset >= base && offset <= maxValue) {
      _rotatePrevOffsetsList(prevOffsets, offset);
      return _EncodedSequenceComponent(
        symbol: symbol,
        extraBits: extraBits,
        extraValue: offset - base,
        baseValue: base,
        isRepeatEncoding: false,
      );
    }
  }
  throw ZstdEncodingError('Match offset $offset cannot be represented');
}

_EncodedSequenceComponent _repeatSymbolZeroComponent() {
  return const _EncodedSequenceComponent(
    symbol: 0,
    extraBits: 0,
    extraValue: 0,
    baseValue: 0,
    isRepeatEncoding: true,
  );
}

_EncodedSequenceComponent _repeatSymbolOneComponent({required int extraValue}) {
  return _EncodedSequenceComponent(
    symbol: 1,
    extraBits: 1,
    extraValue: extraValue,
    baseValue: ofBaseline[1],
    isRepeatEncoding: true,
  );
}

void _applyRepeatOffsetUpdate(
  List<int> prevOffsets, {
  required int updatedOffset,
  required int newOffset,
}) {
  if (updatedOffset != 1) {
    prevOffsets[2] = prevOffsets[1];
  }
  prevOffsets[1] = prevOffsets[0];
  prevOffsets[0] = newOffset;
}

void _rotatePrevOffsetsList(List<int> prevOffsets, int newOffset) {
  prevOffsets[2] = prevOffsets[1];
  prevOffsets[1] = prevOffsets[0];
  prevOffsets[0] = newOffset;
}

Uint8List _encodeSequencesBitstream(
  List<_EncodedSequence> sequences,
  _FseSymbolEncoder llEncoder,
  _FseSymbolEncoder mlEncoder,
  _FseSymbolEncoder ofEncoder,
) {
  if (sequences.isEmpty) {
    throw ZstdEncodingError('Cannot encode empty sequence list');
  }

  final writer = _BitStreamWriter();
  int? llNextState;
  int? mlNextState;
  int? ofNextState;

  for (var index = sequences.length - 1; index >= 0; index--) {
    final sequence = sequences[index];
    final llResult = llEncoder.encode(sequence.literal.symbol, nextState: llNextState);
    final mlResult = mlEncoder.encode(sequence.match.symbol, nextState: mlNextState);
    final ofResult = ofEncoder.encode(sequence.offset.symbol, nextState: ofNextState);

    final isLast = index == sequences.length - 1;
    if (!isLast) {
      writer.writeBits(ofResult.bits, ofResult.bitCount);
      writer.writeBits(mlResult.bits, mlResult.bitCount);
      writer.writeBits(llResult.bits, llResult.bitCount);
    }

    if (sequence.literal.extraBits > 0) {
      writer.writeBits(sequence.literal.extraValue, sequence.literal.extraBits);
    }
    if (sequence.match.extraBits > 0) {
      writer.writeBits(sequence.match.extraValue, sequence.match.extraBits);
    }
    if (sequence.offset.extraBits > 0) {
      writer.writeBits(sequence.offset.extraValue, sequence.offset.extraBits);
    }

    llNextState = llResult.previousState;
    mlNextState = mlResult.previousState;
    ofNextState = ofResult.previousState;
  }

  if (llNextState == null || mlNextState == null || ofNextState == null) {
    throw ZstdEncodingError('Failed to determine initial FSE states');
  }

  writer.writeBits(mlNextState, mlEncoder.tableLog);
  writer.writeBits(ofNextState, ofEncoder.tableLog);
  writer.writeBits(llNextState, llEncoder.tableLog);

  return writer.close();
}

List<int> _encodeSequenceCountBytes(int count) {
  if (count < 0) {
    throw ZstdEncodingError('Sequence count cannot be negative');
  }
  if (count == 0) {
    return const [0];
  }
  if (count < 0x80) {
    return [count];
  }
  if (count < 0x7F00) {
    final high = (count >> 8) + 0x80;
    final low = count & 0xFF;
    return [high, low];
  }
  final adjusted = count - 0x7F00;
  if (adjusted < 0 || adjusted > 0xFFFF) {
    throw ZstdEncodingError('Sequence count $count exceeds supported range');
  }
  return [0xFF, adjusted & 0xFF, (adjusted >> 8) & 0xFF];
}

class _EncodedSequence {
  const _EncodedSequence({
    required this.literal,
    required this.match,
    required this.offset,
  });

  final _EncodedSequenceComponent literal;
  final _EncodedSequenceComponent match;
  final _EncodedSequenceComponent offset;
}

class _EncodedSequencesResult {
  const _EncodedSequencesResult({
    required this.sequences,
    required this.usedRepeatOffsets,
    required this.finalPrevOffsets,
  });

  final List<_EncodedSequence> sequences;
  final bool usedRepeatOffsets;
  final List<int> finalPrevOffsets;
}

class ZstdEncoderState {
  ZstdEncoderState() : prevOffsets = List<int>.from(_defaultPrevOffsets);

  final List<int> prevOffsets;

  void resetPrevOffsets() {
    for (var i = 0; i < prevOffsets.length; i++) {
      prevOffsets[i] = _defaultPrevOffsets[i];
    }
  }

  void updatePrevOffsets(List<int> source) {
    if (source.length < 3) {
      throw ZstdEncodingError('Invalid prev offset snapshot: need 3 entries, got ${source.length}');
    }
    for (var i = 0; i < 3; i++) {
      prevOffsets[i] = source[i];
    }
  }

  void seedPrevOffsets(List<int> source) {
    updatePrevOffsets(source);
  }
}

class SequenceCompressionContext {
  SequenceCompressionContext()
      : literalState = _SequenceEncodingState('literal lengths'),
        offsetState = _SequenceEncodingState('offsets'),
        matchState = _SequenceEncodingState('match lengths');

  final _SequenceEncodingState literalState;
  final _SequenceEncodingState offsetState;
  final _SequenceEncodingState matchState;

  void seedFromDictionary(SequenceDecodingTables tables) {
    literalState.seedRepeat(tables.literalLengthTable);
    offsetState.seedRepeat(tables.offsetTable);
    matchState.seedRepeat(tables.matchLengthTable);
  }
}

class _SequenceEncodingState {
  _SequenceEncodingState(this.label);

  final String label;
  SequenceDecodingTable? _table;
  SymbolEncodingType? _type;
  int? _tableLog;
  List<int>? _normalizedCounts;
  int? _rleSymbol;
  bool _pendingSeedRepeat = false;

  bool canRepeatRle(int symbol) {
    return _type == SymbolEncodingType.rle && _table != null && _rleSymbol == symbol;
  }

  bool canRepeatCompressed(List<int> normalized, int tableLog) {
    if (_type != SymbolEncodingType.compressed || _table == null) {
      return false;
    }
    if (_tableLog != tableLog) {
      return false;
    }
    final previous = _normalizedCounts;
    if (previous == null || previous.length != normalized.length) {
      return false;
    }
    for (var i = 0; i < normalized.length; i++) {
      if (previous[i] != normalized[i]) {
        return false;
      }
    }
    return true;
  }

  void saveCompressed(SequenceDecodingTable table, List<int> normalized, int tableLog) {
    _table = table;
    _type = SymbolEncodingType.compressed;
    _tableLog = tableLog;
    _normalizedCounts = List<int>.from(normalized);
    _rleSymbol = null;
  }

  void saveRle(SequenceDecodingTable table, int symbol) {
    _table = table;
    _type = SymbolEncodingType.rle;
    _tableLog = 0;
    _normalizedCounts = null;
    _rleSymbol = symbol;
  }

  SequenceDecodingTable ensureTableAvailable() {
    final table = _table;
    if (table == null) {
      throw ZstdEncodingError('Sequence table for $label is not initialized');
    }
    return table;
  }

  void seedRepeat(SequenceDecodingTable table) {
    _table = table;
    _type = SymbolEncodingType.repeat;
    _tableLog = table.tableLog;
    _normalizedCounts = null;
    _rleSymbol = null;
    _pendingSeedRepeat = true;
  }

  bool consumeSeededRepeat() {
    if (_pendingSeedRepeat) {
      _pendingSeedRepeat = false;
      return true;
    }
    return false;
  }
}

class _PlannedBlockResult {
  const _PlannedBlockResult({
    required this.sequenceCount,
    required this.usedRepeatOffsets,
  });

  final int sequenceCount;
  final bool usedRepeatOffsets;
}

class _EncodedSequenceComponent {
  const _EncodedSequenceComponent({
    required this.symbol,
    required this.extraBits,
    required this.extraValue,
    required this.baseValue,
    required this.isRepeatEncoding,
  });

  final int symbol;
  final int extraBits;
  final int extraValue;
  final int baseValue;
  final bool isRepeatEncoding;
}

class _SequenceComponentConfig {
  _SequenceComponentConfig({
    required this.name,
    required this.baseValues,
    required this.extraBits,
    required this.maxTableLog,
    required this.defaultTable,
  });

  final String name;
  final List<int> baseValues;
  final List<int> extraBits;
  final int maxTableLog;
  final SequenceDecodingTable defaultTable;

  int get symbolLimit => baseValues.length;
  int get maxSymbol => baseValues.length - 1;
}

final _SequenceComponentConfig _literalEncodingComponent = _SequenceComponentConfig(
  name: 'literal lengths',
  baseValues: llBaseline,
  extraBits: llExtraBits,
  maxTableLog: llDefaultNormLog,
  defaultTable: defaultLiteralLengthDecodingTable,
);

final _SequenceComponentConfig _matchEncodingComponent = _SequenceComponentConfig(
  name: 'match lengths',
  baseValues: mlBaseline,
  extraBits: mlExtraBits,
  maxTableLog: mlDefaultNormLog,
  defaultTable: defaultMatchLengthDecodingTable,
);

final _SequenceComponentConfig _offsetEncodingComponent = _SequenceComponentConfig(
  name: 'offsets',
  baseValues: ofBaseline,
  extraBits: ofExtraBits,
  maxTableLog: ofDefaultNormLog,
  defaultTable: defaultOffsetDecodingTable,
);

class _SymbolEncodingPlan {
  const _SymbolEncodingPlan({
    required this.type,
    required this.encoder,
    required this.headerBytes,
  });

  final SymbolEncodingType type;
  final _FseSymbolEncoder encoder;
  final Uint8List headerBytes;

  factory _SymbolEncodingPlan.predefined(SequenceDecodingTable table) {
    return _SymbolEncodingPlan(
      type: SymbolEncodingType.predefined,
      encoder: _FseSymbolEncoder(table),
      headerBytes: _emptyUint8List,
    );
  }

  factory _SymbolEncodingPlan.repeat(SequenceDecodingTable table) {
    return _SymbolEncodingPlan(
      type: SymbolEncodingType.repeat,
      encoder: _FseSymbolEncoder(table),
      headerBytes: _emptyUint8List,
    );
  }

  factory _SymbolEncodingPlan.rle(SequenceDecodingTable table, int symbol) {
    return _SymbolEncodingPlan(
      type: SymbolEncodingType.rle,
      encoder: _FseSymbolEncoder(table),
      headerBytes: Uint8List.fromList([symbol & 0xFF]),
    );
  }

  factory _SymbolEncodingPlan.compressed(SequenceDecodingTable table, Uint8List headerBytes) {
    return _SymbolEncodingPlan(
      type: SymbolEncodingType.compressed,
      encoder: _FseSymbolEncoder(table),
      headerBytes: headerBytes,
    );
  }
}

_SymbolEncodingPlan _buildSymbolEncodingPlan({
  required _SequenceComponentConfig component,
  required List<int> counts,
  required int totalSequences,
  required _SequenceEncodingState state,
}) {
  if (totalSequences <= 0) {
    throw ZstdEncodingError('Cannot encode empty sequence set for ${component.name}');
  }

  if (state.consumeSeededRepeat()) {
    return _SymbolEncodingPlan.repeat(state.ensureTableAvailable());
  }

  final singleSymbol = _detectRleSymbol(counts, totalSequences);
  if (singleSymbol != null) {
    if (state.canRepeatRle(singleSymbol)) {
      return _SymbolEncodingPlan.repeat(state.ensureTableAvailable());
    }
    final table = _buildSequenceRleTable(singleSymbol, component);
    state.saveRle(table, singleSymbol);
    return _SymbolEncodingPlan.rle(table, singleSymbol);
  }

  final maxSymbolUsed = _findMaxSymbolUsed(counts);
  if (maxSymbolUsed < 0) {
    throw ZstdEncodingError('No symbols registered for ${component.name}');
  }

  final normalized = List<int>.filled(component.symbolLimit, 0);
  try {
    final tableLog = FiniteStateEntropyEncoder.optimalTableLog(
      component.maxTableLog,
      totalSequences,
      maxSymbolUsed,
    );
    FiniteStateEntropyEncoder.normalizeCounts(
      normalized,
      tableLog,
      counts,
      totalSequences,
      maxSymbolUsed,
    );

    if (state.canRepeatCompressed(normalized, tableLog)) {
      return _SymbolEncodingPlan.repeat(state.ensureTableAvailable());
    }

    final headerBytes = FiniteStateEntropyEncoder.writeNormalizedCounts(
      normalized,
      component.maxSymbol,
      tableLog,
    );
    final descriptor = FseTableDescriptor(
      tableLog: tableLog,
      normalizedCounts: normalized,
      maxSymbol: component.maxSymbol,
      maxSymbolUsed: maxSymbolUsed,
    );
    final table = buildSequenceDecodingTable(
      descriptor: descriptor,
      baseValues: component.baseValues,
      extraBits: component.extraBits,
    );
    state.saveCompressed(table, normalized, tableLog);
    return _SymbolEncodingPlan.compressed(table, headerBytes);
  } on StateError {
    return _buildPredefinedPlan(component);
  } on ArgumentError {
    return _buildPredefinedPlan(component);
  }
}

_SymbolEncodingPlan _buildPredefinedPlan(_SequenceComponentConfig component) {
  return _SymbolEncodingPlan.predefined(component.defaultTable);
}

SequenceDecodingTable _buildSequenceRleTable(int symbol, _SequenceComponentConfig component) {
  if (symbol < 0 || symbol >= component.symbolLimit) {
    throw ZstdEncodingError('RLE symbol $symbol is out of range for ${component.name}');
  }
  final entry = SequenceDecodingEntry(
    symbol: symbol,
    baseValue: component.baseValues[symbol],
    nbAdditionalBits: component.extraBits[symbol],
    nbBits: 0,
    nextState: 0,
  );
  return SequenceDecodingTable(
    entries: List<SequenceDecodingEntry>.unmodifiable([entry]),
    tableLog: 0,
  );
}

int _findMaxSymbolUsed(List<int> counts) {
  for (var index = counts.length - 1; index >= 0; index--) {
    if (counts[index] > 0) {
      return index;
    }
  }
  return -1;
}

int? _detectRleSymbol(List<int> counts, int totalSequences) {
  int symbol = -1;
  for (var index = 0; index < counts.length; index++) {
    final count = counts[index];
    if (count == 0) {
      continue;
    }
    if (symbol != -1) {
      return null;
    }
    symbol = index;
  }
  if (symbol == -1) {
    return null;
  }
  return counts[symbol] == totalSequences ? symbol : null;
}

final Uint8List _emptyUint8List = Uint8List(0);

class _FseSymbolEncoder {
  _FseSymbolEncoder(SequenceDecodingTable table)
      : tableLog = table.entries.length.bitLength - 1,
        _entriesBySymbol = _groupEntries(table);

  final int tableLog;
  final Map<int, List<_FseStateEntry>> _entriesBySymbol;

  _FseEncodingResult encode(int symbol, {int? nextState}) {
    final candidates = _entriesBySymbol[symbol];
    if (candidates == null || candidates.isEmpty) {
      throw ZstdEncodingError('Missing FSE entries for symbol $symbol');
    }
    if (nextState == null) {
      final entry = candidates.first;
      return _FseEncodingResult(bits: 0, bitCount: 0, previousState: entry.stateIndex);
    }
    for (final entry in candidates) {
      final range = 1 << entry.nbBits;
      final maxState = entry.nextStateBase + range;
      if (nextState >= entry.nextStateBase && nextState < maxState) {
        final bits = nextState - entry.nextStateBase;
        return _FseEncodingResult(
          bits: bits,
          bitCount: entry.nbBits,
          previousState: entry.stateIndex,
        );
      }
    }
    throw ZstdEncodingError('Unable to backtrack FSE state for symbol $symbol');
  }

  static Map<int, List<_FseStateEntry>> _groupEntries(SequenceDecodingTable table) {
    final map = <int, List<_FseStateEntry>>{};
    for (var state = 0; state < table.entries.length; state++) {
      final entry = table.entries[state];
      map.putIfAbsent(entry.symbol, () => <_FseStateEntry>[]).add(
            _FseStateEntry(
              stateIndex: state,
              nbBits: entry.nbBits,
              nextStateBase: entry.nextState,
            ),
          );
    }
    for (final list in map.values) {
      list.sort((a, b) => a.nextStateBase.compareTo(b.nextStateBase));
    }
    return map;
  }
}

class _FseStateEntry {
  const _FseStateEntry({
    required this.stateIndex,
    required this.nbBits,
    required this.nextStateBase,
  });

  final int stateIndex;
  final int nbBits;
  final int nextStateBase;
}

class _FseEncodingResult {
  const _FseEncodingResult({
    required this.bits,
    required this.bitCount,
    required this.previousState,
  });

  final int bits;
  final int bitCount;
  final int previousState;
}

class _BitStreamWriter {
  final BytesBuilder _builder = BytesBuilder(copy: false);
  int _bitContainer = 0;
  int _bitCount = 0;

  void writeBits(int value, int count) {
    if (count <= 0) {
      return;
    }
    if (count > 31) {
      throw ZstdEncodingError('Bit count $count exceeds writer capacity');
    }
    final mask = (1 << count) - 1;
    _bitContainer |= (value & mask) << _bitCount;
    _bitCount += count;
    while (_bitCount >= 8) {
      _builder.add([_bitContainer & 0xFF]);
      _bitContainer >>= 8;
      _bitCount -= 8;
    }
  }

  Uint8List close() {
    writeBits(1, 1);
    while (_bitCount > 0) {
      _builder.add([_bitContainer & 0xFF]);
      _bitContainer >>= 8;
      _bitCount -= 8;
    }
    _bitContainer = 0;
    _bitCount = 0;
    final bytes = _builder.takeBytes();
    if (bytes.isEmpty || bytes.last == 0) {
      throw ZstdEncodingError('Bitstream terminator missing');
    }
    return bytes;
  }
}

void _emitBlockStats(
  ZstdEncoderBlockCallback? callback, {
  required ZstdBlockType type,
  required int literalBytes,
  required int sequenceCount,
  bool usedRepeatOffsets = false,
}) {
  callback?.call(
    ZstdEncoderBlockStats(
      blockType: type,
      literalBytes: literalBytes,
      sequenceCount: sequenceCount,
      usedRepeatOffsets: usedRepeatOffsets,

    ),
  );
}

void _appendMatchHistory(List<int> history, Uint8List slice) {
  if (slice.isEmpty) {
    return;
  }
  final capacity = zstdMatchWindowBytes;
  final start = slice.length > capacity ? slice.length - capacity : 0;
  final truncated = slice.sublist(start);
  final overflow = history.length + truncated.length - capacity;
  if (overflow > 0) {
    if (overflow >= history.length) {
      history.clear();
    } else {
      history.removeRange(0, overflow);
    }
  }
  history.addAll(truncated);
}

const int _maxWindowDistance = 1 << 18;
const List<int> _defaultPrevOffsets = [1, 4, 8];
