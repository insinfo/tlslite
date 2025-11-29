import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/zstd/bit_stream.dart';
import 'package:tlslite/src/utils/zstd/block.dart';
import 'package:tlslite/src/utils/zstd/byte_reader.dart';
import 'package:tlslite/src/utils/zstd/frame_header.dart';
import 'package:tlslite/src/utils/zstd/fse.dart';
import 'package:tlslite/src/utils/zstd/literals.dart';
import 'package:tlslite/src/utils/zstd/sequences.dart';
import 'package:tlslite/src/utils/zstd/window.dart';

void main() {
  group('parseSequencesHeader', () {
    test('parses zero sequences', () {
      final input = Uint8List.fromList([0x00]);
      final reader = ZstdByteReader(input);
      final header = parseSequencesHeader(reader);
      expect(header.nbSeq, equals(0));
      expect(header.headerSize, equals(1));
      expect(header.llEncoding.type, equals(SymbolEncodingType.predefined));
    });

    test('parses small sequence count (1-byte)', () {
      final input = Uint8List.fromList([50, 0x00]);
      final reader = ZstdByteReader(input);
      final header = parseSequencesHeader(reader);
      expect(header.nbSeq, equals(50));
      expect(header.llEncoding.type, equals(SymbolEncodingType.predefined));
      expect(header.ofEncoding.type, equals(SymbolEncodingType.predefined));
      expect(header.mlEncoding.type, equals(SymbolEncodingType.predefined));
      expect(header.headerSize, equals(2));
    });

    test('parses 2-byte sequence count (128-32767)', () {
      final input = Uint8List.fromList([0x81, 0x2C, 0x00]);
      final reader = ZstdByteReader(input);
      final header = parseSequencesHeader(reader);
      expect(header.nbSeq, equals(300));
      expect(header.headerSize, equals(3));
    });

    test('parses 3-byte sequence count (LONGNBSEQ)', () {
      final input = Uint8List.fromList([0xFF, 0x00, 0x01, 0x00]);
      final reader = ZstdByteReader(input);
      final header = parseSequencesHeader(reader);
      expect(header.nbSeq, equals(32768));
      expect(header.headerSize, equals(4));
    });

    test('parses encoding types correctly (supported modes)', () {
      final input = Uint8List.fromList([10, 0x40, 0x05]);
      final reader = ZstdByteReader(input);
      final header = parseSequencesHeader(reader);
      expect(header.nbSeq, equals(10));
      expect(header.llEncoding.type, equals(SymbolEncodingType.rle));
      expect(header.llEncoding.rleSymbol, equals(5));
      expect(header.ofEncoding.type, equals(SymbolEncodingType.predefined));
      expect(header.mlEncoding.type, equals(SymbolEncodingType.predefined));
    });

    test('parses RLE descriptor symbol value', () {
      final input = Uint8List.fromList([5, 0x40, 0x07]);
      final reader = ZstdByteReader(input);
      final header = parseSequencesHeader(reader);
      expect(header.llEncoding.type, equals(SymbolEncodingType.rle));
      expect(header.llEncoding.rleSymbol, equals(7));
      expect(header.headerSize, equals(3));
    });

    test('parses compressed descriptor from fixture block', () {
      final data = File('test/fixtures/zstd_seq_sample.zst').readAsBytesSync();
      final reader = ZstdByteReader(Uint8List.fromList(data));

      final frameHeader = parseFrameHeader(reader);
      expect(frameHeader.windowSize, greaterThan(0));

      final blockHeader = readBlockHeader(reader);
      expect(blockHeader.type, equals(ZstdBlockType.compressed));
      final blockEnd = reader.offset + blockHeader.compressedSize;

      _skipLiteralsSection(reader);

      final seqHeader = parseSequencesHeader(reader);
      expect(seqHeader.nbSeq, greaterThan(0));
      expect(seqHeader.headerSize, greaterThan(0));
      expect(reader.offset, lessThanOrEqualTo(blockEnd));
    });
  });

  group('baseline tables', () {
    test('literal length baselines are correct', () {
      expect(llBaseline[0], equals(0));
      expect(llBaseline[15], equals(15));
      expect(llBaseline[16], equals(16));
      expect(llBaseline[17], equals(18));
      expect(llBaseline[24], equals(48));
    });

    test('match length baselines are correct', () {
      expect(mlBaseline[0], equals(3));
      expect(mlBaseline[15], equals(18));
      expect(mlBaseline[32], equals(35));
    });

    test('offset baselines align with spec values', () {
      expect(ofBaseline[0], equals(0));
      expect(ofBaseline[1], equals(1));
      expect(ofBaseline[6], equals(61));
      expect(ofBaseline[15], equals(32765));
      expect(ofBaseline[28], equals(268435453));
    });
  });

  group('FSE table builder', () {
    test('matches default literal-length table', () {
      final descriptor = _descriptorFromDefaults(
        norm: llDefaultNorm,
        tableLog: llDefaultNormLog,
      );
      final table = buildSequenceDecodingTable(
        descriptor: descriptor,
        baseValues: llBaseline,
        extraBits: llExtraBits,
      );
      final reference = _parseReferenceTable(_llDefaultDTableSource);
      _expectTableMatchesReference(table.entries, reference, label: 'LL');
    });

    test('matches default offset table', () {
      final descriptor = _descriptorFromDefaults(
        norm: ofDefaultNorm,
        tableLog: ofDefaultNormLog,
      );
      final table = buildSequenceDecodingTable(
        descriptor: descriptor,
        baseValues: ofBaseline,
        extraBits: ofExtraBits,
      );
      final reference = _parseReferenceTable(_ofDefaultDTableSource);
      _expectTableMatchesReference(table.entries, reference, label: 'OF');
    });

    test('matches default match-length table', () {
      final descriptor = _descriptorFromDefaults(
        norm: mlDefaultNorm,
        tableLog: mlDefaultNormLog,
      );
      final table = buildSequenceDecodingTable(
        descriptor: descriptor,
        baseValues: mlBaseline,
        extraBits: mlExtraBits,
      );
      final reference = _parseReferenceTable(_mlDefaultDTableSource);
      _expectTableMatchesReference(table.entries, reference, label: 'ML');
    });
  });

  group('sequence table aggregator', () {
    test('builds predefined tables matching defaults', () {
      final header = SequencesHeader(
        nbSeq: 3,
        llEncoding: const SymbolEncodingDescriptor(type: SymbolEncodingType.predefined),
        ofEncoding: const SymbolEncodingDescriptor(type: SymbolEncodingType.predefined),
        mlEncoding: const SymbolEncodingDescriptor(type: SymbolEncodingType.predefined),
        headerSize: 0,
      );

      final tables = buildSequenceDecodingTables(header);
      final llReference = _parseReferenceTable(_llDefaultDTableSource);
      final ofReference = _parseReferenceTable(_ofDefaultDTableSource);
      final mlReference = _parseReferenceTable(_mlDefaultDTableSource);

      _expectTableMatchesReference(
        tables.literalLengthTable.entries,
        llReference,
        label: 'LL predefined',
      );
      _expectTableMatchesReference(
        tables.offsetTable.entries,
        ofReference,
        label: 'OF predefined',
      );
      _expectTableMatchesReference(
        tables.matchLengthTable.entries,
        mlReference,
        label: 'ML predefined',
      );
    });

    test('builds literal-length RLE table', () {
      final header = SequencesHeader(
        nbSeq: 1,
        llEncoding: const SymbolEncodingDescriptor(
          type: SymbolEncodingType.rle,
          rleSymbol: 5,
        ),
        ofEncoding: const SymbolEncodingDescriptor(type: SymbolEncodingType.predefined),
        mlEncoding: const SymbolEncodingDescriptor(type: SymbolEncodingType.predefined),
        headerSize: 0,
      );

      final tables = buildSequenceDecodingTables(header);
      final table = tables.literalLengthTable;
      expect(table.tableLog, equals(0));
      expect(table.entries.length, equals(1));
      final entry = table.entries.first;
      expect(entry.symbol, equals(5));
      expect(entry.baseValue, equals(llBaseline[5]));
      expect(entry.nbAdditionalBits, equals(llExtraBits[5]));
      expect(entry.nbBits, equals(0));
      expect(entry.nextState, equals(0));
    });

    test('builds compressed literal-length table from descriptor', () {
      final descriptor = FseTableDescriptor(
        tableLog: llDefaultNormLog,
        normalizedCounts: List<int>.from(llDefaultNorm),
        maxSymbol: llDefaultNorm.length - 1,
        maxSymbolUsed: llDefaultNorm.length - 1,
      );
      final header = SequencesHeader(
        nbSeq: 1,
        llEncoding: SymbolEncodingDescriptor(
          type: SymbolEncodingType.compressed,
          fseTable: descriptor,
        ),
        ofEncoding: const SymbolEncodingDescriptor(type: SymbolEncodingType.predefined),
        mlEncoding: const SymbolEncodingDescriptor(type: SymbolEncodingType.predefined),
        headerSize: 0,
      );

      final tables = buildSequenceDecodingTables(header);
      final reference = _parseReferenceTable(_llDefaultDTableSource);
      _expectTableMatchesReference(
        tables.literalLengthTable.entries,
        reference,
        label: 'LL compressed',
      );
    });
  });

  group('sequence decoder', () {
    test('returns empty list when nbSeq is zero', () {
      final tables = _buildRleTables(llSymbol: 0, ofSymbol: 0, mlSymbol: 0);
      final decoder = SequenceSectionDecoder(
        tables: tables,
        bitstream: Uint8List(0),
        nbSequences: 0,
      );
      expect(decoder.decodeAll(), isEmpty);
    });

    test('reuses previous offset when literal base is non-zero', () {
      final tables = _buildRleTables(llSymbol: 5, ofSymbol: 0, mlSymbol: 0);
      final decoder = SequenceSectionDecoder(
        tables: tables,
        bitstream: _minimalBitstream(),
        nbSequences: 2,
        initialPrevOffsets: const [9, 7, 5],
      );
      final sequences = decoder.decodeAll();
      expect(sequences.length, equals(2));
      expect(sequences[0].offset, equals(9));
      expect(sequences[1].offset, equals(9));
    });

    test('shifts repeated offsets when literal base is zero', () {
      final tables = _buildRleTables(llSymbol: 0, ofSymbol: 0, mlSymbol: 0);
      final decoder = SequenceSectionDecoder(
        tables: tables,
        bitstream: _minimalBitstream(),
        nbSequences: 2,
        initialPrevOffsets: const [9, 7, 5],
      );
      final sequences = decoder.decodeAll();
      expect(sequences[0].offset, equals(7));
      expect(sequences[1].offset, equals(9));
    });

    test('handles single extra offset bit', () {
      final tables = _buildRleTables(llSymbol: 0, ofSymbol: 1, mlSymbol: 0);
      final decoder = SequenceSectionDecoder(
        tables: tables,
        bitstream: _minimalBitstream(),
        nbSequences: 1,
        initialPrevOffsets: const [5, 7, 11],
      );
      final sequence = decoder.decodeAll().single;
      expect(sequence.offset, equals(11));
    });

    test('stores new offsets when extra bits > 1', () {
      final tables = _buildRleTables(llSymbol: 5, ofSymbol: 3, mlSymbol: 0);
      final decoder = SequenceSectionDecoder(
        tables: tables,
        bitstream: _minimalBitstream(),
        nbSequences: 1,
        initialPrevOffsets: const [5, 7, 11],
      );
      final sequence = decoder.decodeAll().single;
      expect(sequence.offset, equals(ofBaseline[3]));
    });

    test('validates initial offset length', () {
      final tables = _buildRleTables(llSymbol: 0, ofSymbol: 0, mlSymbol: 0);
      expect(
        () => SequenceSectionDecoder(
          tables: tables,
          bitstream: Uint8List(0),
          nbSequences: 0,
          initialPrevOffsets: const [1, 2],
        ),
        throwsArgumentError,
      );
    });
  });

  group('sequence decoding helpers', () {
    test('decodeSequencesFromPayload returns result metadata', () {
      final header = SequencesHeader(
        nbSeq: 1,
        llEncoding: const SymbolEncodingDescriptor(
          type: SymbolEncodingType.rle,
          rleSymbol: 5,
        ),
        ofEncoding: const SymbolEncodingDescriptor(
          type: SymbolEncodingType.rle,
          rleSymbol: 0,
        ),
        mlEncoding: const SymbolEncodingDescriptor(
          type: SymbolEncodingType.rle,
          rleSymbol: 0,
        ),
        headerSize: 0,
      );
      final payload = _minimalBitstream();
      final result = decodeSequencesFromPayload(
        header: header,
        payload: payload,
        initialPrevOffsets: const [9, 7, 5],
      );
      expect(result.bytesConsumed, equals(payload.length));
      expect(result.sequences.length, equals(1));
      expect(result.sequences.first.offset, equals(9));
      expect(result.finalPrevOffsets, equals(const [9, 7, 5]));
    });

    test('decodeSequencesSection reads from reader', () {
      final header = SequencesHeader(
        nbSeq: 1,
        llEncoding: const SymbolEncodingDescriptor(
          type: SymbolEncodingType.rle,
          rleSymbol: 5,
        ),
        ofEncoding: const SymbolEncodingDescriptor(
          type: SymbolEncodingType.rle,
          rleSymbol: 0,
        ),
        mlEncoding: const SymbolEncodingDescriptor(
          type: SymbolEncodingType.rle,
          rleSymbol: 0,
        ),
        headerSize: 0,
      );
      final reader = ZstdByteReader(_minimalBitstream());
      final result = decodeSequencesSection(reader, header);
      expect(result.bytesConsumed, equals(reader.buffer.length));
      expect(reader.offset, equals(reader.buffer.length));
      expect(result.sequences.length, equals(1));
    });
  });

  group('sequence executor', () {
    test('executes literal and match sequence', () {
      final sequences = [
        const Sequence(litLength: 3, matchLength: 3, offset: 3),
      ];
      final literals = Uint8List.fromList([10, 11, 12]);
      final output = <int>[];
      final window = ZstdWindow(32);
      executeSequences(
        sequences: sequences,
        literals: literals,
        window: window,
        outputBuffer: output,
      );
      expect(output, equals([10, 11, 12, 10, 11, 12]));
    });

    test('supports overlapping matches', () {
      final sequences = [
        const Sequence(litLength: 2, matchLength: 5, offset: 2),
      ];
      final literals = Uint8List.fromList([1, 2]);
      final output = <int>[];
      final window = ZstdWindow(32);
      executeSequences(
        sequences: sequences,
        literals: literals,
        window: window,
        outputBuffer: output,
      );
      expect(output, equals([1, 2, 1, 2, 1, 2, 1]));
    });

    test('appends trailing literals after sequences', () {
      final sequences = [
        const Sequence(litLength: 1, matchLength: 0, offset: 1),
      ];
      final literals = Uint8List.fromList([5, 6, 7]);
      final output = <int>[];
      final window = ZstdWindow(32);
      executeSequences(
        sequences: sequences,
        literals: literals,
        window: window,
        outputBuffer: output,
      );
      expect(output, equals([5, 6, 7]));
    });

    test('throws when offset exceeds produced bytes', () {
      final sequences = [
        const Sequence(litLength: 0, matchLength: 3, offset: 4),
      ];
      final literals = Uint8List(0);
      final output = <int>[];
      final window = ZstdWindow(32);
      expect(
        () => executeSequences(
          sequences: sequences,
          literals: literals,
          window: window,
          outputBuffer: output,
        ),
        throwsA(isA<ZstdFrameFormatException>()),
      );
    });
  });
}

SequenceDecodingTables _buildRleTables({
  required int llSymbol,
  required int ofSymbol,
  required int mlSymbol,
}) {
  final header = SequencesHeader(
    nbSeq: 1,
    llEncoding: SymbolEncodingDescriptor(
      type: SymbolEncodingType.rle,
      rleSymbol: llSymbol,
    ),
    ofEncoding: SymbolEncodingDescriptor(
      type: SymbolEncodingType.rle,
      rleSymbol: ofSymbol,
    ),
    mlEncoding: SymbolEncodingDescriptor(
      type: SymbolEncodingType.rle,
      rleSymbol: mlSymbol,
    ),
    headerSize: 0,
  );
  return buildSequenceDecodingTables(header);
}

Uint8List _minimalBitstream() {
  final data = Uint8List(bitContainerSize);
  data[data.length - 1] = 0x80;
  return data;
}

FseTableDescriptor _descriptorFromDefaults({
  required List<int> norm,
  required int tableLog,
}) {
  final maxSymbol = norm.length - 1;
  return FseTableDescriptor(
    tableLog: tableLog,
    normalizedCounts: List<int>.from(norm),
    maxSymbol: maxSymbol,
    maxSymbolUsed: maxSymbol,
  );
}

void _expectTableMatchesReference(
  List<SequenceDecodingEntry> entries,
  List<_ExpectedEntry> reference, {
  required String label,
}) {
  expect(entries.length, equals(reference.length), reason: '$label table size');
  for (var i = 0; i < reference.length; i++) {
    final actual = entries[i];
    final expected = reference[i];
    expect(actual.nextState, equals(expected.nextState), reason: '$label nextState @$i');
    expect(
      actual.nbAdditionalBits,
      equals(expected.nbAdditionalBits),
      reason: '$label nbAdditionalBits @$i',
    );
    expect(actual.nbBits, equals(expected.nbBits), reason: '$label nbBits @$i');
    expect(actual.baseValue, equals(expected.baseValue), reason: '$label baseValue @$i');
  }
}

class _ExpectedEntry {
  const _ExpectedEntry({
    required this.nextState,
    required this.nbAdditionalBits,
    required this.nbBits,
    required this.baseValue,
  });

  final int nextState;
  final int nbAdditionalBits;
  final int nbBits;
  final int baseValue;
}

List<_ExpectedEntry> _parseReferenceTable(String source) {
  final regex = RegExp(r'\{([^{}]+)\}');
  final entries = <_ExpectedEntry>[];
  for (final match in regex.allMatches(source)) {
    final rawFields = match.group(1)!;
    final parts = rawFields
        .split(',')
        .map((part) => part.trim())
        .where((part) => part.isNotEmpty)
        .toList();
    if (parts.length != 4) {
      continue;
    }
    entries.add(_ExpectedEntry(
      nextState: int.parse(parts[0]),
      nbAdditionalBits: int.parse(parts[1]),
      nbBits: int.parse(parts[2]),
      baseValue: int.parse(parts[3]),
    ));
  }
  return entries;
}

const _llDefaultDTableSource = '''
{  0,  0,  4,    0},  { 16,  0,  4,    0},
{ 32,  0,  5,    1},  {  0,  0,  5,    3},
{  0,  0,  5,    4},  {  0,  0,  5,    6},
{  0,  0,  5,    7},  {  0,  0,  5,    9},
{  0,  0,  5,   10},  {  0,  0,  5,   12},
{  0,  0,  6,   14},  {  0,  1,  5,   16},
{  0,  1,  5,   20},  {  0,  1,  5,   22},
{  0,  2,  5,   28},  {  0,  3,  5,   32},
{  0,  4,  5,   48},  { 32,  6,  5,   64},
{  0,  7,  5,  128},  {  0,  8,  6,  256},
{  0, 10,  6, 1024},  {  0, 12,  6, 4096},
{ 32,  0,  4,    0},  {  0,  0,  4,    1},
{  0,  0,  5,    2},  { 32,  0,  5,    4},
{  0,  0,  5,    5},  { 32,  0,  5,    7},
{  0,  0,  5,    8},  { 32,  0,  5,   10},
{  0,  0,  5,   11},  {  0,  0,  6,   13},
{ 32,  1,  5,   16},  {  0,  1,  5,   18},
{ 32,  1,  5,   22},  {  0,  2,  5,   24},
{ 32,  3,  5,   32},  {  0,  3,  5,   40},
{  0,  6,  4,   64},  { 16,  6,  4,   64},
{ 32,  7,  5,  128},  {  0,  9,  6,  512},
{  0, 11,  6, 2048},  { 48,  0,  4,    0},
{ 16,  0,  4,    1},  { 32,  0,  5,    2},
{ 32,  0,  5,    3},  { 32,  0,  5,    5},
{ 32,  0,  5,    6},  { 32,  0,  5,    8},
{ 32,  0,  5,    9},  { 32,  0,  5,   11},
{ 32,  0,  5,   12},  {  0,  0,  6,   15},
{ 32,  1,  5,   18},  { 32,  1,  5,   20},
{ 32,  2,  5,   24},  { 32,  2,  5,   28},
{ 32,  3,  5,   40},  { 32,  4,  5,   48},
{  0, 16,  6,65536},  {  0, 15,  6,32768},
{  0, 14,  6,16384},  {  0, 13,  6, 8192},
''';

const _ofDefaultDTableSource = '''
{  0,  0,  5,    0},     {  0,  6,  4,   61},
{  0,  9,  5,  509},     {  0, 15,  5,32765},
{  0, 21,  5,2097149},   {  0,  3,  5,    5},
{  0,  7,  4,  125},     {  0, 12,  5, 4093},
{  0, 18,  5,262141},    {  0, 23,  5,8388605},
{  0,  5,  5,   29},     {  0,  8,  4,  253},
{  0, 14,  5,16381},     {  0, 20,  5,1048573},
{  0,  2,  5,    1},     { 16,  7,  4,  125},
{  0, 11,  5, 2045},     {  0, 17,  5,131069},
{  0, 22,  5,4194301},   {  0,  4,  5,   13},
{ 16,  8,  4,  253},     {  0, 13,  5, 8189},
{  0, 19,  5,524285},    {  0,  1,  5,    1},
{ 16,  6,  4,   61},     {  0, 10,  5, 1021},
{  0, 16,  5,65533},     {  0, 28,  5,268435453},
{  0, 27,  5,134217725}, {  0, 26,  5,67108861},
{  0, 25,  5,33554429},  {  0, 24,  5,16777213},
''';

const _mlDefaultDTableSource = '''
{  0,  0,  6,    3},  {  0,  0,  4,    4},
{ 32,  0,  5,    5},  {  0,  0,  5,    6},
{  0,  0,  5,    8},  {  0,  0,  5,    9},
{  0,  0,  5,   11},  {  0,  0,  6,   13},
{  0,  0,  6,   16},  {  0,  0,  6,   19},
{  0,  0,  6,   22},  {  0,  0,  6,   25},
{  0,  0,  6,   28},  {  0,  0,  6,   31},
{  0,  0,  6,   34},  {  0,  1,  6,   37},
{  0,  1,  6,   41},  {  0,  2,  6,   47},
{  0,  3,  6,   59},  {  0,  4,  6,   83},
{  0,  7,  6,  131},  {  0,  9,  6,  515},
{ 16,  0,  4,    4},  {  0,  0,  4,    5},
{ 32,  0,  5,    6},  {  0,  0,  5,    7},
{ 32,  0,  5,    9},  {  0,  0,  5,   10},
{  0,  0,  6,   12},  {  0,  0,  6,   15},
{  0,  0,  6,   18},  {  0,  0,  6,   21},
{  0,  0,  6,   24},  {  0,  0,  6,   27},
{  0,  0,  6,   30},  {  0,  0,  6,   33},
{  0,  1,  6,   35},  {  0,  1,  6,   39},
{  0,  2,  6,   43},  {  0,  3,  6,   51},
{  0,  4,  6,   67},  {  0,  5,  6,   99},
{  0,  8,  6,  259},  { 32,  0,  4,    4},
{ 48,  0,  4,    4},  { 16,  0,  4,    5},
{ 32,  0,  5,    7},  { 32,  0,  5,    8},
{ 32,  0,  5,   10},  { 32,  0,  5,   11},
{  0,  0,  6,   14},  {  0,  0,  6,   17},
{  0,  0,  6,   20},  {  0,  0,  6,   23},
{  0,  0,  6,   26},  {  0,  0,  6,   29},
{  0,  0,  6,   32},  {  0, 16,  6,65539},
{  0, 15,  6,32771},  {  0, 14,  6,16387},
{  0, 13,  6, 8195},  {  0, 12,  6, 4099},
{  0, 11,  6, 2051},  {  0, 10,  6, 1027},
''';

void _skipLiteralsSection(ZstdByteReader reader) {
  final start = reader.offset;
  final firstByte = reader.readUint8();
  final type = LiteralsBlockType.values[firstByte & 0x3];
  reader.offset = start;
  switch (type) {
    case LiteralsBlockType.raw:
    case LiteralsBlockType.rle:
      decodeLiteralsBlock(reader);
      return;
    case LiteralsBlockType.compressed:
      final header = _parseCompressedLiteralHeader(reader);
      reader.skip(header.headerSize + header.compressedSize);
      return;
    case LiteralsBlockType.repeat:
      throw UnsupportedError('Repeat literals are not supported in this test yet');
  }
}

class _CompressedLiteralHeader {
  _CompressedLiteralHeader(this.headerSize, this.compressedSize);
  final int headerSize;
  final int compressedSize;
}

_CompressedLiteralHeader _parseCompressedLiteralHeader(ZstdByteReader reader) {
  final start = reader.offset;
  final byte0 = reader.readUint8();
  final lhlCode = (byte0 >> 2) & 0x3;
  int litCSize;

  switch (lhlCode) {
    case 0:
    case 1:
      reader.offset = start;
      final val = reader.readUint24LE();
      litCSize = (val >> 14) & 0x3FF;
      break;
    case 2:
      reader.offset = start;
      final val = reader.readUint32LE();
      litCSize = val >> 18;
      break;
    case 3:
      reader.offset = start;
      final val = reader.readUint32LE();
      final byte4 = reader.readUint8();
      litCSize = (val >> 22) + (byte4 << 10);
      break;
    default:
      throw StateError('Unreachable literal header state');
  }

  final headerSize = reader.offset - start;
  reader.offset = start;
  return _CompressedLiteralHeader(headerSize, litCSize);
}
