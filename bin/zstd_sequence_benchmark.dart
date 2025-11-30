import 'dart:io';
import 'dart:typed_data';

import 'package:tlslite/src/utils/zstd/block.dart';
import 'package:tlslite/src/utils/zstd/byte_reader.dart';
import 'package:tlslite/src/utils/zstd/frame_header.dart';
import 'package:tlslite/src/utils/zstd/literals.dart';
import 'package:tlslite/src/utils/zstd/sequences.dart';

Future<void> main(List<String> args) async {
  final iterations = _parseIterations(args);
  final benchmark = SequenceSectionBenchmark.fromFixture(
    'test/fixtures/zstd_seq_sample.zst',
  );

  final stopwatch = Stopwatch()..start();
  var decodedSequences = 0;
  for (var i = 0; i < iterations; i++) {
    decodedSequences += benchmark.decodeOnce();
  }
  stopwatch.stop();

  final totalMs = stopwatch.elapsedMilliseconds;
  final perIter = totalMs / iterations;
  final perSeq = decodedSequences == 0 ? 0 : totalMs / decodedSequences;

  stdout.writeln('Sequence decoder benchmark');
  stdout.writeln('Iterations: $iterations');
  stdout.writeln('Sequences decoded: $decodedSequences');
  stdout.writeln('Total time: ${stopwatch.elapsed}');
  stdout.writeln('Avg per iteration: ${perIter.toStringAsFixed(3)} ms');
  stdout.writeln('Avg time per sequence: ${perSeq.toStringAsFixed(6)} ms');
}

int _parseIterations(List<String> args) {
  if (args.isEmpty) {
    return 250;
  }
  final value = int.tryParse(args.first);
  if (value == null || value <= 0) {
    stderr.writeln('Invalid iteration count "${args.first}" – using default 250');
    return 250;
  }
  return value;
}

class SequenceSectionBenchmark {
  SequenceSectionBenchmark({
    required this.nbSequences,
    required this.tables,
    required this.bitstream,
    required this.initialPrevOffsets,
  });

  factory SequenceSectionBenchmark.fromFixture(String path) {
    final bytes = File(path).readAsBytesSync();
    final reader = ZstdByteReader(Uint8List.fromList(bytes));
    final frameHeader = parseFrameHeader(reader);
    if (!frameHeader.singleSegment) {
      throw StateError('Fixture $path is expected to be single-segment');
    }
    final blockHeader = readBlockHeader(reader);
    if (blockHeader.type != ZstdBlockType.compressed) {
      throw StateError('Fixture $path must contain a compressed block');
    }
    final blockEnd = reader.offset + blockHeader.compressedSize;

    // Skip literals – they are not needed for this benchmark.
    decodeLiteralsBlock(reader);

    final seqHeader = parseSequencesHeader(reader);
    final payloadSize = blockEnd - reader.offset;
    if (payloadSize <= 0) {
      throw StateError('Invalid sequences payload size: $payloadSize');
    }
    final payload = reader.readBytes(payloadSize);
    final tables = buildSequenceDecodingTables(seqHeader);
    return SequenceSectionBenchmark(
      nbSequences: seqHeader.nbSeq,
      tables: tables,
      bitstream: payload,
      initialPrevOffsets: const [1, 4, 8],
    );
  }

  final int nbSequences;
  final SequenceDecodingTables tables;
  final Uint8List bitstream;
  final List<int> initialPrevOffsets;

  int decodeOnce() {
    final decoder = SequenceSectionDecoder(
      tables: tables,
      bitstream: bitstream,
      nbSequences: nbSequences,
      initialPrevOffsets: initialPrevOffsets,
    );
    final sequences = decoder.decodeAll();
    return sequences.length;
  }
}
