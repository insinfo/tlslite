import 'dart:async';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:tlslite/src/utils/zstd/block.dart';
import 'package:tlslite/src/utils/zstd/byte_reader.dart';
import 'package:tlslite/src/utils/zstd/frame_header.dart';
import 'package:tlslite/src/utils/zstd/literals.dart';
import 'package:tlslite/src/utils/zstd/sequences.dart';
import 'package:tlslite/src/utils/zstd/window.dart';

Future<void> main(List<String> args) async {
  final timeout = _parseTimeout(args) ?? const Duration(seconds: 5);
  final exitPort = ReceivePort();
  final errorPort = ReceivePort();
  final isolate = await Isolate.spawn<void>(
    _probeIsolateEntry,
    null,
    onExit: exitPort.sendPort,
    onError: errorPort.sendPort,
  );

  final completer = Completer<void>();
  late StreamSubscription exitSub;
  late StreamSubscription errorSub;

  exitSub = exitPort.listen((_) {
    if (!completer.isCompleted) {
      completer.complete();
    }
  });

  errorSub = errorPort.listen((dynamic message) {
    if (message is List && message.isNotEmpty) {
      stderr.writeln('Probe isolate error: ${message[0]}');
      if (message.length > 1) {
        stderr.writeln(message[1]);
      }
    } else {
      stderr.writeln('Probe isolate error: $message');
    }
    if (!completer.isCompleted) {
      completer.completeError(Exception('Probe isolate failed'));
    }
  });

  var timedOut = false;
  final timer = Timer(timeout, () {
    if (completer.isCompleted) {
      return;
    }
    timedOut = true;
    stderr.writeln('zstd_probe timed out after ${timeout.inSeconds} seconds; terminating isolate');
    isolate.kill(priority: Isolate.immediate);
    completer.completeError(TimeoutException('Probe timed out', timeout));
  });

  try {
    await completer.future;
    if (timedOut) {
      exitCode = 124;
    }
  } on TimeoutException {
    exitCode = 124;
  } catch (_) {
    exitCode = 1;
  } finally {
    timer.cancel();
    await exitSub.cancel();
    await errorSub.cancel();
    exitPort.close();
    errorPort.close();
  }
}

void _probeIsolateEntry(void _) {
  try {
    _runProbe();
  } finally {
    // exit will be captured by onExit port
  }
}

void _runProbe() {
  final fileData = File('test/fixtures/zstd_seq_sample.zst').readAsBytesSync();
  // Clear checksum flag and drop trailing checksum to reach current decoder path.
  fileData[4] &= 0xFB;
  final compressed = fileData.sublist(0, fileData.length - 4);
  final data = Uint8List.fromList(compressed);
  final reader = ZstdByteReader(data);
  final frameHeader = parseFrameHeader(reader);
  stdout.writeln('Frame header: window=${frameHeader.windowSize} dict=${frameHeader.dictId} contentSize=${frameHeader.frameContentSize}');

  final frameBytes = <int>[];
  final window = ZstdWindow(frameHeader.windowSize);
  HuffmanDecodingTable? repeatTable;
  var prevOffsets = <int>[1, 4, 8];
  while (!reader.isEOF) {
    final blockHeader = readBlockHeader(reader);
    stdout.writeln('Block type=${blockHeader.type} size=${blockHeader.compressedSize} last=${blockHeader.lastBlock}');
    final blockEnd = reader.offset + blockHeader.compressedSize;
    if (blockHeader.type != ZstdBlockType.compressed) {
      stdout.writeln('Non-compressed block; breaking');
      break;
    }
    final literals = decodeLiteralsBlock(reader, repeatTable: repeatTable);
    repeatTable = literals.huffmanTable ?? repeatTable;
    stdout.writeln('Literals: regen=${literals.literals.length} bytesConsumed=${literals.bytesConsumed}');

    final seqHeader = parseSequencesHeader(reader);
    stdout.writeln('Sequences header: nbSeq=${seqHeader.nbSeq} headerSize=${seqHeader.headerSize}');
    void logDescriptor(String label, SymbolEncodingDescriptor desc) {
      stdout.write('  $label=${desc.type}');
      if (desc.fseTable != null) {
        stdout.write(' log=${desc.fseTable!.tableLog} maxSym=${desc.fseTable!.maxSymbolUsed}');
      }
      if (desc.rleSymbol != null) {
        stdout.write(' rle=${desc.rleSymbol}');
      }
      stdout.writeln();
    }
    logDescriptor('LL', seqHeader.llEncoding);
    logDescriptor('OF', seqHeader.ofEncoding);
    logDescriptor('ML', seqHeader.mlEncoding);
    final payloadSize = blockEnd - reader.offset;
    final sequences = decodeSequencesSection(
      reader,
      seqHeader,
      payloadSize: payloadSize,
      initialPrevOffsets: prevOffsets,
    );
    prevOffsets = List<int>.from(sequences.finalPrevOffsets);
    stdout.writeln('Sequences decoded: count=${sequences.sequences.length} payload=${sequences.bytesConsumed}');
    for (var i = 0; i < sequences.sequences.length; i++) {
      final seq = sequences.sequences[i];
      stdout.writeln('  Seq[$i]: lit=${seq.litLength} match=${seq.matchLength} offset=${seq.offset}');
    }
    stdout.writeln('  final prevOffsets=${sequences.finalPrevOffsets}');

    try {
      executeSequences(
        sequences: sequences.sequences,
        literals: literals.literals,
        window: window,
        outputBuffer: frameBytes,
      );
      stdout.writeln('frame now ${frameBytes.length} bytes');
    } catch (e, st) {
      stderr.writeln('executeSequences failed: $e');
      stderr.writeln(st);
      break;
    }

    if (reader.offset != blockEnd) {
      reader.offset = blockEnd;
    }
    if (blockHeader.lastBlock) break;
  }
}

Duration? _parseTimeout(List<String> args) {
  for (final arg in args) {
    if (arg.startsWith('--timeout=')) {
      final value = arg.substring('--timeout='.length);
      final parsed = int.tryParse(value);
      if (parsed != null && parsed > 0) {
        return Duration(seconds: parsed);
      }
    }
    if (arg.startsWith('--timeout-ms=')) {
      final value = arg.substring('--timeout-ms='.length);
      final parsed = int.tryParse(value);
      if (parsed != null && parsed > 0) {
        return Duration(milliseconds: parsed);
      }
    }
  }
  return null;
}
