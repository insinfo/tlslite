import 'dart:io';
import 'dart:typed_data';

import 'BrotliInputStream.dart';
import 'State.dart';

/// Toy decoder CLI mirroring the reference implementation in Java.
class Decoder {
  Decoder._();

  /// Streams the Brotli payload from [input] into [output] using [buffer].
  ///
  /// Returns the number of bytes written to [output].
  static int decodeBytes(InputStream input, RandomAccessFile output, Uint8List buffer) {
    if (buffer.isEmpty) {
      throw ArgumentError.value(buffer.length, 'buffer.length', 'Buffer must be non-empty');
    }

    final brotliInput = BrotliInputStream(input);
    brotliInput.enableLargeWindow();
    var totalOut = 0;
    try {
      while (true) {
        final readBytes = brotliInput.read(buffer, 0, buffer.length);
        if (readBytes < 0) {
          break;
        }
        output.writeFromSync(buffer, 0, readBytes);
        totalOut += readBytes;
      }
      return totalOut;
    } finally {
      brotliInput.close();
    }
  }

  /// Runs a single decode pass for the given paths and returns emitted bytes.
  static int _decompressOnce(String fromPath, String toPath, Uint8List buffer) {
    RandomAccessFile? inputFile;
    RandomAccessFile? outputFile;
    _FileInputStream? source;
    try {
      inputFile = File(fromPath).openSync();
      final output = File(toPath);
      output.parent.createSync(recursive: true);
      outputFile = output.openSync(mode: FileMode.write);
      outputFile.setPositionSync(0);
      outputFile.truncateSync(0);
      source = _FileInputStream(inputFile);
      final bytesDecoded = decodeBytes(source, outputFile, buffer);
      outputFile.flushSync();
      return bytesDecoded;
    } finally {
      source?.close();
      outputFile?.closeSync();
    }
  }

  /// Decompresses [fromPath] into [toPath], repeating the pass [repeat] times.
  /// Prints the throughput (MiB/s) for each iteration similar to the Java CLI.
  static void decompress(String fromPath, String toPath, {int repeat = 1, int bufferSize = 1024 * 1024}) {
    if (repeat < 1) {
      throw ArgumentError.value(repeat, 'repeat', 'Repeat count must be >= 1');
    }
    if (bufferSize <= 0) {
      throw ArgumentError.value(bufferSize, 'bufferSize', 'Buffer must be positive');
    }

    final buffer = Uint8List(bufferSize);
    for (var i = 0; i < repeat; ++i) {
      final watch = Stopwatch()..start();
      final bytesDecoded = _decompressOnce(fromPath, toPath, buffer);
      watch.stop();
      final seconds = watch.elapsedMicroseconds / 1000000.0;
      if (seconds <= 0) {
        continue;
      }
      final mbDecoded = bytesDecoded / (1024.0 * 1024.0);
      stdout.writeln('${(mbDecoded / seconds).toStringAsFixed(2)} MiB/s');
    }
  }

  /// CLI entry point used when running this file directly.
  static void cli(List<String> args) {
    if (args.length != 2 && args.length != 3) {
      stdout.writeln('Usage: decoder <compressed_in> <decompressed_out> [repeat]');
      return;
    }

    var repeat = 1;
    if (args.length == 3) {
      repeat = int.parse(args[2]);
    }

    decompress(args[0], args[1], repeat: repeat);
  }
}

class _FileInputStream implements InputStream {
  _FileInputStream(this._file);

  final RandomAccessFile _file;
  bool _closed = false;

  @override
  int read(Uint8List buffer, int offset, int length) {
    if (length <= 0) {
      return 0;
    }
    final end = offset + length;
    if (end > buffer.length) {
      throw RangeError.range(end, 0, buffer.length, 'length', 'Read would overflow buffer');
    }
    final bytesRead = _file.readIntoSync(buffer, offset, end);
    return bytesRead == 0 ? -1 : bytesRead;
  }

  @override
  void close() {
    if (_closed) {
      return;
    }
    _closed = true;
    _file.closeSync();
  }
}

void main(List<String> args) {
  Decoder.cli(args);
}
