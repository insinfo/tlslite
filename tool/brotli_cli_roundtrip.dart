import 'dart:io';
import 'dart:typed_data';

import 'package:tlslite/src/brotli/dec/Decode.dart';
import 'package:tlslite/src/brotli/enc/brotli_encoder.dart';

Future<void> main(List<String> args) async {
  final options = _parseArgs(args);
  if (options == null) {
    _printUsage();
    exitCode = 64;
    return;
  }

  try {
    final inputFile = File(options.inputPath);
    if (!await inputFile.exists()) {
      stderr.writeln('Input file not found: ${options.inputPath}');
      exitCode = 66;
      return;
    }

    final inputBytes = await inputFile.readAsBytes();
    stdout.writeln('Read ${inputBytes.length} bytes from ${options.inputPath}.');

    final sw = Stopwatch()..start();
    final compressed = brotliCompressLiteral(
      Uint8List.fromList(inputBytes),
      windowBits: options.windowBits,
    );
    sw.stop();
    await File(options.outputPath).writeAsBytes(compressed, flush: true);
    stdout.writeln(
      'Compressed -> ${compressed.length} bytes (windowBits=${options.windowBits}, ${sw.elapsedMilliseconds} ms).',
    );

    if (options.roundtrip) {
      final roundtripSw = Stopwatch()..start();
      final decompressed = brotliDecompressBuffer(compressed);
      roundtripSw.stop();
      if (!_buffersEqual(decompressed, inputBytes)) {
        stderr.writeln('Round-trip mismatch: decoded payload differs from input.');
        if (!options.keepArtifacts) {
          await _deleteIfExists(options.outputPath);
        }
        exitCode = 1;
        return;
      }

      stdout.writeln(
        'Round-trip verified (${decompressed.length} bytes, ${roundtripSw.elapsedMilliseconds} ms).',
      );

      if (options.roundtripOutputPath != null) {
        await File(options.roundtripOutputPath!).writeAsBytes(
          decompressed,
          flush: true,
        );
        stdout.writeln('Wrote round-trip payload to ${options.roundtripOutputPath!}.');
      }
    }
  } on FormatException catch (error) {
    stderr.writeln('Argument error: ${error.message}');
    exitCode = 64;
  } on IOException catch (error) {
    stderr.writeln('I/O error: $error');
    exitCode = 74;
  } catch (error, stackTrace) {
    stderr.writeln('Unexpected error: $error');
    stderr.writeln(stackTrace);
    exitCode = 70;
  }
}

Future<void> _deleteIfExists(String path) async {
  final file = File(path);
  if (await file.exists()) {
    await file.delete();
  }
}

bool _buffersEqual(Uint8List a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}

_CliOptions? _parseArgs(List<String> args) {
  if (args.isEmpty || args.contains('--help') || args.contains('-h')) {
    return null;
  }

  String? input;
  String? output;
  String? roundtripOutput;
  var roundtrip = true;
  var keepArtifacts = false;
  var windowBits = 16;

  for (var i = 0; i < args.length; i++) {
    final arg = args[i];
    switch (arg) {
      case '--output':
        output = _takeValue(args, ++i, '--output');
        break;
      case '--roundtrip-output':
        roundtripOutput = _takeValue(args, ++i, '--roundtrip-output');
        break;
      case '--window-bits':
        final value = _takeValue(args, ++i, '--window-bits');
        windowBits = int.parse(value);
        break;
      case '--roundtrip':
        roundtrip = true;
        break;
      case '--skip-roundtrip':
        roundtrip = false;
        break;
      case '--keep-artifacts':
        keepArtifacts = true;
        break;
      default:
        if (arg.startsWith('-')) {
          throw FormatException('Unknown flag $arg');
        }
        input ??= arg;
        break;
    }
  }

  if (input == null) {
    throw FormatException('Missing input file');
  }

  if (windowBits < 16 || windowBits > 24) {
    throw FormatException('windowBits must be between 16 and 24 (got $windowBits)');
  }

  output ??= '$input.br';

  return _CliOptions(
    inputPath: input,
    outputPath: output,
    roundtripOutputPath: roundtripOutput,
    roundtrip: roundtrip,
    windowBits: windowBits,
    keepArtifacts: keepArtifacts,
  );
}

String _takeValue(List<String> args, int index, String flag) {
  if (index >= args.length) {
    throw FormatException('Missing value after $flag');
  }
  return args[index];
}

void _printUsage() {
  stdout.writeln('Brotli CLI roundtrip helper');
  stdout.writeln('Usage: dart run tool/brotli_cli_roundtrip.dart <input> [options]\n');
  stdout.writeln('Options:');
  stdout.writeln('  --output <path>             Path for the compressed payload (default: <input>.br)');
  stdout.writeln(
    '  --window-bits <16-24>      Brotli window size to use (default: 16)',
  );
  stdout.writeln('  --roundtrip                 Verify by decoding (default)');
  stdout.writeln('  --skip-roundtrip            Skip verification step');
  stdout.writeln(
    '  --roundtrip-output <path>  Write the decoded payload after verification',
  );
  stdout.writeln('  --keep-artifacts            Keep compressed file when verification fails');
  stdout.writeln('  -h, --help                  Show this message');
}

class _CliOptions {
  const _CliOptions({
    required this.inputPath,
    required this.outputPath,
    required this.roundtripOutputPath,
    required this.roundtrip,
    required this.windowBits,
    required this.keepArtifacts,
  });

  final String inputPath;
  final String outputPath;
  final String? roundtripOutputPath;
  final bool roundtrip;
  final int windowBits;
  final bool keepArtifacts;
}
