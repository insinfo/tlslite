import 'dart:io';
import 'dart:typed_data';

import 'package:tlslite/src/utils/brotlidecpy/brotli_encoder.dart';

Future<void> main(List<String> args) async {
  final config = _CliConfig.parse(args);
  final payload = await File(config.inputPath).readAsBytes();
  final stream = brotliCompressRaw(
    Uint8List.fromList(payload),
    windowBits: config.windowBits,
  );

  final workDir = await config.prepareWorkingDirectory();
  final streamFile = File('${workDir.path}/payload.br');
  await streamFile.writeAsBytes(stream, flush: true);
  final decodedFile = File('${workDir.path}/decoded.bin');

  ProcessResult cliResult;
  try {
    cliResult = await Process.run(
      'brotli',
      ['-d', '-f', '-o', decodedFile.path, streamFile.path],
    );
  } on ProcessException catch (error) {
    stderr.writeln('Failed to launch brotli CLI: ${error.message}');
    stderr.writeln('Artifacts kept at ${workDir.path}');
    exit(2);
  }

  if (cliResult.exitCode != 0) {
    stderr.writeln('brotli CLI exited with ${cliResult.exitCode}');
    stderr.writeln(cliResult.stderr);
    stderr.writeln('Artifacts kept at ${workDir.path}');
    exit(cliResult.exitCode);
  }

  final decoded = await decodedFile.readAsBytes();
  final payloadBytes = Uint8List.fromList(payload);
  if (!_bytesEqual(decoded, payloadBytes)) {
    stderr.writeln('Decoded payload does not match input');
    stderr.writeln('Expected ${payloadBytes.length} bytes, got ${decoded.length}');
    stderr.writeln('Artifacts kept at ${workDir.path}');
    exit(3);
  }

  stdout.writeln('Roundtrip succeeded (${payloadBytes.length} bytes)');
  if (!config.keepArtifacts && config.workDir == null) {
    await workDir.delete(recursive: true);
  } else {
    stdout.writeln('Artifacts preserved at ${workDir.path}');
  }
}

class _CliConfig {
  _CliConfig({
    required this.inputPath,
    required this.windowBits,
    required this.keepArtifacts,
    this.workDir,
  });

  final String inputPath;
  final int windowBits;
  final bool keepArtifacts;
  final String? workDir;

  static _CliConfig parse(List<String> args) {
    String? inputPath;
    String? workDir;
    var windowBits = 16;
    var keepArtifacts = false;

    for (var i = 0; i < args.length; i++) {
      final arg = args[i];
      switch (arg) {
        case '--keep-artifacts':
          keepArtifacts = true;
          continue;
        case '--input':
          inputPath = _consumeValue(args, ++i, '--input');
          continue;
        case '--window-bits':
          final value = _consumeValue(args, ++i, '--window-bits');
          windowBits = int.parse(value);
          continue;
        case '--work-dir':
          workDir = _consumeValue(args, ++i, '--work-dir');
          continue;
      }

      if (arg.startsWith('--input=')) {
        inputPath = arg.substring('--input='.length);
        continue;
      }
      if (arg.startsWith('--window-bits=')) {
        windowBits = int.parse(arg.substring('--window-bits='.length));
        continue;
      }
      if (arg.startsWith('--work-dir=')) {
        workDir = arg.substring('--work-dir='.length);
        continue;
      }

      _usage('Unknown argument: $arg');
    }

    if (inputPath == null) {
      _usage('Missing required --input');
    }

    return _CliConfig(
      inputPath: inputPath,
      windowBits: windowBits,
      keepArtifacts: keepArtifacts,
      workDir: workDir,
    );
  }

  Future<Directory> prepareWorkingDirectory() async {
    if (workDir != null) {
      final dir = Directory(workDir!);
      if (!dir.existsSync()) {
        dir.createSync(recursive: true);
      }
      return dir.absolute;
    }
    return Directory.systemTemp.createTemp('brotli_cli_roundtrip');
  }
}

String _consumeValue(List<String> args, int index, String flag) {
  if (index >= args.length) {
    _usage('Flag $flag expects a value');
  }
  return args[index];
}

Never _usage(String message) {
  stderr.writeln(message);
  stderr.writeln('''
Usage: dart run tool/brotli_cli_roundtrip.dart --input <file> [--window-bits <16-24>] [--keep-artifacts] [--work-dir <dir>]
''');
  exit(64);
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.lengthInBytes != b.lengthInBytes) {
    return false;
  }
  for (var i = 0; i < a.lengthInBytes; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}
