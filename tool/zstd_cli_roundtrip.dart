import 'dart:io';
import 'dart:typed_data';

import 'package:tlslite/src/utils/zstd/dictionary.dart';
import 'package:tlslite/src/utils/zstd/zstd_encoder.dart';

Future<void> main(List<String> args) async {
  final config = _CliConfig.parse(args);
  final payload = await File(config.inputPath).readAsBytes();

  ZstdDictionary? dictionary;
  final dictPath = config.dictPath;
  if (dictPath != null) {
    final dictBytes = await File(dictPath).readAsBytes();
    dictionary = parseZstdDictionary(Uint8List.fromList(dictBytes));
  }

  final frame = zstdCompress(
    Uint8List.fromList(payload),
    includeChecksum: config.includeChecksum,
    dictionary: dictionary,
  );

  final workDir = await config.prepareWorkingDirectory();
  final frameFile = File('${workDir.path}/frame.zst');
  await frameFile.writeAsBytes(frame, flush: true);
  final decodedFile = File('${workDir.path}/decoded.bin');

  final argsList = <String>[
    '-d',
    '--single-thread',
    '--no-progress',
    '-f',
    '-o',
    decodedFile.path,
  ];
  if (dictPath != null) {
    argsList..add('-D')..add(dictPath);
  }
  argsList.add(frameFile.path);

  ProcessResult cliResult;
  try {
    cliResult = await Process.run('zstd', argsList);
  } on ProcessException catch (error) {
    stderr.writeln('Failed to launch zstd CLI: ${error.message}');
    stderr.writeln('Artifacts kept at ${workDir.path}');
    exit(2);
  }

  if (cliResult.exitCode != 0) {
    stderr.writeln('zstd CLI exited with ${cliResult.exitCode}');
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

  stdout.writeln('Roundtrip succeeded (${payloadBytes.length} bytes, checksum=${config.includeChecksum})');
  if (!config.keepArtifacts && config.workDir == null) {
    await workDir.delete(recursive: true);
  } else {
    stdout.writeln('Artifacts preserved at ${workDir.path}');
  }
}

class _CliConfig {
  _CliConfig({
    required this.inputPath,
    this.dictPath,
    required this.includeChecksum,
    required this.keepArtifacts,
    this.workDir,
  });

  final String inputPath;
  final String? dictPath;
  final bool includeChecksum;
  final bool keepArtifacts;
  final String? workDir;

  static _CliConfig parse(List<String> args) {
    String? inputPath;
    String? dictPath;
    String? workDir;
    var includeChecksum = false;
    var keepArtifacts = false;

    for (var i = 0; i < args.length; i++) {
      final arg = args[i];
      switch (arg) {
        case '--checksum':
          includeChecksum = true;
          continue;
        case '--keep-artifacts':
          keepArtifacts = true;
          continue;
        case '--input':
          inputPath = _consumeValue(args, ++i, '--input');
          continue;
        case '--dict':
          dictPath = _consumeValue(args, ++i, '--dict');
          continue;
        case '--work-dir':
          workDir = _consumeValue(args, ++i, '--work-dir');
          continue;
      }

      if (arg.startsWith('--input=')) {
        inputPath = arg.substring('--input='.length);
        continue;
      }
      if (arg.startsWith('--dict=')) {
        dictPath = arg.substring('--dict='.length);
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
      dictPath: dictPath,
      includeChecksum: includeChecksum,
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
    return Directory.systemTemp.createTemp('zstd_cli_roundtrip');
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
Usage: dart run tool/zstd_cli_roundtrip.dart --input <file> [--dict <dictFile>] [--checksum] [--keep-artifacts] [--work-dir <dir>]
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
