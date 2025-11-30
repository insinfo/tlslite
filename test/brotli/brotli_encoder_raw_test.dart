import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/brotlidecpy/bit_reader.dart';
import 'package:tlslite/src/utils/brotlidecpy/brotli_encoder.dart';
import 'package:tlslite/src/utils/brotlidecpy/decode.dart';

void main() {
  test('emits uncompressed meta-block header', () {
    final payload = Uint8List.fromList(List<int>.filled(32, 0xAB));
    final stream = brotliCompressRaw(payload);
    final reader = BrotliBitReader(stream);
    final windowBits = decodeWindowBits(reader);
    expect(windowBits, equals(16));

    final header = decodeMetaBlockLength(reader);
    expect(header.inputEnd, isFalse);
    expect(header.metaBlockLength, equals(payload.length));
    expect(header.isUncompressed, isTrue);
  });

  test('splits payload larger than single meta-block', () {
    final largePayload = Uint8List(brotliRawMaxChunkLength + 123);
    for (var i = 0; i < largePayload.length; i++) {
      largePayload[i] = (i * 29) & 0xFF;
    }
    final stream = brotliCompressRaw(largePayload, windowBits: 18);
    final lengths = _collectUncompressedBlockLengths(stream);
    expect(lengths, equals([brotliRawMaxChunkLength, 123]));
  });

  test('handles empty payloads', () {
    final stream = brotliCompressRaw(Uint8List(0));
    final lengths = _collectUncompressedBlockLengths(stream);
    expect(lengths, isEmpty);
  });

  test('stream decodes via brotli cli', () async {
    final payload = Uint8List.fromList(
      List<int>.generate(4096, (i) => (i * 13 + 5) & 0xFF),
    );
    final stream = brotliCompressRaw(payload);
    final decoded = await _roundTripThroughBrotliCli(stream);
    expect(decoded, equals(payload));
  }, skip: _brotliCliSkipReason);
}

Future<Uint8List> _roundTripThroughBrotliCli(Uint8List stream) async {
  final tempDir = await Directory.systemTemp.createTemp('brotli_cli_roundtrip_test');
  var shouldCleanup = false;
  try {
    final streamFile = File('${tempDir.path}/payload.br');
    await streamFile.writeAsBytes(stream, flush: true);

    final decodedFile = File('${tempDir.path}/decoded.bin');
    ProcessResult cliResult;
    try {
      cliResult = await Process.run('brotli', ['-d', '-f', '-o', decodedFile.path, streamFile.path]);
    } on ProcessException catch (error) {
      fail('brotli CLI is required for this test but was not found: ${error.message}');
    }

    if (cliResult.exitCode != 0) {
      fail('brotli CLI exited with ${cliResult.exitCode}: ${cliResult.stderr}');
    }

    final decoded = await decodedFile.readAsBytes();
    shouldCleanup = true;
    return decoded;
  } finally {
    if (shouldCleanup) {
      try {
        await tempDir.delete(recursive: true);
      } catch (_) {
        // Best-effort cleanup
      }
    }
  }
}

final String? _brotliCliSkipReason = _detectBrotliCli();

String? _detectBrotliCli() {
  try {
    final result = Process.runSync('brotli', ['--version']);
    if (result.exitCode != 0) {
      return 'brotli CLI exited with ${result.exitCode} during detection';
    }
    return null;
  } on ProcessException catch (error) {
    return 'brotli CLI not found: ${error.message}';
  }
}

List<int> _collectUncompressedBlockLengths(Uint8List stream) {
  final reader = BrotliBitReader(stream);
  decodeWindowBits(reader);
  final lengths = <int>[];
  var finished = false;
  while (!finished) {
    final meta = decodeMetaBlockLength(reader);
    if (meta.isMetadata) {
      reader.jumpToByteBoundary();
      reader.dropBytes(meta.metaBlockLength);
      finished = meta.inputEnd;
      continue;
    }
    if (!meta.isUncompressed) {
      throw StateError('Expected only uncompressed meta-blocks');
    }
    lengths.add(meta.metaBlockLength);
    reader.jumpToByteBoundary();
    reader.dropBytes(meta.metaBlockLength);
    finished = meta.inputEnd;
  }
  return lengths;
}
