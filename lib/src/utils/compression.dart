import 'dart:typed_data';

import '../constants.dart';
import '../errors.dart';
import 'brotlidecpy/brotli_encoder.dart';
import 'brotlidecpy/decode.dart';
import 'lists.dart';
import 'zstd/zstd_decoder.dart';
import 'zstd/zstd_encoder.dart';

/// Holds references to optional compression/decompression helpers.
///
/// Keys mirror the Python implementation so higher level code can probe for
/// availability (e.g., 'brotli_compress', 'zstd_accepts_limit').  Values are
/// nullable so the map can be filled dynamically by future platform specific
/// integrations.
final Map<String, dynamic> compressionAlgoImpls = {
  'brotli_compress': _brotliCompressAdapter,
  'brotli_decompress': _brotliDecompressAdapter,
  'brotli_accepts_limit': true,
  'zstd_compress': _zstdCompressAdapter,
  'zstd_decompress': _zstdDecompressAdapter,
  'zstd_accepts_limit': true,
};

Uint8List _brotliCompressAdapter(Uint8List input) {
  return brotliCompressRaw(input);
}

Uint8List _brotliDecompressAdapter(Uint8List input, [int? expectedOutputSize]) {
  return brotliDecompressBuffer(
    input,
    bufferLimit: expectedOutputSize,
  );
}

Uint8List _zstdCompressAdapter(Uint8List input) {
  return zstdCompress(input);
}

Uint8List _zstdDecompressAdapter(Uint8List input, [int? expectedOutputSize]) {
  return zstdDecompress(
    input,
    expectedOutputSize: expectedOutputSize,
  );
}

const Map<String, int> _compressionAlgoIds = {
  'zlib': CertificateCompressionAlgorithm.zlib,
  'brotli': CertificateCompressionAlgorithm.brotli,
  'zstd': CertificateCompressionAlgorithm.zstd,
};

bool _isAtLeastTls13((int, int) version) {
  return version.$1 > 3 || (version.$1 == 3 && version.$2 >= 4);
}

/// Implements the logic from tlslite-ng to select the certificate compression
/// algorithm advertised by both peers. Returns the numeric ID or null when no
/// overlap exists (or when TLS < 1.3 is negotiated).
int? chooseCompressionSendAlgo(
  (int, int)? version,
  dynamic extension,
  Iterable<String> validAlgos,
) {
  if (extension == null || version == null || !_isAtLeastTls13(version)) {
    return null;
  }

  final dynamic algorithmsField = extension.algorithms;
  final Iterable<int>? advertisedAlgorithms =
      algorithmsField == null ? null : List<int>.from(algorithmsField);

  if (advertisedAlgorithms == null || advertisedAlgorithms.isEmpty) {
    throw TLSDecodeError(
      'Empty algorithm list in compress_certificate extension',
    );
  }

  final supportedAlgorithms = <int>[];
  for (final algoName in validAlgos) {
    final id = _compressionAlgoIds[algoName];
    if (id != null) {
      supportedAlgorithms.add(id);
    }
  }

  if (supportedAlgorithms.isEmpty) {
    return null;
  }

  return getFirstMatching<int>(advertisedAlgorithms, supportedAlgorithms);
}
