import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/// Minimal hashlib-compatible helpers 
///
/// The original dart module ensures hashes still work in FIPS mode. For the
/// Dart port we expose a thin wrapper that mimics hashlib's API surface so the
/// rest of the TLS stack can request digests by algorithm string.
class TlsHash {
  TlsHash._(this.algorithm, this.digestSize, this.blockSize, List<int>? seed)
      : _buffer = seed != null ? List<int>.from(seed) : <int>[];

  final String algorithm;
  final int digestSize;
  final int blockSize;
  final List<int> _buffer;

  /// Feeds additional data into the digest.
  void update(List<int> data) {
    _buffer.addAll(data);
  }

  /// Produces the digest without mutating the internal buffer.
  Uint8List digest() {
    return Uint8List.fromList(_computeDigest(_buffer, algorithm));
  }

  /// Returns a copy of this hash object including buffered data.
  TlsHash copy() {
    return TlsHash._(algorithm, digestSize, blockSize, _buffer);
  }
}

/// Returns a hashlib-like object for [algorithm]. Optionally seeds it with
/// [data].
TlsHash newHash(String algorithm, [List<int>? data]) {
  final key = algorithm.toLowerCase();
  final impl = _hashImplementations[key];
  if (impl == null) {
    throw ArgumentError('Unsupported hash algorithm: $algorithm');
  }
  final hash = TlsHash._(key, impl.digestSize, impl.blockSize, null);
  if (data != null && data.isNotEmpty) {
    hash.update(data);
  }
  return hash;
}

/// Convenience constructor for MD5.
TlsHash md5([List<int>? data]) => newHash('md5', data);

class _HashImpl {
  const _HashImpl(this.digestSize, this.blockSize, this.compute);

  final int digestSize;
  final int blockSize;
  final List<int> Function(List<int>) compute;
}

List<int> _computeDigest(List<int> data, String algorithm) {
  final impl = _hashImplementations[algorithm];
  if (impl == null) {
    throw ArgumentError('Unsupported hash algorithm: $algorithm');
  }
  return impl.compute(data);
}

List<int> _digestBytes(List<int> data, crypto.Hash hash) {
  return hash.convert(data).bytes;
}

final Map<String, _HashImpl> _hashImplementations = {
  'md5': _HashImpl(16, 64, (data) => _digestBytes(data, crypto.md5)),
  'sha1': _HashImpl(20, 64, (data) => _digestBytes(data, crypto.sha1)),
  'sha224': _HashImpl(28, 64, (data) => _digestBytes(data, crypto.sha224)),
  'sha256': _HashImpl(32, 64, (data) => _digestBytes(data, crypto.sha256)),
  'sha384': _HashImpl(48, 128, (data) => _digestBytes(data, crypto.sha384)),
  'sha512': _HashImpl(64, 128, (data) => _digestBytes(data, crypto.sha512)),
};
