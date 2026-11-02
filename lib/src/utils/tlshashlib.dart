// Ported to Dart from tlslite-ng tlslite/utils/tlshashlib.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:typed_data';

import 'digest/digest.dart';

/// Minimal hashlib-compatible helpers
///
/// The original dart module ensures hashes still work in FIPS mode. For the
/// Dart port we expose a thin wrapper that mimics hashlib's API surface so the
/// rest of the TLS stack can request digests by algorithm string.
class TlsHash {
  TlsHash._(this.algorithm, this._digest);

  final String algorithm;
  final MessageDigest _digest;

  int get digestSize => _digest.digestSize;

  int get blockSize => _digest.blockSize;

  /// Feeds additional data into the digest.
  void update(List<int> data) {
    _digest.update(data);
  }

  /// Produces the digest without mutating the internal state.
  Uint8List digest() {
    return _digest.digest();
  }

  /// Returns a copy of this hash object including absorbed data.
  TlsHash copy() {
    return TlsHash._(algorithm, _digest.clone());
  }
}

/// Returns a hashlib-like object for [algorithm]. Optionally seeds it with
/// [data].
TlsHash newHash(String algorithm, [List<int>? data]) {
  final key = algorithm.toLowerCase();
  final impl = tryCreateDigest(key);
  if (impl == null) {
    throw ArgumentError('Unsupported hash algorithm: $algorithm');
  }
  final hash = TlsHash._(key, impl);
  if (data != null && data.isNotEmpty) {
    hash.update(data);
  }
  return hash;
}

/// Convenience constructor for MD5.
TlsHash md5([List<int>? data]) => newHash('md5', data);
