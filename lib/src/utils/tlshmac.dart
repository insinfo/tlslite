// Ported to Dart from tlslite-ng tlslite/utils/tlshmac.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:typed_data';

import 'digest/digest.dart';
import 'tlshashlib.dart';

/// Minimal HMAC helper compatible
class TlsHmac {
  TlsHmac(List<int> key, {dynamic digestmod, List<int>? message})
      : this._(createHmac(_resolveAlgorithm(digestmod), key), message);

  TlsHmac._(this._mac, [List<int>? message]) {
    if (message != null && message.isNotEmpty) {
      update(message);
    }
  }

  final Hmac _mac;

  int get digestSize => _mac.digestSize;

  int get blockSize => _mac.blockSize;

  /// Appends data into the HMAC stream.
  void update(List<int> data) {
    _mac.update(data);
  }

  /// Returns the HMAC digest for the data seen so far.
  Uint8List digest() {
    return _mac.digest();
  }

  /// Returns a copy of the current HMAC state.
  TlsHmac copy() {
    return TlsHmac._(_mac.clone());
  }
}

/// Convenience constructor mimicking dart's `hmac.new` helper.
TlsHmac newHmac(List<int> key, {dynamic digestmod, List<int>? message}) {
  return TlsHmac(key, digestmod: digestmod, message: message);
}

/// Constant-time comparison between two digests.
bool compareDigest(List<int> left, List<int> right) {
  if (left.length != right.length) {
    return false;
  }
  var result = 0;
  for (var i = 0; i < left.length; i++) {
    result |= (left[i] ^ right[i]);
  }
  return result == 0;
}

String _resolveAlgorithm(dynamic digestmod) {
  if (digestmod == null) {
    return 'md5';
  }
  if (digestmod is String) {
    return digestmod.toLowerCase();
  }
  if (digestmod is TlsHash) {
    return digestmod.algorithm;
  }
  throw ArgumentError('Unsupported digest spec: ${digestmod.runtimeType}');
}
