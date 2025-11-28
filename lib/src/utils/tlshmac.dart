import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

import 'tlshashlib.dart';

/// Minimal HMAC helper compatible with tlslite's tlshmac module.
class TlsHmac {
  TlsHmac(List<int> key, {dynamic digestmod, List<int>? message})
      : _algorithm = _resolveAlgorithm(digestmod),
        _key = Uint8List.fromList(key),
        _buffer = BytesBuilder() {
    if (message != null && message.isNotEmpty) {
      update(message);
    }
  }

  final String _algorithm;
  final Uint8List _key;
  final BytesBuilder _buffer;

  /// Appends data into the HMAC stream.
  void update(List<int> data) {
    _buffer.add(data);
  }

  /// Returns the HMAC digest for the data seen so far.
  Uint8List digest() {
    final mac = crypto.Hmac(_selectHash(_algorithm), _key);
    return Uint8List.fromList(mac.convert(_buffer.toBytes()).bytes);
  }

  /// Returns a copy of the current HMAC state.
  TlsHmac copy() {
    final snapshot = _buffer.toBytes();
    final clone = TlsHmac(_key, digestmod: _algorithm);
    if (snapshot.isNotEmpty) {
      clone.update(snapshot);
    }
    return clone;
  }
}

/// Convenience constructor mimicking Python's `hmac.new` helper.
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

crypto.Hash _selectHash(String algorithm) {
  switch (algorithm) {
    case 'md5':
      return crypto.md5;
    case 'sha1':
      return crypto.sha1;
    case 'sha224':
      return crypto.sha224;
    case 'sha256':
      return crypto.sha256;
    case 'sha384':
      return crypto.sha384;
    case 'sha512':
      return crypto.sha512;
    default:
      throw ArgumentError('Unsupported HMAC algorithm: $algorithm');
  }
}
