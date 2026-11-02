import 'dart:typed_data';

import 'message_digest.dart';

/// HMAC (RFC 2104) over any [MessageDigest].
///
/// The inner and outer pads are absorbed once at construction, so [clone]
/// (used per TLS record) only copies two small hash states.
class Hmac {
  /// Creates an HMAC keyed with [key]. [digest] is used as a prototype: it is
  /// reset and owned by this object.
  Hmac(MessageDigest digest, List<int> key)
      : _innerInit = digest..reset(),
        _outerInit = digest.clone() {
    final bs = digest.blockSize;
    var k = key is Uint8List ? key : Uint8List.fromList(key);
    if (k.length > bs) {
      final h = digest.clone()..update(k);
      k = h.finish();
    }
    final pad = Uint8List(bs);
    pad.setRange(0, k.length, k);
    for (var i = 0; i < bs; i++) {
      pad[i] ^= 0x36;
    }
    _innerInit.update(pad);
    for (var i = 0; i < bs; i++) {
      pad[i] ^= 0x36 ^ 0x5c;
    }
    _outerInit.update(pad);
    pad.fillRange(0, bs, 0);
    _inner = _innerInit.clone();
  }

  Hmac._clone(this._innerInit, this._outerInit, this._inner);

  /// State after absorbing `key ^ ipad`.
  final MessageDigest _innerInit;

  /// State after absorbing `key ^ opad`.
  final MessageDigest _outerInit;

  /// Running inner hash.
  late MessageDigest _inner;

  String get algorithm => _inner.algorithm;

  int get digestSize => _inner.digestSize;

  int get blockSize => _inner.blockSize;

  void update(List<int> data, [int start = 0, int? end]) =>
      _inner.update(data, start, end);

  /// Returns the MAC of the data so far without altering the state.
  Uint8List digest() {
    final innerHash = _inner.digest();
    return (_outerInit.clone()..update(innerHash)).finish();
  }

  /// Returns the MAC and resets to the keyed initial state.
  Uint8List finish() {
    final innerHash = _inner.finish();
    _inner = _innerInit.clone();
    return (_outerInit.clone()..update(innerHash)).finish();
  }

  /// Resets to the keyed initial state (the key is kept).
  void reset() {
    _inner = _innerInit.clone();
  }

  /// Returns an independent copy of the current state. The keyed initial
  /// states are immutable and shared.
  Hmac clone() => Hmac._clone(_innerInit, _outerInit, _inner.clone());
}
