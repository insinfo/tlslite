import 'dart:math';
import 'dart:typed_data';

/// Poly1305 authenticator per RFC 7539.
class Poly1305 {
  Poly1305(Uint8List key)
      : _acc = BigInt.zero,
        _r = _deriveR(key),
        _s = _deriveS(key);

  static final BigInt _p = BigInt.parse('0x3fffffffffffffffffffffffffffffffb');
  static final BigInt _rMask =
      BigInt.parse('0x0ffffffc0ffffffc0ffffffc0fffffff');

  BigInt _acc;
  final BigInt _r;
  final BigInt _s;

  static BigInt _deriveR(Uint8List key) {
    _ensureKeyLength(key);
    return _maskR(_leBytesToNum(key.sublist(0, 16)));
  }

  static BigInt _deriveS(Uint8List key) {
    _ensureKeyLength(key);
    return _leBytesToNum(key.sublist(16, 32));
  }

  static void _ensureKeyLength(Uint8List key) {
    if (key.length != 32) {
      throw ArgumentError('Poly1305 key must be 32 bytes long');
    }
  }

  static BigInt _maskR(BigInt value) {
    return value & _rMask;
  }

  static BigInt _leBytesToNum(Uint8List bytes) {
    BigInt result = BigInt.zero;
    for (var i = bytes.length - 1; i >= 0; i--) {
      result = (result << 8) + BigInt.from(bytes[i]);
    }
    return result;
  }

  static Uint8List _numTo16LeBytes(BigInt value) {
    final out = Uint8List(16);
    var temp = value;
    for (var i = 0; i < 16; i++) {
      out[i] = (temp & BigInt.from(0xff)).toInt();
      temp = temp >> 8;
    }
    return out;
  }

  /// Exposed for testing compatibility with Python helper.
  static BigInt leBytesToNum(Uint8List bytes) => _leBytesToNum(bytes);
  static Uint8List numTo16LeBytes(BigInt value) => _numTo16LeBytes(value);

  Uint8List createTag(Uint8List data) {
    final blocks = (data.length + 15) ~/ 16;
    for (var i = 0; i < blocks; i++) {
      final start = i * 16;
      final end = min(start + 16, data.length);
      final chunkLen = end - start;
      final block = Uint8List(chunkLen + 1);
      block.setRange(0, chunkLen, data.sublist(start, end));
      block[chunkLen] = 0x01;
      final n = _leBytesToNum(block);
      _acc += n;
      _acc = (_r * _acc) % _p;
    }
    _acc += _s;
    return _numTo16LeBytes(_acc);
  }
}
