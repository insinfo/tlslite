import 'dart:typed_data';

import 'aes.dart';
import 'constanttime.dart';
import 'cryptomath.dart';
import 'python_aes.dart' as python_aes;

/// Pure Dart port of tlslite's AES-GCM implementation (slow, but dependency-free).
class AESGCM {
  AESGCM(Uint8List key, this.implementation, RawAesEncrypt rawAesEncrypt)
      : key = Uint8List.fromList(key),
        _rawAesEncrypt = rawAesEncrypt {
    if (key.length == 16) {
      name = 'aes128gcm';
    } else if (key.length == 32) {
      name = 'aes256gcm';
    } else {
      throw ArgumentError('AES-GCM key must be 16 or 32 bytes long');
    }
    _ctr = python_aes.Python_AES_CTR(
      Uint8List.fromList(this.key),
      aesModeCTR_OR_GCM,
      Uint8List(16),
    );
    _productTable = List<BigInt>.filled(16, BigInt.zero);
    final h = bytesToNumber(_rawAesEncrypt(Uint8List(16)));
    _productTable[_reverseBits(1)] = h;
    for (var i = 2; i < 16; i += 2) {
      _productTable[_reverseBits(i)] =
          _gcmShift(_productTable[_reverseBits(i ~/ 2)]);
      _productTable[_reverseBits(i + 1)] =
          _gcmAdd(_productTable[_reverseBits(i)], h);
    }
  }

  final bool isBlockCipher = false;
  final bool isAEAD = true;
  final int nonceLength = 12;
  final int tagLength = 16;
  final String implementation;
  late final String name;
  final Uint8List key;

  final RawAesEncrypt _rawAesEncrypt;
  late final python_aes.Python_AES_CTR _ctr;
  late final List<BigInt> _productTable;

  Uint8List seal(Uint8List nonce, Uint8List plaintext, Uint8List data) {
    _checkNonce(nonce);
    final tagCounter = _buildCounter(nonce, 1);
    final tagMask = _rawAesEncrypt(tagCounter);
    final encCounter = _buildCounter(nonce, 2);
    _ctr.counter = encCounter;
    final ciphertext = _ctr.encrypt(plaintext);
    final tag = _auth(ciphertext, data, tagMask);
    return Uint8List.fromList([...ciphertext, ...tag]);
  }

  Uint8List? open(
      Uint8List nonce, Uint8List ciphertextWithTag, Uint8List data) {
    _checkNonce(nonce);
    if (ciphertextWithTag.length < tagLength) {
      return null;
    }
    final tag = ciphertextWithTag.sublist(ciphertextWithTag.length - tagLength);
    final ciphertext =
        ciphertextWithTag.sublist(0, ciphertextWithTag.length - tagLength);

    final tagCounter = _buildCounter(nonce, 1);
    final tagMask = _rawAesEncrypt(tagCounter);
    final calculated = _auth(ciphertext, data, tagMask);
    if (!ctCompareDigest(calculated, tag)) {
      return null;
    }

    final encCounter = _buildCounter(nonce, 2);
    _ctr.counter = encCounter;
    return _ctr.decrypt(ciphertext);
  }

  void _checkNonce(Uint8List nonce) {
    if (nonce.length != nonceLength) {
      throw ArgumentError('Bad nonce length');
    }
  }

  Uint8List _buildCounter(Uint8List nonce, int initialValue) {
    final counter = Uint8List(16);
    counter.setRange(0, nonceLength, nonce);
    counter[12] = (initialValue >> 24) & 0xff;
    counter[13] = (initialValue >> 16) & 0xff;
    counter[14] = (initialValue >> 8) & 0xff;
    counter[15] = initialValue & 0xff;
    return counter;
  }

  Uint8List _auth(Uint8List ciphertext, Uint8List ad, Uint8List tagMask) {
    var y = BigInt.zero;
    y = _update(y, ad);
    y = _update(y, ciphertext);
    y ^= (BigInt.from(ad.length) << 67) | (BigInt.from(ciphertext.length) << 3);
    y = _mul(y);
    y ^= bytesToNumber(tagMask);
    return numberToByteArray(y, howManyBytes: 16);
  }

  BigInt _update(BigInt y, Uint8List data) {
    var result = y;
    final fullBlocks = data.length ~/ 16;
    for (var i = 0; i < fullBlocks; i++) {
      final block = data.sublist(i * 16, i * 16 + 16);
      result ^= bytesToNumber(block);
      result = _mul(result);
    }
    final extra = data.length % 16;
    if (extra != 0) {
      final block = Uint8List(16);
      block.setRange(0, extra, data.sublist(data.length - extra));
      result ^= bytesToNumber(block);
      result = _mul(result);
    }
    return result;
  }

  BigInt _mul(BigInt y) {
    var ret = BigInt.zero;
    var val = y;
    for (var i = 0; i < 128; i += 4) {
      final retHigh = (ret & BigInt.from(0xf)).toInt();
      ret >>= 4;
      ret ^= (BigInt.from(_gcmReductionTable[retHigh]) << (128 - 16));
      final idx = (val & BigInt.from(0xf)).toInt();
      ret ^= _productTable[idx];
      val >>= 4;
    }
    return ret;
  }

  static int _reverseBits(int value) {
    assert(value < 16);
    var i = value & 0xf;
    i = ((i << 2) & 0xc) | ((i >> 2) & 0x3);
    i = ((i << 1) & 0xa) | ((i >> 1) & 0x5);
    return i;
  }

  static BigInt _gcmAdd(BigInt x, BigInt y) => x ^ y;

  static BigInt _gcmShift(BigInt x) {
    final highTermSet = (x & BigInt.one) == BigInt.one;
    var result = x >> 1;
    if (highTermSet) {
      result ^= BigInt.from(0xe1) << (128 - 8);
    }
    return result;
  }

  static const List<int> _gcmReductionTable = <int>[
    0x0000,
    0x1c20,
    0x3840,
    0x2460,
    0x7080,
    0x6ca0,
    0x48c0,
    0x54e0,
    0xe100,
    0xfd20,
    0xd940,
    0xc560,
    0x9180,
    0x8da0,
    0xa9c0,
    0xb5e0,
  ];
}
