import 'dart:typed_data';

import 'aes.dart';
import 'cryptomath.dart';
import 'dart_aes.dart' as dart_aes;

class AESCCM {
  AESCCM(
    Uint8List key,
    this.implementation,
    RawAesEncrypt rawAesEncrypt, {
    this.tagLength = 16,
  })  : key = Uint8List.fromList(key),
        _rawAesEncrypt = rawAesEncrypt {
    if (this.key.length != 16 && this.key.length != 32) {
      throw ArgumentError('AES-CCM key must be 16 or 32 bytes long');
    }
    if (tagLength != 8 && tagLength != 16) {
      throw ArgumentError('AES-CCM tag length must be 8 or 16 bytes');
    }

    if (this.key.length == 16 && tagLength == 8) {
      name = 'aes128ccm_8';
    } else if (this.key.length == 16 && tagLength == 16) {
      name = 'aes128ccm';
    } else if (this.key.length == 32 && tagLength == 8) {
      name = 'aes256ccm_8';
    } else {
      name = 'aes256ccm';
    }

    _ctr = dart_aes.Dart_AES_CTR.Dart_AES_CTR(
      Uint8List.fromList(this.key),
      aesModeCTR_OR_GCM,
      Uint8List(16),
    );
    _cbc = dart_aes.Dart_AES(
      Uint8List.fromList(this.key),
      aesModeCBC,
      Uint8List(16),
    );
  }

  final bool isBlockCipher = false;
  final bool isAEAD = true;
  final int nonceLength = 12;
  final String implementation;
  late final String name;
  final Uint8List key;
  final int tagLength;
  // ignore: unused_field
  final RawAesEncrypt _rawAesEncrypt;

  late final dart_aes.Dart_AES_CTR _ctr;
  late final dart_aes.Dart_AES _cbc;

  Uint8List seal(Uint8List nonce, Uint8List msg, Uint8List aad) {
    _checkNonce(nonce);
    final l = 15 - nonce.length;
    final counter = _buildCounter(nonce, BigInt.zero, l);

    final mac = _cbcmacCalc(nonce, aad, msg);
    _ctr.counter = counter;
    late Uint8List authValue;
    if (tagLength == 16) {
      authValue = _ctr.encrypt(mac);
    } else {
      final paddedMac = _padWithZeroes(mac, 16);
      authValue = _ctr.encrypt(paddedMac).sublist(0, tagLength);
    }
    final encMsg = _ctr.encrypt(msg);
    return Uint8List.fromList([...encMsg, ...authValue]);
  }

  Uint8List? open(Uint8List nonce, Uint8List ciphertext, Uint8List aad) {
    _checkNonce(nonce);
    if (ciphertext.length < tagLength) {
      return null;
    }

    final l = 15 - nonce.length;
    final counter = _buildCounter(nonce, BigInt.zero, l);
    final authValue = ciphertext.sublist(ciphertext.length - tagLength);

    _ctr.counter = counter;
    late Uint8List receivedMac;
    if (tagLength == 16) {
      receivedMac = _ctr.decrypt(authValue);
    } else {
      final paddedAuth = _padWithZeroes(authValue, 16);
      receivedMac = _ctr.decrypt(paddedAuth).sublist(0, tagLength);
    }

    final decrypted = _ctr.decrypt(ciphertext);
    final msg = decrypted.sublist(0, decrypted.length - tagLength);
    final computedMac = _cbcmacCalc(nonce, aad, msg);

    if (!_constantTimeEquals(receivedMac, computedMac)) {
      return null;
    }
    return msg;
  }

  void _checkNonce(Uint8List nonce) {
    if (nonce.length != nonceLength) {
      throw ArgumentError('Bad nonce length');
    }
  }

  Uint8List _cbcmacCalc(Uint8List nonce, Uint8List aad, Uint8List msg) {
    final l = 15 - nonce.length;
    final hasAad = aad.isNotEmpty ? 1 : 0;
    final flags = (hasAad << 6) + (((tagLength - 2) ~/ 2) << 3) + (l - 1);

    final block = Uint8List(1 + nonce.length + l)
      ..[0] = flags
      ..setRange(1, 1 + nonce.length, nonce)
      ..setRange(
        1 + nonce.length,
        1 + nonce.length + l,
        numberToByteArray(BigInt.from(msg.length), howManyBytes: l),
      );

    Uint8List macInput = block;
    if (aad.isNotEmpty) {
      final aadHeader = _encodeAadLength(aad.length);
      final builder = BytesBuilder()
        ..add(macInput)
        ..add(aadHeader)
        ..add(aad);
      macInput = builder.toBytes();
    }

    macInput = _padWithZeroes(macInput, 16);
    if (msg.isNotEmpty) {
      final msgBuilder = BytesBuilder()
        ..add(macInput)
        ..add(msg);
      macInput = _padWithZeroes(msgBuilder.toBytes(), 16);
    }

    _cbc.iv = Uint8List(16);
    final cbcmac = _cbc.encrypt(macInput);
    final start = cbcmac.length - 16;
    return cbcmac.sublist(start, start + tagLength);
  }

  Uint8List _encodeAadLength(int length) {
    if (length < (1 << 16) - (1 << 8)) {
      return numberToByteArray(BigInt.from(length), howManyBytes: 2);
    }
    if (length < (1 << 32)) {
      final prefix = Uint8List.fromList([0xff, 0xfe]);
      final encoded = numberToByteArray(BigInt.from(length), howManyBytes: 4);
      return Uint8List.fromList([...prefix, ...encoded]);
    }
    final prefix = Uint8List.fromList([0xff, 0xff]);
    final encoded = numberToByteArray(BigInt.from(length), howManyBytes: 8);
    return Uint8List.fromList([...prefix, ...encoded]);
  }

  Uint8List _buildCounter(Uint8List nonce, BigInt value, int l) {
    final counter = Uint8List(16);
    counter[0] = l - 1;
    counter.setRange(1, 1 + nonce.length, nonce);
    final suffix = numberToByteArray(value, howManyBytes: l);
    counter.setRange(1 + nonce.length, 16, suffix);
    return counter;
  }

  Uint8List _padWithZeroes(Uint8List data, int size) {
    final remainder = data.length % size;
    if (remainder == 0) {
      return data;
    }
    final padded = Uint8List(data.length + (size - remainder))
      ..setRange(0, data.length, data);
    return padded;
  }

  bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) {
      return false;
    }
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
