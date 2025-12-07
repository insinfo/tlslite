import 'dart:typed_data';

import 'chacha.dart';
import 'constanttime.dart';
import 'poly1305.dart';

class Chacha20Poly1305 {
  Chacha20Poly1305(Uint8List key, this.implementation)
      : key = Uint8List.fromList(key) {
    if (key.length != 32) {
      throw ArgumentError('ChaCha20-Poly1305 key must be 32 bytes long');
    }
    if (implementation != 'dart') {
      throw ArgumentError('Unsupported implementation: $implementation');
    }
  }

  final bool isBlockCipher = false;
  final bool isAEAD = true;
  final int nonceLength = 12;
  final int tagLength = 16;
  final String implementation;
  final String name = 'chacha20-poly1305';
  final Uint8List key;

  static Uint8List poly1305KeyGen(Uint8List key, Uint8List nonce) {
    final chaCha = ChaCha(key, nonce);
    return chaCha.encrypt(Uint8List(32));
  }

  static Uint8List pad16(Uint8List data) {
    final remainder = data.length % 16;
    if (remainder == 0) {
      return Uint8List(0);
    }
    return Uint8List(16 - remainder);
  }

  Uint8List seal(
      Uint8List nonce, Uint8List plaintext, Uint8List associatedData) {
    if (nonce.length != nonceLength) {
      throw ArgumentError('Nonce must be $nonceLength bytes long');
    }
    final otk = poly1305KeyGen(key, nonce);
    final ciphertext = ChaCha(key, nonce, initialCounter: 1).encrypt(plaintext);
    final macData = _buildMacData(associatedData, ciphertext);
    final tag = Poly1305(otk).createTag(macData);
    return Uint8List.fromList([...ciphertext, ...tag]);
  }

  Uint8List? open(
      Uint8List nonce, Uint8List ciphertextWithTag, Uint8List associatedData) {
    if (nonce.length != nonceLength) {
      throw ArgumentError('Nonce must be $nonceLength bytes long');
    }
    if (ciphertextWithTag.length < tagLength) {
      return null;
    }
    final tag = ciphertextWithTag.sublist(ciphertextWithTag.length - tagLength);
    final ciphertext =
        ciphertextWithTag.sublist(0, ciphertextWithTag.length - tagLength);
    final otk = poly1305KeyGen(key, nonce);
    final macData = _buildMacData(associatedData, ciphertext);
    final expectedTag = Poly1305(otk).createTag(macData);
    if (!ctCompareDigest(expectedTag, tag)) {
      return null;
    }
    return ChaCha(key, nonce, initialCounter: 1).decrypt(ciphertext);
  }

  Uint8List _buildMacData(Uint8List aad, Uint8List ciphertext) {
    final builder = BytesBuilder(copy: false);
    builder.add(aad);
    final aadPad = pad16(aad);
    if (aadPad.isNotEmpty) {
      builder.add(aadPad);
    }
    builder.add(ciphertext);
    final cipherPad = pad16(ciphertext);
    if (cipherPad.isNotEmpty) {
      builder.add(cipherPad);
    }
    builder.add(_packUint64(aad.length));
    builder.add(_packUint64(ciphertext.length));
    return builder.toBytes();
  }

  Uint8List _packUint64(int value) {
    final data = ByteData(8);
    data.setUint64(0, value, Endian.little);
    return data.buffer.asUint8List();
  }
}
