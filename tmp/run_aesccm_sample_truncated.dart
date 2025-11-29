import 'dart:typed_data';

import 'package:tlslite/src/utils/python_aesccm.dart' as python_aesccm;

void main() {
  final key = hex('feffe9928665731c6d6a8f9467308308');
  final nonce = hex('cafebabefacedbaddecaf888');
  final aad = hex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
  final plaintext = hex(
      '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b4179e66c3710');
  final aes = python_aesccm.newAESCCM(key, tagLength: 8);
  final ciphertext = aes.seal(nonce, plaintext, aad);
  print(toHex(ciphertext));
  final decrypted = aes.open(nonce, ciphertext, aad);
  print(toHex(decrypted ?? Uint8List(0)));
}

Uint8List hex(String data) {
  final cleaned = data.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
  final out = Uint8List(cleaned.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(cleaned.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String toHex(Uint8List data) =>
    data.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
