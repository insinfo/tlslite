import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/aesccm.dart';
import 'package:tlslite/src/utils/cipherfactory.dart' as cipherfactory;
import 'package:tlslite/src/utils/python_aesccm.dart' as python_aesccm;

void main() {
  group('AESCCM', () {
    test('constructor names for 128-bit key', () {
      final aes = python_aesccm.newAESCCM(Uint8List(16));
      expect(aes.name, equals('aes128ccm'));
      expect(aes.tagLength, equals(16));
      expect(aes.implementation, equals('python'));
    });

    test('constructor names for 128-bit key truncated tag', () {
      final aes = python_aesccm.newAESCCM(Uint8List(16), tagLength: 8);
      expect(aes.name, equals('aes128ccm_8'));
      expect(aes.tagLength, equals(8));
    });

    test('constructor names for 256-bit key', () {
      final aes = python_aesccm.newAESCCM(Uint8List(32));
      expect(aes.name, equals('aes256ccm'));
    });

    test('constructor names for 256-bit key truncated tag', () {
      final aes = python_aesccm.newAESCCM(Uint8List(32), tagLength: 8);
      expect(aes.name, equals('aes256ccm_8'));
    });

    test('constructor rejects invalid key length', () {
      expect(() => python_aesccm.newAESCCM(Uint8List(8)), throwsArgumentError);
    });

    test('factory prefers python implementation', () {
      final aes = cipherfactory.createAESCCM(Uint8List(16));
      expect(aes.implementation, equals('python'));
    });

    test('factory prefers python implementation for AES-CCM-8', () {
      final aes = cipherfactory.createAESCCM8(Uint8List(16));
      expect(aes.implementation, equals('python'));
      expect(aes.tagLength, equals(8));
    });

    test('seal basic example (AES128)', () {
      final aes = python_aesccm
          .newAESCCM(Uint8List.fromList(List<int>.filled(16, 0x01)));
      final nonce = Uint8List.fromList(List<int>.filled(12, 0x02));
      final ciphertext =
          aes.seal(nonce, asciiBytes('text to encrypt.'), Uint8List(0));
      expect(
          ciphertext,
          equals(hex(
              '257d512e99a30daecb4d63f2162c5effa0498ef9c9463ebfa400590270e3b8a2')));
    });

    test('seal basic example (AES256)', () {
      final aes = python_aesccm
          .newAESCCM(Uint8List.fromList(List<int>.filled(32, 0x01)));
      final nonce = Uint8List.fromList(List<int>.filled(12, 0x02));
      final ciphertext =
          aes.seal(nonce, asciiBytes('text to encrypt.'), Uint8List(0));
      expect(
          ciphertext,
          equals(hex(
              '494e1c06b80b3953443cf8524cb42c3dd62664ae5e31f8bffa384498dd14b531')));
    });

    test('seal truncated tag example (AES128)', () {
      final aes = python_aesccm.newAESCCM(
        Uint8List.fromList(List<int>.filled(16, 0x01)),
        tagLength: 8,
      );
      final nonce = Uint8List.fromList(List<int>.filled(12, 0x02));
      final ciphertext =
          aes.seal(nonce, asciiBytes('text to encrypt.'), Uint8List(0));
      expect(ciphertext,
          equals(hex('257d512e99a30daecb4d63f2162c5eff14b82d3f7fac8b49')));
    });

    test('seal truncated tag example (AES256)', () {
      final aes = python_aesccm.newAESCCM(
        Uint8List.fromList(List<int>.filled(32, 0x01)),
        tagLength: 8,
      );
      final nonce = Uint8List.fromList(List<int>.filled(12, 0x02));
      final ciphertext =
          aes.seal(nonce, asciiBytes('text to encrypt.'), Uint8List(0));
      expect(ciphertext,
          equals(hex('494e1c06b80b3953443cf8524cb42c3da291846a312a0feb')));
    });

    test('seal throws on invalid nonce length', () {
      final aes = python_aesccm
          .newAESCCM(Uint8List.fromList(List<int>.filled(16, 0x01)));
      expect(
        () => aes.seal(
            Uint8List(11), asciiBytes('text to encrypt.'), Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('open basic example (AES128)', () {
      final aes = python_aesccm
          .newAESCCM(Uint8List.fromList(List<int>.filled(16, 0x01)));
      final nonce = Uint8List.fromList(List<int>.filled(12, 0x02));
      final plaintext = aes.open(
        nonce,
        hex('257d512e99a30daecb4d63f2162c5effa0498ef9c9463ebfa400590270e3b8a2'),
        Uint8List(0),
      );
      expect(plaintext, equals(asciiBytes('text to encrypt.')));
    });

    test('open truncated tag example (AES128)', () {
      final aes = python_aesccm.newAESCCM(
        Uint8List.fromList(List<int>.filled(16, 0x01)),
        tagLength: 8,
      );
      final nonce = Uint8List.fromList(List<int>.filled(12, 0x02));
      final plaintext = aes.open(
        nonce,
        hex('257d512e99a30daecb4d63f2162c5eff14b82d3f7fac8b49'),
        Uint8List(0),
      );
      expect(plaintext, equals(asciiBytes('text to encrypt.')));
    });

    test('open returns null with incorrect key', () {
      final key = Uint8List.fromList(List<int>.filled(16, 0x01));
      final good = python_aesccm.newAESCCM(key);
      final badKey =
          Uint8List.fromList(List<int>.filled(16, 0x01)..[15] = 0x00);
      final bad = python_aesccm.newAESCCM(badKey);
      final nonce = Uint8List.fromList(List<int>.filled(12, 0x02));
      final ciphertext =
          good.seal(nonce, asciiBytes('text to encrypt.'), Uint8List(0));
      expect(bad.open(nonce, ciphertext, Uint8List(0)), isNull);
    });

    test('open returns null with incorrect nonce', () {
      final key = Uint8List.fromList(List<int>.filled(16, 0x01));
      final aes = python_aesccm.newAESCCM(key);
      final nonce = Uint8List.fromList(List<int>.filled(12, 0x02));
      final ciphertext =
          aes.seal(nonce, asciiBytes('text to encrypt.'), Uint8List(0));
      final otherNonce =
          Uint8List.fromList(List<int>.filled(11, 0x02) + [0x03]);
      expect(aes.open(otherNonce, ciphertext, Uint8List(0)), isNull);
    });

    test('open throws on invalid nonce length', () {
      final aes = python_aesccm.newAESCCM(Uint8List(16));
      expect(
        () => aes.open(Uint8List(11), Uint8List(16), Uint8List(0)),
        throwsArgumentError,
      );
    });

    test('open returns null for short ciphertext', () {
      final aes = python_aesccm.newAESCCM(Uint8List(16));
      expect(aes.open(Uint8List(12), Uint8List(15), Uint8List(0)), isNull);
    });

    test('RFC 3610 vector 1', () {
      final aes = python_aesccm.newAESCCM(Uint8List(16));
      final nonce = Uint8List(12);
      final ciphertext = aes.seal(nonce, Uint8List(0), Uint8List(0));
      expect(ciphertext, equals(hex('b9f650fb3c39bb1bee0e291d33f6ae28')));
    });

    test('RFC 3610 vector 2', () {
      final aes = python_aesccm.newAESCCM(Uint8List(16));
      final nonce = Uint8List(12);
      final ciphertext = aes.seal(nonce, Uint8List(16), Uint8List(0));
      expect(
          ciphertext,
          equals(hex(
              '6ec75fb2e2b487461eddcbb8971192ba4d4fa3af0bf6d3454171306ffadd9afd')));
    });

    test('RFC 3610 vector 3', () {
      final key = hex('feffe9928665731c6d6a8f9467308308');
      final aes = python_aesccm.newAESCCM(key);
      final nonce = hex('cafebabefacedbaddecaf888');
        final plaintext = hex(
          'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255');
      final ciphertext = aes.seal(nonce, plaintext, Uint8List(0));
      expect(
          ciphertext,
          equals(hex(
              '0893e94b9148801af0f73426abb00e3ca49bf09d79a20127a7eb1926fa89053787ff02d07d71813b885b85e7f96c4eedf420db126a0451ce13bd41ba018d1ba7fcec65994467a77b8b2642de912c012e')));
    });

    test('RFC 3610 vector 4 (with AAD)', () {
      final key = hex('feffe9928665731c6d6a8f9467308308');
      final aes = python_aesccm.newAESCCM(key);
      final nonce = hex('cafebabefacedbaddecaf888');
        final plaintext = hex(
          'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39');
      final aad = hex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
      final ciphertext = aes.seal(nonce, plaintext, aad);
      expect(
          ciphertext,
          equals(hex(
              '0893e94b9148801af0f73426abb00e3ca49bf09d79a20127a7eb1926fa89053787ff02d07d71813b885b85e7f96c4eedf420db126a0451ce13bd41ba0238c326b47b34f78f659e751096cd22')));
    });

    test('RFC 3610 vector 5 (AES256)', () {
      final aes = python_aesccm.newAESCCM(Uint8List(32));
      final ciphertext = aes.seal(Uint8List(12), Uint8List(0), Uint8List(0));
      expect(ciphertext, equals(hex('a890265e43a26855f269b93ff4dddef6')));
    });

    test('RFC 3610 vector 6 (AES256)', () {
      final aes = python_aesccm.newAESCCM(Uint8List(32));
      final ciphertext = aes.seal(Uint8List(12), Uint8List(16), Uint8List(0));
      expect(
          ciphertext,
          equals(hex(
              'c1944044c8e7aa95d2de9513c7f3dd8c4b0a3e5e51f151eb0ffae7c43d010fdb')));
    });

    test('identical message encryption is deterministic', () {
      final key = hex('feffe9928665731c6d6a8f9467308308');
      final aes = python_aesccm.newAESCCM(key);
      final nonce = hex('cafebabefacedbaddecaf888');
      final aad = hex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
      final plaintext = hex(
          '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b4179e66c3710');
      final first = aes.seal(nonce, plaintext, aad);
      final second = aes.seal(nonce, plaintext, aad);
      expect(
          first,
          equals(hex(
              'ba63658c478c1969bc9343f277d63f8c8c11d39972955a61171046b735170114ab0b12034b456c79426f4adaaac0a927b3d512a21f462c8e04f57bf8fd4efee2e978fe311735a6c45c513380f4ca528c')));
      expect(second, equals(first));
      expect(aes.open(nonce, first, aad), equals(plaintext));
      expect(aes.open(nonce, second, aad), equals(plaintext));
    });

    test('identical message encryption truncated tag', () {
      final key = hex('feffe9928665731c6d6a8f9467308308');
      final aes = python_aesccm.newAESCCM(key, tagLength: 8);
      final nonce = hex('cafebabefacedbaddecaf888');
      final aad = hex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
      final plaintext = hex(
          '6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b4179e66c3710');
      final first = aes.seal(nonce, plaintext, aad);
      final second = aes.seal(nonce, plaintext, aad);
      expect(
          first,
          equals(hex(
              'ba63658c478c1969bc9343f277d63f8c8c11d39972955a61171046b735170114ab0b12034b456c79426f4adaaac0a927b3d512a21f462c8e04f57bf8fd4efee21faeebcb3ab22fd0')));
      expect(second, equals(first));
      expect(aes.open(nonce, first, aad), equals(plaintext));
      expect(aes.open(nonce, second, aad), equals(plaintext));
    });
  });
}

Uint8List asciiBytes(String value) => Uint8List.fromList(utf8.encode(value));

Uint8List hex(String data) {
  final cleaned = data.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
  if (cleaned.length.isOdd) {
    throw ArgumentError('Hex string must have even length');
  }
  final out = Uint8List(cleaned.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(cleaned.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
