import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/aesgcm.dart';
import 'package:tlslite/src/utils/dart_aesgcm.dart' as dart_aesgcm;
import 'package:tlslite/src/utils/rijndael.dart';

void main() {
  group('AESGCM', () {
    test('constructor accepts 16-byte key', () {
      final key = Uint8List(16);
      expect(
        () => AESGCM(key, 'dart', Rijndael(Uint8List.fromList(key), blockSize: 16).encrypt),
        returnsNormally,
      );
    });

    test('constructor rejects invalid key length', () {
      final key = Uint8List(8);
      expect(
        () => AESGCM(key, 'dart', Rijndael(Uint8List(16), blockSize: 16).encrypt),
        throwsArgumentError,
      );
    });

    test('seal basic example', () {
      final key = Uint8List.fromList(List<int>.filled(16, 0x01));
      final aes = dart_aesgcm.newAESGCM(key);
      final nonce = Uint8List.fromList(List<int>.filled(12, 0x02));
      final plaintext = asciiBytes('text to encrypt.');
      final ciphertext = aes.seal(nonce, plaintext, Uint8List(0));
      expect(ciphertext, equals(hex('27816817e65a295cf28e6d46cb910e757a313af67da75c40ba11d872df234bd4')));
    });

    test('seal throws on invalid nonce length', () {
      final aes = dart_aesgcm.newAESGCM(Uint8List(16));
      expect(() => aes.seal(Uint8List(11), Uint8List(0), Uint8List(0)), throwsArgumentError);
    });

    test('open basic example', () {
      final key = Uint8List.fromList(List<int>.filled(16, 0x01));
      final aes = dart_aesgcm.newAESGCM(key);
      final nonce = Uint8List.fromList(List<int>.filled(12, 0x02));
      final ciphertext = hex('27816817e65a295cf28e6d46cb910e757a313af67da75c40ba11d872df234bd4');
      final plaintext = aes.open(nonce, ciphertext, Uint8List(0));
      expect(plaintext, equals(asciiBytes('text to encrypt.')));
    });

    test('open returns null with incorrect key', () {
      final key = Uint8List.fromList(List<int>.filled(16, 0x01));
      final aes = dart_aesgcm.newAESGCM(key);
      final wrong = dart_aesgcm.newAESGCM(Uint8List.fromList(List<int>.filled(16, 0x01)..[15] = 0));
      final nonce = Uint8List.fromList(List<int>.filled(12, 0x02));
      final ciphertext = aes.seal(nonce, asciiBytes('text to encrypt.'), Uint8List(0));
      expect(wrong.open(nonce, ciphertext, Uint8List(0)), isNull);
    });

    test('open returns null with incorrect nonce', () {
      final key = Uint8List.fromList(List<int>.filled(16, 0x01));
      final aes = dart_aesgcm.newAESGCM(key);
      final nonce = Uint8List.fromList(List<int>.filled(12, 0x02));
      final ciphertext = aes.seal(nonce, asciiBytes('text to encrypt.'), Uint8List(0));
      final otherNonce = Uint8List.fromList(List<int>.filled(11, 0x02) + [0x01]);
      expect(aes.open(otherNonce, ciphertext, Uint8List(0)), isNull);
    });

    test('open throws on invalid nonce length', () {
      final aes = dart_aesgcm.newAESGCM(Uint8List(16));
      expect(() => aes.open(Uint8List(11), Uint8List(16), Uint8List(0)), throwsArgumentError);
    });

    test('open returns null on short ciphertext', () {
      final aes = dart_aesgcm.newAESGCM(Uint8List(16));
      expect(aes.open(Uint8List(12), Uint8List(15), Uint8List(0)), isNull);
    });

    test('RFC 5116 vector 1', () {
      final key = Uint8List(16);
      final aes = dart_aesgcm.newAESGCM(key);
      final nonce = Uint8List(12);
      final result = aes.seal(nonce, Uint8List(0), Uint8List(0));
      expect(result, equals(hex('58e2fccefa7e3061367f1d57a4e7455a')));
    });

    test('RFC 5116 vector 2', () {
      final key = Uint8List(16);
      final aes = dart_aesgcm.newAESGCM(key);
      final nonce = Uint8List(12);
      final plaintext = Uint8List(16);
      final result = aes.seal(nonce, plaintext, Uint8List(0));
      expect(result, equals(hex('0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf')));
    });

    test('RFC 5116 vector 3', () {
      final key = hex('feffe9928665731c6d6a8f9467308308');
      final aes = dart_aesgcm.newAESGCM(key);
      final nonce = hex('cafebabefacedbaddecaf888');
      final plaintext = hex(
        'd9313225f88406e5a55909c5aff5269a'
        '86a7a9531534f7da2e4c303d8a318a72'
        '1c3c0c95956809532fcf0e2449a6b525'
        'b16aedf5aa0de657ba637b391aafd255',
      );
      final result = aes.seal(nonce, plaintext, Uint8List(0));
      expect(
        result,
        equals(hex(
          '42831ec2217774244b7221b784d0d49c'
          'e3aa212f2c02a4e035c17e2329aca12e'
          '21d514b25466931c7d8f6a5aac84aa05'
          '1ba30b396a0aac973d58e091473f5985'
          '4d5c2af327cd64a62cf35abd2ba6fab4',
        )),
      );
    });

    test('RFC 5116 vector 4', () {
      final key = hex('feffe9928665731c6d6a8f9467308308');
      final aes = dart_aesgcm.newAESGCM(key);
      final nonce = hex('cafebabefacedbaddecaf888');
      final plaintext = hex(
        'd9313225f88406e5a55909c5aff5269a'
        '86a7a9531534f7da2e4c303d8a318a72'
        '1c3c0c95956809532fcf0e2449a6b525'
        'b16aedf5aa0de657ba637b39',
      );
      final aad = hex('feedfacedeadbeeffeedfacedeadbeefabaddad2');
      final result = aes.seal(nonce, plaintext, aad);
      expect(
        result,
        equals(hex(
          '42831ec2217774244b7221b784d0d49c'
          'e3aa212f2c02a4e035c17e2329aca12e'
          '21d514b25466931c7d8f6a5aac84aa05'
          '1ba30b396a0aac973d58e0915bc94fbc'
          '3221a5db94fae95ae7121a47',
        )),
      );
    });

    test('AES-256 name reported correctly', () {
      final aes = dart_aesgcm.newAESGCM(Uint8List(32));
      expect(aes.name, equals('aes256gcm'));
    });

    test('RFC 5116 vector 13 (AES256)', () {
      final aes = dart_aesgcm.newAESGCM(Uint8List(32));
      final result = aes.seal(Uint8List(12), Uint8List(0), Uint8List(0));
      expect(result, equals(hex('530f8afbc74536b9a963b4f1c4cb738b')));
    });

    test('RFC 5116 vector 14 (AES256)', () {
      final aes = dart_aesgcm.newAESGCM(Uint8List(32));
      final result = aes.seal(Uint8List(12), Uint8List(16), Uint8List(0));
      expect(result, equals(hex('cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919')));
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
