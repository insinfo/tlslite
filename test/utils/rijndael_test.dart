import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/src/utils/rijndael.dart';

Uint8List _hex(String s) {
  s = s.replaceAll(' ', '');
  final result = Uint8List(s.length ~/ 2);
  for (int i = 0; i < result.length; i++) {
    result[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

void main() {
  group('Rijndael (AES)', () {
    // AES-128 Test Vectors (FIPS 197 Appendix C.1)
    test('AES-128 Encryption (FIPS 197 C.1)', () {
      final key = _hex('000102030405060708090a0b0c0d0e0f');
      final plaintext = _hex('00112233445566778899aabbccddeeff');
      final expectedCiphertext = _hex('69c4e0d86a7b0430d8cdb78070b4c55a');

      final r = Rijndael(key, blockSize: 16);
      final ciphertext = r.encrypt(plaintext);

      expect(ciphertext, equals(expectedCiphertext));
    });

    test('AES-128 Decryption (FIPS 197 C.1)', () {
      final key = _hex('000102030405060708090a0b0c0d0e0f');
      final ciphertext = _hex('69c4e0d86a7b0430d8cdb78070b4c55a');
      final expectedPlaintext = _hex('00112233445566778899aabbccddeeff');

      final r = Rijndael(key, blockSize: 16);
      final plaintext = r.decrypt(ciphertext);

      expect(plaintext, equals(expectedPlaintext));
    });

    // AES-192 Test Vectors (FIPS 197 Appendix C.2)
    test('AES-192 Encryption (FIPS 197 C.2)', () {
      final key = _hex('000102030405060708090a0b0c0d0e0f1011121314151617');
      final plaintext = _hex('00112233445566778899aabbccddeeff');
      final expectedCiphertext = _hex('dda97ca4864cdfe06eaf70a0ec0d7191');

      final r = Rijndael(key, blockSize: 16);
      final ciphertext = r.encrypt(plaintext);

      expect(ciphertext, equals(expectedCiphertext));
    });

    test('AES-192 Decryption (FIPS 197 C.2)', () {
      final key = _hex('000102030405060708090a0b0c0d0e0f1011121314151617');
      final ciphertext = _hex('dda97ca4864cdfe06eaf70a0ec0d7191');
      final expectedPlaintext = _hex('00112233445566778899aabbccddeeff');

      final r = Rijndael(key, blockSize: 16);
      final plaintext = r.decrypt(ciphertext);

      expect(plaintext, equals(expectedPlaintext));
    });

    // AES-256 Test Vectors (FIPS 197 Appendix C.3)
    test('AES-256 Encryption (FIPS 197 C.3)', () {
      final key = _hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
      final plaintext = _hex('00112233445566778899aabbccddeeff');
      final expectedCiphertext = _hex('8ea2b7ca516745bfeafc49904b496089');

      final r = Rijndael(key, blockSize: 16);
      final ciphertext = r.encrypt(plaintext);

      expect(ciphertext, equals(expectedCiphertext));
    });

    test('AES-256 Decryption (FIPS 197 C.3)', () {
      final key = _hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
      final ciphertext = _hex('8ea2b7ca516745bfeafc49904b496089');
      final expectedPlaintext = _hex('00112233445566778899aabbccddeeff');

      final r = Rijndael(key, blockSize: 16);
      final plaintext = r.decrypt(ciphertext);

      expect(plaintext, equals(expectedPlaintext));
    });

    // Rijndael Block Size 24 (192 bits) - Not AES
    test('Rijndael-128/192 (Key 128, Block 192) Roundtrip', () {
      final key = Uint8List(16); // Zero key
      final plaintext = Uint8List(24); // Zero block
      for(int i=0; i<24; i++) plaintext[i] = i;

      final r = Rijndael(key, blockSize: 24);
      final ciphertext = r.encrypt(plaintext);
      final decrypted = r.decrypt(ciphertext);

      expect(decrypted, equals(plaintext));
    });

    // Rijndael Block Size 32 (256 bits) - Not AES
    test('Rijndael-128/256 (Key 128, Block 256) Roundtrip', () {
      final key = Uint8List(16); // Zero key
      final plaintext = Uint8List(32); // Zero block
      for(int i=0; i<32; i++) plaintext[i] = i;

      final r = Rijndael(key, blockSize: 32);
      final ciphertext = r.encrypt(plaintext);
      final decrypted = r.decrypt(ciphertext);

      expect(decrypted, equals(plaintext));
    });
    
    test('Invalid Block Size', () {
        final key = Uint8List(16);
        expect(() => Rijndael(key, blockSize: 20), throwsArgumentError);
    });

    test('Invalid Key Size', () {
        final key = Uint8List(20);
        expect(() => Rijndael(key, blockSize: 16), throwsArgumentError);
    });
    
    test('Encrypt Invalid Block Length', () {
        final key = Uint8List(16);
        final r = Rijndael(key, blockSize: 16);
        expect(() => r.encrypt(Uint8List(15)), throwsArgumentError);
    });

    test('Decrypt Invalid Block Length', () {
        final key = Uint8List(16);
        final r = Rijndael(key, blockSize: 16);
        expect(() => r.decrypt(Uint8List(15)), throwsArgumentError);
    });
  });
}
