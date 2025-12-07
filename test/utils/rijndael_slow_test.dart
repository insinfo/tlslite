import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/src/utils/rijndael_slow.dart';

Uint8List _hex(String s) {
  s = s.replaceAll(' ', '');
  final result = Uint8List(s.length ~/ 2);
  for (int i = 0; i < result.length; i++) {
    result[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

class _RijndaelVector {
  final String name;
  final String keyHex;
  final String plaintextHex;
  final String ciphertextHex;
  final int blockSize;

  const _RijndaelVector(
    this.name,
    this.keyHex,
    this.plaintextHex,
    this.ciphertextHex, {
    this.blockSize = 16,
  });
}

void _addVectorTests(_RijndaelVector vector) {
  final key = _hex(vector.keyHex);
  final plaintext = _hex(vector.plaintextHex);
  final ciphertext = _hex(vector.ciphertextHex);

  test('${vector.name} encrypt', () {
    final r = Rijndael(key, blockSize: vector.blockSize);
    expect(r.encrypt(plaintext), equals(ciphertext));
  });

  test('${vector.name} decrypt', () {
    final r = Rijndael(key, blockSize: vector.blockSize);
    expect(r.decrypt(ciphertext), equals(plaintext));
  });
}

void main() {
  group('Rijndael (AES)', () {
    final vectors = <_RijndaelVector>[
      const _RijndaelVector(
        'AES-128 zero block',
        '00000000000000000000000000000000',
        '00000000000000000000000000000000',
        '66e94bd4ef8a2c3b884cfa59ca342b2e',
        blockSize: 16, // explicitly pass to exercise optional param
      ),
      const _RijndaelVector(
        'AES-128 sequential block',
        '000102030405060708090a0b0c0d0e0f',
        '000102030405060708090a0b0c0d0e0f',
        '0a940bb5416ef045f1c39458c653ea5a',
      ),
      const _RijndaelVector(
        'AES-128 FIPS 197 C.1',
        '000102030405060708090a0b0c0d0e0f',
        '00112233445566778899aabbccddeeff',
        '69c4e0d86a7b0430d8cdb78070b4c55a',
      ),
      const _RijndaelVector(
        'AES-192 zero block',
        '000000000000000000000000000000000000000000000000',
        '00000000000000000000000000000000',
        'aae06992acbf52a3e8f4a96ec9300bd7',
      ),
      const _RijndaelVector(
        'AES-192 sequential block',
        '000102030405060708090a0b0c0d0e0f1011121314151617',
        '000102030405060708090a0b0c0d0e0f',
        '0060bffe46834bb8da5cf9a61ff220ae',
      ),
      const _RijndaelVector(
        'AES-192 FIPS 197 C.2',
        '000102030405060708090a0b0c0d0e0f1011121314151617',
        '00112233445566778899aabbccddeeff',
        'dda97ca4864cdfe06eaf70a0ec0d7191',
      ),
      const _RijndaelVector(
        'AES-256 zero block',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '00000000000000000000000000000000',
        'dc95c078a2408989ad48a21492842087',
      ),
      const _RijndaelVector(
        'AES-256 sequential block',
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '000102030405060708090a0b0c0d0e0f',
        '5a6e045708fb7196f02e553d02c3a692',
      ),
      const _RijndaelVector(
        'AES-256 FIPS 197 C.3',
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '00112233445566778899aabbccddeeff',
        '8ea2b7ca516745bfeafc49904b496089',
      ),
    ];

    for (final vector in vectors) {
      _addVectorTests(vector);
    }

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
