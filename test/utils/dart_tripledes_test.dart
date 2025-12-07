import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/cipherfactory.dart' as cipherfactory;
import 'package:tlslite/src/utils/dart_tripledes.dart' as dart_tripledes;

void main() {
  group('DartTripleDES', () {
    test('factory constructor exposes metadata', () {
      final key = hex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      final iv = hex('bbbbbbbbbbbbbbbb');
      final cipher = dart_tripledes.newTripleDES(key, iv);
      expect(cipher.name, equals('3des'));
      expect(cipher.implementation, equals('dart'));
      expect(cipher.isBlockCipher, isTrue);
      expect(cipher.isAEAD, isFalse);
    });

    test('rejects invalid key length', () {
      final shortKey = Uint8List(8);
      final iv = Uint8List(8);
      expect(() => dart_tripledes.newTripleDES(shortKey, iv),
          throwsArgumentError);
    });

    test('rejects invalid IV length', () {
      final key = Uint8List(24);
      final iv = Uint8List(7);
      expect(() => dart_tripledes.newTripleDES(key, iv),
          throwsArgumentError);
    });

    test('supports 16-byte keys by repeating first component', () {
      final key = hex('7ca110454a1a6e577ca110454a1a6e57');
      final iv = hex('55fe072a7351a5c8');
        var cipher = dart_tripledes.newTripleDES(key, iv);
        final plaintext = hex(
          '800000000000000080000000000000008000000000000000');
        final ciphertext = cipher.encrypt(plaintext);
      expect(
        ciphertext,
        equals(hex(
            '56284a04c9b5f7b68f36f6cdf63617d29a1c079ac40cf462')),
      );
        cipher = dart_tripledes.newTripleDES(key, iv);
        expect(cipher.decrypt(ciphertext), equals(plaintext));
    });

    test('single-block known answer encrypt/decrypt', () {
      final key = hex(
          '010101010101010101010101010101010101010101010101');
      final iv = Uint8List(8);
      final cipher = dart_tripledes.newTripleDES(key, iv);
      final plaintext = hex('8000000000000000');
      final ciphertext = cipher.encrypt(plaintext);
      expect(ciphertext, equals(hex('95f8a5e5dd31d900')));
      final roundtrip =
          dart_tripledes.newTripleDES(key, iv).decrypt(ciphertext);
      expect(roundtrip, equals(plaintext));
    });

    test('KO1 multi-block encrypt/decrypt vectors', () {
      final key = hex(
          '7ca110454a1a6e571007d015989801200101010101010101');
      final iv = hex('fa269c070cc57182');
        final plaintext = hex(
          '800000000000000080000000000000008000000000000000');
        final ciphertext =
          dart_tripledes.newTripleDES(key, iv).encrypt(plaintext);
      expect(
        ciphertext,
        equals(hex(
            'a155a6ba61cfda01315d41b7e559807a6e9668aff44c6f0f')),
      );
        final decrypted =
          dart_tripledes.newTripleDES(key, iv).decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('KO2 multi-block encrypt/decrypt vectors', () {
      final key = hex(
          '7ca110454a1a6e5701079404911904017ca110454a1a6e57');
      final iv = hex('8a4d359f8528954a');
        final plaintext = hex(
          '800000000000000080000000000000008000000000000000');
        final ciphertext =
          dart_tripledes.newTripleDES(key, iv).encrypt(plaintext);
      expect(
        ciphertext,
        equals(hex(
            '9493b0cd54f976adfd267ea433de50193f30c94ba957f714')),
      );
        final decrypted =
          dart_tripledes.newTripleDES(key, iv).decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('KO3 multi-block encrypt/decrypt vectors', () {
      final key = hex(
          '7ca110454a1a6e577ca110454a1a6e577ca110454a1a6e57');
      final iv = hex('55fe072a7351a5c8');
        final plaintext = hex(
          '800000000000000080000000000000008000000000000000');
        final ciphertext =
          dart_tripledes.newTripleDES(key, iv).encrypt(plaintext);
      expect(
        ciphertext,
        equals(hex(
            '56284a04c9b5f7b68f36f6cdf63617d29a1c079ac40cf462')),
      );
        final decrypted =
          dart_tripledes.newTripleDES(key, iv).decrypt(ciphertext);
      expect(decrypted, equals(plaintext));
    });

    test('rejects non block-aligned plaintext/ciphertext', () {
      final key = Uint8List(24);
      final iv = Uint8List(8);
      final cipher = dart_tripledes.newTripleDES(key, iv);
      expect(() => cipher.encrypt(Uint8List(7)), throwsArgumentError);
      expect(() => cipher.decrypt(Uint8List(5)), throwsArgumentError);
    });

    test('cipherfactory returns dart implementation', () {
      final key = Uint8List(24);
      final iv = Uint8List(8);
      final cipher = cipherfactory.createTripleDES(key, iv);
      expect(cipher.implementation, equals('dart'));
    });
  });
}

Uint8List hex(String data) {
  final cleaned = data.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
  if (cleaned.length.isOdd) {
    throw ArgumentError('Hex string must have even length');
  }
  final result = Uint8List(cleaned.length ~/ 2);
  for (var i = 0; i < result.length; i++) {
    result[i] = int.parse(cleaned.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}
