// dart format width=5000
// Tests for the optimized SHA-256

import 'dart:convert';
import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:crypto/crypto.dart' as crypto;

import 'package:tlslite/src/experimental/sha256_asm_x86_64.dart';

void main() {
  group('ShaNiSupport', () {
    test('detects SHA-NI support', () {
      final supported = ShaNiSupport.isSupported;
      print('SHA-NI supported: $supported');
      expect(supported, isA<bool>());
    });
  });

  group('Sha256Asm', () {
    test('hash of an empty string', () {
      final result = Sha256Asm.hash(Uint8List(0));
      final expected = crypto.sha256.convert([]).bytes;

      expect(result, equals(expected));
      print('Empty string hash: ${result.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
    });

    test('hash of "abc"', () {
      final data = utf8.encode('abc');
      final result = Sha256Asm.hash(Uint8List.fromList(data));
      final expected = crypto.sha256.convert(data).bytes;

      expect(result, equals(expected));
    });

    test('hash of a long string', () {
      final data = utf8.encode('The quick brown fox jumps over the lazy dog');
      final result = Sha256Asm.hash(Uint8List.fromList(data));
      final expected = crypto.sha256.convert(data).bytes;

      expect(result, equals(expected));
    });

    test('hash of binary data', () {
      final data = Uint8List.fromList(List.generate(256, (i) => i));
      final result = Sha256Asm.hash(data);
      final expected = crypto.sha256.convert(data).bytes;

      expect(result, equals(expected));
    });

    test('hash of data larger than one block (64 bytes)', () {
      final data = Uint8List.fromList(List.generate(1000, (i) => i & 0xFF));
      final result = Sha256Asm.hash(data);
      final expected = crypto.sha256.convert(data).bytes;

      expect(result, equals(expected));
    });

    test('incremental hash works', () {
      final data1 = utf8.encode('Hello, ');
      final data2 = utf8.encode('World!');
      final fullData = utf8.encode('Hello, World!');

      final sha = Sha256Asm();
      sha.update(Uint8List.fromList(data1));
      sha.update(Uint8List.fromList(data2));
      final incrementalResult = sha.finalize();

      final singleResult = Sha256Asm.hash(Uint8List.fromList(fullData));
      final expected = crypto.sha256.convert(fullData).bytes;

      expect(incrementalResult, equals(expected));
      expect(singleResult, equals(expected));
    });

    test('reset works correctly', () {
      final sha = Sha256Asm();

      sha.update(Uint8List.fromList(utf8.encode('test1')));
      sha.finalize();

      sha.reset();
      sha.update(Uint8List.fromList(utf8.encode('test2')));
      final result = sha.finalize();

      final expected = crypto.sha256.convert(utf8.encode('test2')).bytes;
      expect(result, equals(expected));
    });
  });

  group('HmacSha256Asm', () {
    test('HMAC with a short key', () {
      final key = Uint8List.fromList(utf8.encode('key'));
      final data = Uint8List.fromList(utf8.encode('The quick brown fox jumps over the lazy dog'));

      final hmac = HmacSha256Asm(key);
      final result = hmac.compute(data);

      final expected = crypto.Hmac(crypto.sha256, key).convert(data).bytes;
      expect(result, equals(expected));
    });

    test('HMAC with a long key (> 64 bytes)', () {
      final key = Uint8List.fromList(List.generate(100, (i) => i));
      final data = Uint8List.fromList(utf8.encode('test data'));

      final hmac = HmacSha256Asm(key);
      final result = hmac.compute(data);

      final expected = crypto.Hmac(crypto.sha256, key).convert(data).bytes;
      expect(result, equals(expected));
    });

    test('HMAC with empty data', () {
      final key = Uint8List.fromList(utf8.encode('secret'));
      final data = Uint8List(0);

      final hmac = HmacSha256Asm(key);
      final result = hmac.compute(data);

      final expected = crypto.Hmac(crypto.sha256, key).convert(data).bytes;
      expect(result, equals(expected));
    });
  });
}
