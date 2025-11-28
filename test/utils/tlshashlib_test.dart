import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';
import 'package:tlslite/src/utils/tlshashlib.dart';

void main() {
  group('md5 helper', () {
    test('matches crypto package output', () {
      final data = utf8.encode('hello world');
      final hash = md5(data);
      expect(hash.digest(), equals(crypto.md5.convert(data).bytes));
    });

    test('supports incremental updates', () {
      final hash = md5();
      hash.update(utf8.encode('hello '));
      hash.update(utf8.encode('world'));
      final expected = crypto.md5.convert(utf8.encode('hello world')).bytes;
      expect(hash.digest(), equals(expected));
    });
  });

  group('newHash', () {
    test('returns sha256 instance with copy support', () {
      final hash = newHash('sha256');
      hash.update(Uint8List.fromList([1, 2, 3]));
      final clone = hash.copy();
      hash.update(Uint8List.fromList([4]));
      final originalBytes = crypto.sha256.convert([1, 2, 3]).bytes;
      expect(clone.digest(), equals(originalBytes));
    });

    test('throws on unsupported algorithm', () {
      expect(() => newHash('ripemd160'), throwsArgumentError);
    });
  });
}
