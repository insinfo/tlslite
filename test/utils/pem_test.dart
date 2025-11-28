import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/pem.dart';

void main() {
  group('dePem', () {
    test('decodes first block', () {
      const body = 'AQID';
      final pemText = '-----BEGIN DATA-----\n$body\n-----END DATA-----';
      final decoded = dePem(pemText, 'DATA');
      expect(decoded, equals(Uint8List.fromList([1, 2, 3])));
    });

    test('throws when delimiters missing', () {
      expect(() => dePem('foo', 'CERT'), throwsFormatException);
    });
  });

  group('dePemList', () {
    test('returns all blocks', () {
      const block = '-----BEGIN DATA-----\nAQID\n-----END DATA-----';
      final text = 'pre$block middle$block post';
      final items = dePemList(text, 'DATA');
      expect(items.length, 2);
    });
  });

  group('pem', () {
    test('wraps output with headers and 64 char lines', () {
      final data = Uint8List.fromList(List<int>.generate(70, (i) => i & 0xff));
      final encoded = pem(data, 'BYTES');
      expect(encoded.startsWith('-----BEGIN BYTES-----'), isTrue);
      expect(encoded.trimRight().endsWith('-----END BYTES-----'), isTrue);
    });
  });

  group('pemSniff', () {
    test('detects presence', () {
      expect(pemSniff('hello -----BEGIN CERT-----', 'CERT'), isTrue);
      expect(pemSniff('nothing here', 'CERT'), isFalse);
    });
  });
}
