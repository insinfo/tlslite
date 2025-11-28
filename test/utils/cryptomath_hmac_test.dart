import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';
import 'package:tlslite/src/utils/cryptomath.dart';

void main() {
  Uint8List _bytes(List<int> ints) => Uint8List.fromList(ints);

  group('secureHMAC', () {
    test('matches package:crypto for sha256', () {
      final key = _bytes(List<int>.filled(16, 0x0b));
      final data = _bytes('Hi There'.codeUnits);
      final expected = crypto.Hmac(crypto.sha256, key).convert(data).bytes;
      expect(secureHMAC(key, data, 'sha256'), expected);
    });

    test('supports md5 compatibility path', () {
      final key = _bytes('key'.codeUnits);
      final data = _bytes('data'.codeUnits);
      final expected = crypto.Hmac(crypto.md5, key).convert(data).bytes;
      expect(secureHMAC(key, data, 'md5'), expected);
    });
  });
}
