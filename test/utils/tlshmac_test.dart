import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:test/test.dart';
import 'package:tlslite/src/utils/tlshashlib.dart';
import 'package:tlslite/src/utils/tlshmac.dart';

void main() {
  group('TlsHmac', () {
    test('produces same MD5 digest as package:crypto', () {
      final key = utf8.encode('secret');
      final data = utf8.encode('payload');
      final mac = TlsHmac(key, digestmod: 'md5', message: data);
      final expected = crypto.Hmac(crypto.md5, key).convert(data).bytes;
      expect(mac.digest(), equals(expected));
    });

    test('supports incremental updates and copy semantics', () {
      final key = Uint8List.fromList([1, 2, 3, 4]);
      final mac = TlsHmac(key, digestmod: 'sha256');
      mac.update([10, 11]);
      final clone = mac.copy();
      mac.update([12]);
      final expectedClone =
          crypto.Hmac(crypto.sha256, key).convert([10, 11]).bytes;
      expect(clone.digest(), equals(expectedClone));
    });

    test('accepts TlsHash instance as digestmod', () {
      final hash = md5();
      final mac = TlsHmac([0x41], digestmod: hash);
      mac.update([0x42]);
      expect(mac.digest().length, hash.digestSize);
    });
  });

  group('compareDigest', () {
    test('returns true for equal lists', () {
      final bytes = [1, 2, 3];
      expect(compareDigest(bytes, [1, 2, 3]), isTrue);
    });

    test('returns false for unequal inputs or length mismatch', () {
      expect(compareDigest([1, 2], [1, 3]), isFalse);
      expect(compareDigest([1, 2], [1, 2, 3]), isFalse);
    });
  });
}
