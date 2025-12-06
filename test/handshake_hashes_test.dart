import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/src/handshake_hashes.dart';

void main() {
  group('HandshakeHashes', () {
    test('initial digest is empty hash', () {
      final hashes = HandshakeHashes();
      
      // MD5 empty hash
      final md5Empty = Uint8List.fromList([
        0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
        0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
      ]);
      
      // SHA-1 empty hash
      final sha1Empty = Uint8List.fromList([
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
        0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
        0xaf, 0xd8, 0x07, 0x09,
      ]);
      
      final digest = hashes.digest();
      expect(digest.sublist(0, 16), equals(md5Empty));
      expect(digest.sublist(16), equals(sha1Empty));
    });

    test('update adds data to hashes', () {
      final hashes = HandshakeHashes();
      final data = Uint8List.fromList([0x01, 0x02, 0x03, 0x04]);
      
      hashes.update(data);
      
      // Digest should be different from empty
      final digest = hashes.digest();
      expect(digest.length, equals(36)); // MD5(16) + SHA1(20)
    });

    test('digest returns MD5+SHA1 by default', () {
      final hashes = HandshakeHashes();
      hashes.update(Uint8List.fromList([0x42]));
      
      final digest = hashes.digest();
      expect(digest.length, equals(36)); // 16 + 20
    });

    test('digest with md5 returns MD5 only', () {
      final hashes = HandshakeHashes();
      hashes.update(Uint8List.fromList([0x42]));
      
      final digest = hashes.digest('md5');
      expect(digest.length, equals(16));
    });

    test('digest with sha1 returns SHA-1 only', () {
      final hashes = HandshakeHashes();
      hashes.update(Uint8List.fromList([0x42]));
      
      final digest = hashes.digest('sha1');
      expect(digest.length, equals(20));
    });

    test('digest with sha224 returns SHA-224 hash', () {
      final hashes = HandshakeHashes();
      hashes.update(Uint8List.fromList([0x42]));
      
      final digest = hashes.digest('sha224');
      expect(digest.length, equals(28));
    });

    test('digest with sha256 returns SHA-256', () {
      final hashes = HandshakeHashes();
      hashes.update(Uint8List.fromList([0x42]));
      
      final digest = hashes.digest('sha256');
      expect(digest.length, equals(32));
    });

    test('digest with sha384 returns SHA-384', () {
      final hashes = HandshakeHashes();
      hashes.update(Uint8List.fromList([0x42]));
      
      final digest = hashes.digest('sha384');
      expect(digest.length, equals(48));
    });

    test('digest with sha512 returns SHA-512', () {
      final hashes = HandshakeHashes();
      hashes.update(Uint8List.fromList([0x42]));
      
      final digest = hashes.digest('sha512');
      expect(digest.length, equals(64));
    });

    test('digest with intrinsic returns buffered data', () {
      final hashes = HandshakeHashes();
      final data = Uint8List.fromList([0x01, 0x02, 0x03, 0x04, 0x05]);
      hashes.update(data);
      
      final digest = hashes.digest('intrinsic');
      expect(digest, equals(data));
    });

    test('digest throws on unknown digest name', () {
      final hashes = HandshakeHashes();
      
      expect(() => hashes.digest('unknown'), throwsArgumentError);
    });

    test('multiple updates accumulate', () {
      final hashes = HandshakeHashes();
      
      hashes.update(Uint8List.fromList([0x01, 0x02]));
      hashes.update(Uint8List.fromList([0x03, 0x04]));
      hashes.update(Uint8List.fromList([0x05]));
      
      final intrinsic = hashes.digest('intrinsic');
      expect(intrinsic, equals([0x01, 0x02, 0x03, 0x04, 0x05]));
    });

    test('digestSSL calculates SSLv3 digest', () {
      final hashes = HandshakeHashes();
      // Python test uses empty update
      
      final masterSecret = Uint8List(48); // Zeros
      final label = Uint8List(0); // Empty
      
      final digest = hashes.digestSSL(masterSecret, label);
      
      final expected = Uint8List.fromList([
        0xb5, 0x51, 0x15, 0xa4, 0xcd, 0xff, 0xfd, 0x46, 0xa6, 0x9c, 0xe2, 0x0f, 0x83, 0x7e, 0x94, 0x38,
        0xc3, 0xb5, 0xc1, 0x8d, 0xb6, 0x7c, 0x10, 0x6e, 0x40, 0x61, 0x97, 0xcc, 0x47, 0xfe, 0x49, 0xa8,
        0x73, 0x20, 0x54, 0x5c
      ]);
      
      expect(digest, equals(expected));
    });

    test('copy creates independent copy', () {
      final hashes1 = HandshakeHashes();
      hashes1.update(Uint8List.fromList([0x01, 0x02]));
      
      final hashes2 = hashes1.copy();
      
      // Add more data to original
      hashes1.update(Uint8List.fromList([0x03, 0x04]));
      
      // Copy should not have the new data
      final digest1 = hashes1.digest('intrinsic');
      final digest2 = hashes2.digest('intrinsic');
      
      expect(digest1, equals([0x01, 0x02, 0x03, 0x04]));
      expect(digest2, equals([0x01, 0x02]));
    });

    test('copy preserves all hash states', () {
      final hashes1 = HandshakeHashes();
      final data = Uint8List.fromList([0x42, 0x43, 0x44]);
      hashes1.update(data);
      
      final hashes2 = hashes1.copy();
      
      // All digests should match
      expect(hashes2.digest('md5'), equals(hashes1.digest('md5')));
      expect(hashes2.digest('sha1'), equals(hashes1.digest('sha1')));
      expect(hashes2.digest('sha256'), equals(hashes1.digest('sha256')));
      expect(hashes2.digest('sha384'), equals(hashes1.digest('sha384')));
      expect(hashes2.digest('sha512'), equals(hashes1.digest('sha512')));
    });

    test('digest is idempotent', () {
      final hashes = HandshakeHashes();
      hashes.update(Uint8List.fromList([0x01, 0x02, 0x03]));
      
      final digest1 = hashes.digest('sha256');
      final digest2 = hashes.digest('sha256');
      
      expect(digest1, equals(digest2));
    });

    test('different data produces different digests', () {
      final hashes1 = HandshakeHashes();
      final hashes2 = HandshakeHashes();
      
      hashes1.update(Uint8List.fromList([0x01, 0x02, 0x03]));
      hashes2.update(Uint8List.fromList([0x04, 0x05, 0x06]));
      
      final digest1 = hashes1.digest('sha256');
      final digest2 = hashes2.digest('sha256');
      
      expect(digest1, isNot(equals(digest2)));
    });

    test('empty update has no effect', () {
      final hashes = HandshakeHashes();
      final digest1 = hashes.digest('sha256');
      
      hashes.update(Uint8List(0));
      final digest2 = hashes.digest('sha256');
      
      expect(digest1, equals(digest2));
    });

    test('large data can be hashed', () {
      final hashes = HandshakeHashes();
      final largeData = Uint8List(10000);
      for (var i = 0; i < largeData.length; i++) {
        largeData[i] = i % 256;
      }
      
      hashes.update(largeData);
      final digest = hashes.digest('sha256');
      
      expect(digest.length, equals(32));
    });
  });
}
