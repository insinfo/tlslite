import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/constants.dart';
import 'package:tlslite/src/handshake_hashes.dart';
import 'package:tlslite/src/mathtls.dart';
import 'package:tlslite/src/utils/cryptomath.dart';

void main() {
  group('PRF functions', () {
    test('pHash produces expected output for short input', () {
      final secret = Uint8List.fromList([1, 2, 3]);
      final seed = Uint8List.fromList([4, 5, 6]);
      final result = pHash('sha256', secret, seed, 32);
      
      expect(result.length, equals(32));
      expect(result, isNot(equals(Uint8List(32))));
    });

    test('TLS 1.0/1.1 PRF combines MD5 and SHA1', () {
      final secret = Uint8List.fromList(List.generate(48, (i) => i));
      final label = 'test label'.codeUnits;
      final seed = Uint8List.fromList(List.generate(32, (i) => i + 100));
      
      final result = prf(secret, label, seed, 48);
      
      expect(result.length, equals(48));
      // Result should be different from pure MD5 or SHA1
      expect(result, isNot(equals(Uint8List(48))));
    });

    test('TLS 1.2 PRF with SHA256', () {
      final secret = Uint8List.fromList(List.generate(48, (i) => i));
      final label = 'master secret'.codeUnits;
      final seed = Uint8List.fromList(List.generate(64, (i) => i));
      
      final result = prf12(secret, label, seed, 48);
      
      expect(result.length, equals(48));
      expect(result, isNot(equals(Uint8List(48))));
    });

    test('TLS 1.2 PRF with SHA384', () {
      final secret = Uint8List.fromList(List.generate(48, (i) => i));
      final label = 'master secret'.codeUnits;
      final seed = Uint8List.fromList(List.generate(64, (i) => i));
      
      final result = prf12Sha384(secret, label, seed, 48);
      
      expect(result.length, equals(48));
      expect(result, isNot(equals(Uint8List(48))));
    });

    test('SSL 3.0 PRF', () {
      final secret = Uint8List.fromList(List.generate(48, (i) => i));
      final seed = Uint8List.fromList(List.generate(64, (i) => i + 50));
      
      final result = prfSsl(secret, seed, 48);
      
      expect(result.length, equals(48));
      expect(result, isNot(equals(Uint8List(48))));
    });
  });

  group('calcMasterSecret', () {
    test('TLS 1.0 master secret derivation', () {
      final premasterSecret = Uint8List(48)..fillRange(0, 48, 0xAB);
      final clientRandom = Uint8List(32)..fillRange(0, 32, 0x01);
      final serverRandom = Uint8List(32)..fillRange(0, 32, 0x02);
      
      final masterSecret = calcMasterSecret(
        [3, 1], // TLS 1.0
        0, // cipher suite (ignored for TLS 1.0/1.1)
        premasterSecret,
        clientRandom,
        serverRandom,
      );
      
      expect(masterSecret.length, equals(48));
      expect(masterSecret, isNot(equals(premasterSecret)));
    });

    test('TLS 1.2 master secret with default PRF', () {
      final premasterSecret = Uint8List(48)..fillRange(0, 48, 0xCD);
      final clientRandom = Uint8List(32)..fillRange(0, 32, 0x03);
      final serverRandom = Uint8List(32)..fillRange(0, 32, 0x04);
      
      final masterSecret = calcMasterSecret(
        [3, 3], // TLS 1.2
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256, // non-SHA384 suite
        premasterSecret,
        clientRandom,
        serverRandom,
      );
      
      expect(masterSecret.length, equals(48));
      expect(masterSecret, isNot(equals(premasterSecret)));
    });

    test('SSL 3.0 master secret derivation', () {
      final premasterSecret = Uint8List(48)..fillRange(0, 48, 0xEF);
      final clientRandom = Uint8List(32)..fillRange(0, 32, 0x05);
      final serverRandom = Uint8List(32)..fillRange(0, 32, 0x06);
      
      final masterSecret = calcMasterSecret(
        [3, 0], // SSL 3.0
        0,
        premasterSecret,
        clientRandom,
        serverRandom,
      );
      
      expect(masterSecret.length, equals(48));
      expect(masterSecret, isNot(equals(premasterSecret)));
    });
  });

  group('paramStrength', () {
    test('returns correct security levels for various bit sizes', () {
      // Test boundaries more carefully
      expect(paramStrength(BigInt.from(2).pow(500)), equals(48)); // < 512
      expect(paramStrength(BigInt.from(2).pow(700)), equals(56)); // < 768
      expect(paramStrength(BigInt.from(2).pow(800)), equals(64)); // < 816
      expect(paramStrength(BigInt.from(2).pow(1000)), equals(72)); // < 1023
      expect(paramStrength(BigInt.from(2).pow(1500)), equals(80)); // < 1535
      expect(paramStrength(BigInt.from(2).pow(2000)), equals(88)); // < 2047
      expect(paramStrength(BigInt.from(2).pow(3000)), equals(112)); // < 3071
      expect(paramStrength(BigInt.from(2).pow(4000)), equals(128)); // < 4095
      expect(paramStrength(BigInt.from(2).pow(16000)), equals(256)); // >= 15359
    });
  });

  group('calcKey universal function', () {
    test('calculates master secret for TLS 1.2', () {
      final premasterSecret = Uint8List(48)..fillRange(0, 48, 0x42);
      final clientRandom = Uint8List(32)..fillRange(0, 32, 0x11);
      final serverRandom = Uint8List(32)..fillRange(0, 32, 0x22);
      
      final result = calcKey(
        [3, 3],
        premasterSecret,
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        'master secret'.codeUnits,
        clientRandom: clientRandom,
        serverRandom: serverRandom,
        outputLength: 48,
      );
      
      expect(result.length, equals(48));
      expect(result, isNot(equals(Uint8List(48))));
    });

    test('calculates key expansion for TLS 1.2', () {
      final masterSecret = Uint8List(48)..fillRange(0, 48, 0x33);
      final clientRandom = Uint8List(32)..fillRange(0, 32, 0x44);
      final serverRandom = Uint8List(32)..fillRange(0, 32, 0x55);
      
      final result = calcKey(
        [3, 3],
        masterSecret,
        CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256,
        'key expansion'.codeUnits,
        clientRandom: clientRandom,
        serverRandom: serverRandom,
        outputLength: 128,
      );
      
      expect(result.length, equals(128));
      expect(result, isNot(equals(Uint8List(128))));
    });

    test('derives TLS 1.3 traffic secret with transcript hash', () {
      final handshakeHashes = HandshakeHashes()
        ..update(Uint8List.fromList(List<int>.generate(32, (i) => i)));
      final baseSecret = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));

      final result = calcKey(
        [3, 4],
        baseSecret,
        CipherSuite.TLS_AES_128_GCM_SHA256,
        'c hs traffic'.codeUnits,
        handshakeHashes: handshakeHashes,
      );

      final expected = derive_secret(
        baseSecret,
        Uint8List.fromList('c hs traffic'.codeUnits),
        handshakeHashes,
        'sha256',
      );

      expect(result, equals(expected));
    });

    test('throws when TLS 1.3 transcript labels miss handshake hashes', () {
      final baseSecret = Uint8List.fromList(List<int>.generate(32, (i) => i + 5));

      expect(
        () => calcKey(
          [3, 4],
          baseSecret,
          CipherSuite.TLS_AES_128_GCM_SHA256,
          'c hs traffic'.codeUnits,
        ),
        throwsArgumentError,
      );
    });

    test('derives TLS 1.3 context-free secrets', () {
      final baseSecret = Uint8List.fromList(List<int>.generate(32, (i) => i + 7));

      final result = calcKey(
        [3, 4],
        baseSecret,
        CipherSuite.TLS_AES_128_GCM_SHA256,
        'derived'.codeUnits,
      );

      final expected = derive_secret(
        baseSecret,
        Uint8List.fromList('derived'.codeUnits),
        null,
        'sha256',
      );

      expect(result, equals(expected));
    });

    test('expands TLS 1.3 finished key and key material', () {
      final baseSecret = Uint8List.fromList(List<int>.filled(32, 0xA5));

      final finishedKey = calcKey(
        [3, 4],
        baseSecret,
        CipherSuite.TLS_AES_128_GCM_SHA256,
        'finished'.codeUnits,
      );

      final expectedFinished = HKDF_expand_label(
        baseSecret,
        Uint8List.fromList('finished'.codeUnits),
        Uint8List(0),
        32,
        'sha256',
      );

      expect(finishedKey, equals(expectedFinished));

      expect(
        () => calcKey(
          [3, 4],
          baseSecret,
          CipherSuite.TLS_AES_128_GCM_SHA256,
          'key'.codeUnits,
        ),
        throwsArgumentError,
      );

      final trafficKey = calcKey(
        [3, 4],
        baseSecret,
        CipherSuite.TLS_AES_128_GCM_SHA256,
        'key'.codeUnits,
        outputLength: 16,
      );

      final expectedKey = HKDF_expand_label(
        baseSecret,
        Uint8List.fromList('key'.codeUnits),
        Uint8List(0),
        16,
        'sha256',
      );

      expect(trafficKey, equals(expectedKey));
    });
  });

  group('SRP helpers', () {
    test('makeX produces consistent output', () {
      final salt = Uint8List.fromList(List<int>.filled(16, 0xAB));
      final username = 'alice'.codeUnits;
      final password = 'password123'.codeUnits;
      
      final x1 = makeX(salt, username, password);
      final x2 = makeX(salt, username, password);
      
      expect(x1, equals(x2));
      expect(x1, greaterThan(BigInt.zero));
    });

    test('makeX throws on long username', () {
      final salt = Uint8List(16);
      final username = List<int>.filled(256, 0x41);
      final password = 'pass'.codeUnits;
      
      expect(() => makeX(salt, username, password), throwsArgumentError);
    });

    test('makeX throws on long salt', () {
      final salt = Uint8List(256);
      final username = 'user'.codeUnits;
      final password = 'pass'.codeUnits;
      
      expect(() => makeX(salt, username, password), throwsArgumentError);
    });

    test('makeVerifier returns valid components', () {
      final username = 'testuser'.codeUnits;
      final password = 'testpass'.codeUnits;
      
      final (N, g, salt, verifier) = makeVerifier(username, password, 1024);
      
      expect(N, greaterThan(BigInt.zero));
      expect(g, equals(BigInt.from(2)));
      expect(salt.length, equals(16));
      expect(verifier, greaterThan(BigInt.zero));
      expect(verifier, lessThan(N));
    });

    test('makeVerifier supports various bit sizes', () {
      final username = 'user'.codeUnits;
      final password = 'pass'.codeUnits;
      
      for (final bits in [1024, 1536, 2048, 3072, 4096, 6144, 8192]) {
        final (N, g, salt, verifier) = makeVerifier(username, password, bits);
        expect(verifier, lessThan(N));
        expect(verifier, greaterThan(BigInt.zero));
      }
    });

    test('makeVerifier throws on invalid bit size', () {
      final username = 'user'.codeUnits;
      final password = 'pass'.codeUnits;
      
      expect(() => makeVerifier(username, password, 512), throwsArgumentError);
      expect(() => makeVerifier(username, password, 4000), throwsArgumentError);
    });

    test('pad adds leading zeros correctly', () {
      final n = BigInt.parse('FF' * 32, radix: 16);
      final x = BigInt.from(0x1234);
      
      final padded = pad(n, x);
      
      expect(padded.length, equals(32));
      expect(padded[padded.length - 2], equals(0x12));
      expect(padded[padded.length - 1], equals(0x34));
    });

    test('makeU produces consistent output', () {
      final N = BigInt.parse('FF' * 128, radix: 16);
      final A = BigInt.from(12345);
      final B = BigInt.from(67890);
      
      final u1 = makeU(N, A, B);
      final u2 = makeU(N, A, B);
      
      expect(u1, equals(u2));
      expect(u1, greaterThan(BigInt.zero));
    });

    test('makeK produces consistent output', () {
      final N = BigInt.parse('FF' * 128, radix: 16);
      final g = BigInt.from(2);
      
      final k1 = makeK(N, g);
      final k2 = makeK(N, g);
      
      expect(k1, equals(k2));
      expect(k1, greaterThan(BigInt.zero));
    });
  });

  group('FFDHE groups', () {
    test('goodGroupParameters has correct number of entries', () {
      expect(goodGroupParameters.length, equals(7));
    });

    test('all goodGroupParameters have valid primes', () {
      for (final group in goodGroupParameters) {
        expect(group.prime, greaterThan(BigInt.zero));
        expect(group.generator, greaterThan(BigInt.zero));
      }
    });
  });
}
