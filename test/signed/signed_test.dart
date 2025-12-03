import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:tlslite/src/signed.dart';
import 'package:tlslite/src/utils/eddsakey.dart';
import 'package:tlslite/src/utils/python_ecdsakey.dart';

void main() {
  group('SignatureSettings.validate', () {
    test('returns defaults when no overrides provided', () {
      final settings = SignatureSettings();
      final validated = settings.validate();
      expect(validated.minKeySize, 1023);
      expect(validated.maxKeySize, 8193);
      expect(validated.rsaSigHashes, orderedEquals(RSA_SIGNATURE_HASHES));
      expect(validated.rsaSchemes, orderedEquals(RSA_SCHEMES));
    });

    test('throws when min key size is too small', () {
      final settings = SignatureSettings(minKeySize: 256);
      expect(
        () => settings.validate(),
        throwsA(predicate((e) =>
            e is ArgumentError && e.toString().contains('min_key_size too small'))),
      );
    });

    test('throws when min key size is too large', () {
      final settings = SignatureSettings(minKeySize: 17000);
      expect(
        () => settings.validate(),
        throwsA(predicate((e) =>
            e is ArgumentError && e.toString().contains('min_key_size too large'))),
      );
    });

    test('throws when max key size is too small', () {
      final settings = SignatureSettings(maxKeySize: 256);
      expect(
        () => settings.validate(),
        throwsA(predicate((e) =>
            e is ArgumentError && e.toString().contains('max_key_size too small'))),
      );
    });

    test('throws when max key size is too large', () {
      final settings = SignatureSettings(maxKeySize: 17000);
      expect(
        () => settings.validate(),
        throwsA(predicate((e) =>
            e is ArgumentError && e.toString().contains('max_key_size too large'))),
      );
    });

    test('throws when min key size exceeds max key size', () {
      final settings = SignatureSettings(minKeySize: 2048, maxKeySize: 1024);
      expect(
        () => settings.validate(),
        throwsA(predicate((e) => e is ArgumentError &&
            e.toString().contains('max_key_size smaller than min_key_size'))),
      );
    });

    test('throws when signature algorithms include unsupported hashes', () {
      final settings = SignatureSettings(
        rsaSigHashes: ['sha1', 'sha128', 'sha129'],
      );
      expect(
        () => settings.validate(),
        throwsA(predicate((e) => e is ArgumentError &&
            e
                .toString()
                .contains('Following signature algorithms are not allowed: sha128, sha129'))),
      );
    });
  });

  group('SignedObject.verifySignature', () {
    test('verifies ecdsa-with-sha256 signature', () {
      final signer = PythonECDSAKey(
        curveName: 'secp256r1',
        secretMultiplier: BigInt.from(42),
      );
      final payload = Uint8List.fromList('ecdsa payload'.codeUnits);
      final signature = signer.hashAndSign(payload, hAlg: 'sha256');
      final signed = SignedObject()
        ..tbsData = payload
        ..signature = signature
        ..signatureAlgorithm = Uint8List.fromList(
          [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
        );

      expect(signed.verifySignature(signer), isTrue);
    });

    test('verifies Ed25519 signature', () {
      final seed = Uint8List.fromList(List<int>.generate(32, (i) => i));
      final signer = PythonEdDSAKey.ed25519(privateKey: seed);
      final payload = Uint8List.fromList('ed25519 payload'.codeUnits);
      final signature = signer.hashAndSign(payload);
      final signed = SignedObject()
        ..tbsData = payload
        ..signature = signature
        ..signatureAlgorithm = Uint8List.fromList([0x2b, 0x65, 0x70]);

      expect(signed.verifySignature(signer), isTrue);
    });

    test('throws when key type mismatches signature algorithm', () {
      final payload = Uint8List.fromList([1, 2, 3]);
      final signed = SignedObject()
        ..tbsData = payload
        ..signature = Uint8List.fromList([0])
        ..signatureAlgorithm = Uint8List.fromList(
          [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b],
        );
      final ecdsaKey = PythonECDSAKey(
        curveName: 'secp256r1',
        secretMultiplier: BigInt.from(7),
      );

      expect(
        () => signed.verifySignature(ecdsaKey),
        throwsA(isA<ArgumentError>()
          .having((e) => e.message, 'message', contains('RSA signature requires an RSAKey'))),
      );
    });
  });
}
