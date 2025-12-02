import 'package:test/test.dart';

import 'package:tlslite/src/signed.dart';

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
}
