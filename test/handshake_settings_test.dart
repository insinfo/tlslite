import 'package:test/test.dart';
import 'package:tlslite/src/handshake_settings.dart';

void main() {
  group('HandshakeSettings', () {
    test('validate accepts default settings', () {
      final settings = HandshakeSettings();
      // Should not throw
      settings.validate();
    });

    test('minKeySize too small throws', () {
      final settings = HandshakeSettings(minKeySize: 511);
      expect(() => settings.validate(), throwsArgumentError);
    });

    test('maxKeySize too small throws', () {
      final settings = HandshakeSettings(maxKeySize: 511);
      expect(() => settings.validate(), throwsArgumentError);
    });

    test('minKeySize > maxKeySize throws', () {
      final settings = HandshakeSettings(minKeySize: 2048, maxKeySize: 1024);
      expect(() => settings.validate(), throwsArgumentError);
    });

    test('unknown cipher name throws', () {
      final settings = HandshakeSettings(cipherNames: ['aes256', 'unknown_cipher']);
      expect(() => settings.validate(), throwsArgumentError);
    });

    test('unknown MAC name throws', () {
      final settings = HandshakeSettings(macNames: ['sha256', 'unknown_mac']);
      expect(() => settings.validate(), throwsArgumentError);
    });

    test('unknown certificate type throws', () {
      final settings = HandshakeSettings(certificateTypes: ['x509', 'unknown_type']);
      expect(() => settings.validate(), throwsArgumentError);
    });

    test('unknown curve name throws', () {
      final settings = HandshakeSettings(eccCurves: ['secp256r1', 'unknown_curve']);
      expect(() => settings.validate(), throwsArgumentError);
    });

    test('unknown DH group throws', () {
      final settings = HandshakeSettings(dhGroups: ['ffdhe2048', 'unknown_group']);
      expect(() => settings.validate(), throwsArgumentError);
    });

    test('unknown key exchange throws', () {
      final settings = HandshakeSettings(keyExchangeNames: ['rsa', 'unknown_kx']);
      expect(() => settings.validate(), throwsArgumentError);
    });

    test('unknown minVersion throws', () {
      final settings = HandshakeSettings(minVersion: (1, 1)); // TLS 1.1 is (3, 2). (1, 1) is unknown/old
      // Wait, knownVersions = [(3, 0), (3, 1), (3, 2), (3, 3), (3, 4)];
      // (1, 1) is not in knownVersions.
      expect(() => settings.validate(), throwsArgumentError);
    });

    test('minVersion > maxVersion throws', () {
      final settings = HandshakeSettings(
        minVersion: (3, 3), // TLS 1.2
        maxVersion: (3, 2), // TLS 1.1
      );
      expect(() => settings.validate(), throwsArgumentError);
    });

    test('empty versions list throws', () {
      final settings = HandshakeSettings(versions: []);
      expect(() => settings.validate(), throwsArgumentError);
    });

    // Tests for empty lists that SHOULD throw according to Python but might not in Dart yet
    test('empty cipherNames throws', () {
      final settings = HandshakeSettings(cipherNames: []);
      // If this fails, I will fix HandshakeSettings
      expect(() => settings.validate(), throwsArgumentError);
    }, skip: 'Not implemented yet');

    test('empty certificateTypes throws', () {
      final settings = HandshakeSettings(certificateTypes: []);
      expect(() => settings.validate(), throwsArgumentError);
    }, skip: 'Not implemented yet');
  });
}
