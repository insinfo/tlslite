import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:tlslite/src/utils/eddsakey.dart';
import 'package:tlslite/src/utils/keyfactory.dart';

void main() {
  late PythonEdDSAKey privateKey;
  late Uint8List seed;

  setUp(() {
    seed = Uint8List.fromList(
      List<int>.generate(32, (index) => index + 1),
    );
    privateKey = PythonEdDSAKey.ed25519(privateKey: seed);
  });

  test('write serializes Ed25519 private key to PKCS#8 PEM', () {
    final pemData = privateKey.write();
    expect(pemData, contains('-----BEGIN PRIVATE KEY-----'));
    final parsed = parsePrivateKey(pemData) as PythonEdDSAKey;
    expect(parsed.curveName, equals('Ed25519'));
    expect(parsed.hasPrivateKey(), isTrue);
  });

  test('write serializes Ed25519 private key to encrypted PKCS#8 when password set', () {
    final pemData = privateKey.write(password: 'hunter2');
    expect(pemData, contains('-----BEGIN ENCRYPTED PRIVATE KEY-----'));
    final parsed = parsePEMKey(
      pemData,
      private: true,
      passwordCallback: () => 'hunter2',
    ) as PythonEdDSAKey;
    expect(parsed.curveName, equals('Ed25519'));
    expect(parsed.hasPrivateKey(), isTrue);
  });

  test('write serializes Ed25519 public key to SPKI PEM', () {
    final publicOnly =
        PythonEdDSAKey.ed25519(publicKey: privateKey.publicKeyBytes);
    final pemData = publicOnly.write();
    expect(pemData, contains('-----BEGIN PUBLIC KEY-----'));
    final parsed = parseAsPublicKey(pemData) as PythonEdDSAKey;
    expect(parsed.curveName, equals('Ed25519'));
    expect(parsed.hasPrivateKey(), isFalse);
  });

  group('Ed448 placeholders', () {
    late Uint8List ed448Seed;
    late Uint8List ed448Public;

    setUp(() {
      ed448Seed = Uint8List.fromList(
        List<int>.generate(57, (index) => (index * 3) & 0xff),
      );
      ed448Public = Uint8List.fromList(
        List<int>.generate(57, (index) => (255 - index) & 0xff),
      );
    });

    test('public placeholder serializes to SPKI PEM', () {
      final publicKey = Ed448PublicKey(ed448Public);
      final pemData = publicKey.write();
      expect(pemData, contains('-----BEGIN PUBLIC KEY-----'));
      final parsed = parseAsPublicKey(pemData);
      expect(parsed, isA<Ed448PublicKey>());
      expect((parsed as Ed448PublicKey).publicKeyBytes, equals(ed448Public));
    });

    test('private placeholder serializes and decrypts via password', () {
      final privatePlaceholder = Ed448PrivateKey(
        privateKeyBytes: ed448Seed,
        publicKeyBytes: ed448Public,
      );
      final pemData = privatePlaceholder.write(password: 'hunter2');
      expect(pemData, contains('-----BEGIN ENCRYPTED PRIVATE KEY-----'));
      final parsed = parsePEMKey(
        pemData,
        private: true,
        passwordCallback: () => 'hunter2',
      );
      expect(parsed, isA<Ed448PrivateKey>());
      final decoded = parsed as Ed448PrivateKey;
      expect(decoded.publicKeyBytes, equals(ed448Public));
      expect(decoded.hasPrivateKey(), isTrue);
    });
  });
}
