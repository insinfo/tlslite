import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:tlslite/src/ed448/ed448.dart' as ed448;
import 'package:tlslite/src/utils/eddsakey.dart';
import 'package:tlslite/src/utils/keyfactory.dart';

void main() {
  late DartEdDSAKey privateKey;
  late Uint8List seed;

  setUp(() {
    seed = Uint8List.fromList(
      List<int>.generate(32, (index) => index + 1),
    );
    privateKey = DartEdDSAKey.ed25519(privateKey: seed);
  });

  test('write serializes Ed25519 private key to PKCS#8 PEM', () {
    final pemData = privateKey.write();
    expect(pemData, contains('-----BEGIN PRIVATE KEY-----'));
    final parsed = parsePrivateKey(pemData) as DartEdDSAKey;
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
    ) as DartEdDSAKey;
    expect(parsed.curveName, equals('Ed25519'));
    expect(parsed.hasPrivateKey(), isTrue);
  });

  test('write serializes Ed25519 public key to SPKI PEM', () {
    final publicOnly =
        DartEdDSAKey.ed25519(publicKey: privateKey.publicKeyBytes);
    final pemData = publicOnly.write();
    expect(pemData, contains('-----BEGIN PUBLIC KEY-----'));
    final parsed = parseAsPublicKey(pemData) as DartEdDSAKey;
    expect(parsed.curveName, equals('Ed25519'));
    expect(parsed.hasPrivateKey(), isFalse);
  });

  group('Ed448 keys', () {
    late Uint8List ed448Seed;
    late Uint8List ed448Public;

    setUp(() {
      // Generate a valid Ed448 key pair from a seed
      ed448Seed = Uint8List.fromList(
        List<int>.generate(57, (index) => (index * 3 + 1) & 0xff),
      );
      // Use the real Ed448 implementation to derive the public key
      final ed448Impl = ed448.Ed448PrivateKeyImpl.fromSeed(ed448Seed);
      ed448Public = ed448Impl.publicKeyBytes;
    });

    test('public key serializes to SPKI PEM', () {
      final publicKey = Ed448PublicKey(ed448Public);
      final pemData = publicKey.write();
      expect(pemData, contains('-----BEGIN PUBLIC KEY-----'));
      final parsed = parseAsPublicKey(pemData);
      expect(parsed, isA<Ed448PublicKey>());
      expect((parsed as Ed448PublicKey).publicKeyBytes, equals(ed448Public));
    });

    test('private key serializes and decrypts via password', () {
      final privateEd448 = Ed448PrivateKey(
        privateKeyBytes: ed448Seed,
        publicKeyBytes: ed448Public,
      );
      final pemData = privateEd448.write(password: 'hunter2');
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

    test('Ed448 sign and verify', () {
      final privateEd448 = Ed448PrivateKey(
        privateKeyBytes: ed448Seed,
        publicKeyBytes: ed448Public,
      );
      final message = Uint8List.fromList([1, 2, 3, 4, 5]);
      final signature = privateEd448.hashAndSign(message);
      expect(signature.length, equals(114));
      
      final publicKey = Ed448PublicKey(ed448Public);
      expect(publicKey.hashAndVerify(signature, message), isTrue);
      
      // Tampered message should fail
      final tamperedMessage = Uint8List.fromList([1, 2, 3, 4, 6]);
      expect(publicKey.hashAndVerify(signature, tamperedMessage), isFalse);
    });
  });
}
