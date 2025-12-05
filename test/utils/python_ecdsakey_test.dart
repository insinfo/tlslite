import 'package:test/test.dart';

import 'package:tlslite/src/utils/keyfactory.dart';
import 'package:tlslite/src/utils/python_ecdsakey.dart';

void main() {
  late PythonECDSAKey privateKey;

  setUp(() {
    privateKey = PythonECDSAKey(
      curveName: 'secp256r1',
      secretMultiplier: BigInt.from(123456789),
    );
  });

  test('write serializes EC private key to PEM', () {
    final pemData = privateKey.write();
    expect(pemData, contains('-----BEGIN EC PRIVATE KEY-----'));
    final parsed = parsePrivateKey(pemData) as PythonECDSAKey;
    expect(parsed.curveName, equals(privateKey.curveName));
    expect(parsed.secretMultiplier, equals(privateKey.secretMultiplier));
    expect(parsed.publicPointX, equals(privateKey.publicPointX));
    expect(parsed.publicPointY, equals(privateKey.publicPointY));
  });

  test('write serializes EC private key to encrypted PKCS#8 when password set', () {
    final pemData = privateKey.write(password: 'hunter2');
    expect(pemData, contains('-----BEGIN ENCRYPTED PRIVATE KEY-----'));
    final parsed = parsePEMKey(
      pemData,
      private: true,
      passwordCallback: () => 'hunter2',
    ) as PythonECDSAKey;
    expect(parsed.curveName, equals(privateKey.curveName));
    expect(parsed.secretMultiplier, equals(privateKey.secretMultiplier));
  });

  test('write serializes EC public key to SPKI PEM', () {
    final publicOnly = PythonECDSAKey(
      pointX: privateKey.publicPointX,
      pointY: privateKey.publicPointY,
      curveName: privateKey.curveName,
    );
    final pemData = publicOnly.write();
    expect(pemData, contains('-----BEGIN PUBLIC KEY-----'));
    final parsed = parseAsPublicKey(pemData) as PythonECDSAKey;
    expect(parsed.curveName, equals(publicOnly.curveName));
    expect(parsed.hasPrivateKey(), isFalse);
    expect(parsed.publicPointX, equals(publicOnly.publicPointX));
    expect(parsed.publicPointY, equals(publicOnly.publicPointY));
  });
}
