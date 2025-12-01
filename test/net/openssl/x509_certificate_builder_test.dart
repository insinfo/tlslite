import 'package:test/test.dart';
import 'package:tlslite/src/net/openssl/openssl_loader.dart';
import 'package:tlslite/src/net/openssl/x509_certificate_builder.dart';

void main() {
  final builderResult = _BuilderResult.load();

  group('X509CertificateBuilder', () {
    test(
      'generates PEM for key and certificate',
      () {
        final builder = builderResult.builder!;
        final key = builder.generateKeyPair();
        final cert = builder.createSelfSignedCertificate(key);

        final certPem = builder.x509ToPem(cert);
        final keyPem = builder.privateKeyToPem(key);

        expect(certPem, contains('BEGIN CERTIFICATE'));
        expect(keyPem, contains('BEGIN PRIVATE KEY'));

        builder.libcrypt.X509_free(cert);
        builder.libcrypt.EVP_PKEY_free(key);
      },
      skip: builderResult.skipReason,
    );
  });
}

class _BuilderResult {
  const _BuilderResult({this.builder, this.skipReason});

  final X509CertificateBuilder? builder;
  final String? skipReason;

  static _BuilderResult load() {
    try {
      return _BuilderResult(
        builder: X509CertificateBuilder.withSystemLibraries(),
      );
    } on OpenSslLoadException catch (error) {
      return _BuilderResult(skipReason: error.message);
    } catch (error) {
      return _BuilderResult(skipReason: 'Failed to load OpenSSL: $error');
    }
  }
}
