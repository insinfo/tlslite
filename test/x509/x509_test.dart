import 'package:test/test.dart';

import 'package:tlslite/src/utils/dsakey.dart';
import 'package:tlslite/src/utils/eddsakey.dart';
import 'package:tlslite/src/utils/dart_ecdsakey.dart';
import 'package:tlslite/src/x509.dart';
import 'package:tlslite/src/x509certchain.dart';

void main() {
  group('X509 DSA certificate', () {
    test('parses public key parameters', () {
      final cert = X509()..parse(_dsaCertPem);
      expect(cert.publicKey, isA<DartDSAKey>());
      final key = cert.publicKey as DartDSAKey;
      expect(
        key.y,
        equals(
          BigInt.parse(
            '16798405106129606882295006910154614336997455047535738179977898112652777747305',
          ),
        ),
      );
      expect(
        key.p,
        equals(
          BigInt.parse(
            '69602034731989554929546346371414762967051205729581487767213360812510562307621',
          ),
        ),
      );
      expect(
        key.q,
        equals(
          BigInt.parse('907978205720450240238233398695599264980368073799'),
        ),
      );
      expect(
        key.g,
        equals(
          BigInt.parse(
            '44344860785224683582210580276798141855549498608976964582640232671615126065387',
          ),
        ),
      );
    });
  });

  group('X509 ECDSA certificate', () {
    test('parses public key and supports equality', () {
      final cert = X509()..parse(_ecdsaCertPem);
      expect(cert.publicKey, isA<DartECDSAKey>());
      final key = cert.publicKey as DartECDSAKey;
      expect(
        key.publicPointX,
        equals(
          BigInt.parse(
            '90555129468518880658937518803653422065597446465131062487534800201457796212578',
          ),
        ),
      );
      expect(
        key.publicPointY,
        equals(
          BigInt.parse(
            '12490546948316647166662676770106859255378658810545502161335656899238893361610',
          ),
        ),
      );
      expect(key.curveName.toLowerCase(), 'secp256r1');

      final cert2 = X509()..parse(_ecdsaCertPem);
      expect(cert, equals(cert2));
      expect(cert.hashCode, equals(cert2.hashCode));
    });
  });

  group('X509 certificate chain', () {
    test('parses PEM list and compares chains', () {
      final chain1 = X509CertChain()..parsePemList(_ecdsaCertPem);
      final chain2 = X509CertChain()..parsePemList(_ecdsaCertPem);
      expect(chain1.getNumCerts(), 1);
      expect(chain1.getEndEntityPublicKey(), isA<DartECDSAKey>());
      expect(chain1, equals(chain2));
      expect(chain1.hashCode, equals(chain2.hashCode));
      expect(chain1.getFingerprint(), chain2.getFingerprint());
    });
  });

  group('X509 EdDSA certificates', () {
    test('parses Ed25519 certificate', () {
      final cert = X509()..parse(_ed25519CertPem);
      expect(cert.publicKey, isA<EdDSAKey>());
      expect(cert.certAlg, 'Ed25519');
    });

    test('parses Ed448 certificate (stub)', () {
      final cert = X509()..parse(_ed448CertPem);
      expect(cert.publicKey, isA<EdDSAKey>());
      expect(cert.certAlg, 'Ed448');
    });
  });
}

const _dsaCertPem = '''
-----BEGIN CERTIFICATE-----
MIIBQjCCAQACFFyBKCftN0cXDwuMuZWvtW7uG2xGMAsGCWCGSAFlAwQDAjAUMRIw
EAYDVQQDDAlsb2NhbGhvc3QwHhcNMjAwOTAzMDkwNzUxWhcNMjAxMDAzMDkwNzUx
WjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwgY4wZwYHKoZIzjgEATBcAiEAmeFbCUhV
UZgVpljXObhmRaQYIQ12YSr9zlCja2kpTiUCFQCfCyagvEDkgK5nHqscaYlF32ek
RwIgYgpNP8JjVxfJ4P3IErO07qqzWS21hSyMhsaCN0an0OsDIwACICUjj3Np+JO4
2v8Mc8oH6T8yNd5X0ssy8XdK3Bo9nfNpMAsGCWCGSAFlAwQDAgMvADAsAhRgjSkX
k9nkSQc2P3uA+fFEH2OOnAIUZnBeKDjTEMawkvRSXoGHhA93qQ4=
-----END CERTIFICATE-----
''';

const _ecdsaCertPem = '''
-----BEGIN CERTIFICATE-----
MIIBbTCCARSgAwIBAgIJAPM58cskyK+yMAkGByqGSM49BAEwFDESMBAGA1UEAwwJ
bG9jYWxob3N0MB4XDTE3MTAyMzExNDI0MVoXDTE3MTEyMjExNDI0MVowFDESMBAG
A1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyDRjEAJe
3F5T62MyZbhjoJnPLGL2nrTthLFymBupZ2IbnWYnqVWDkT/L6i8sQhf2zCLrlSjj
1kn7ERqPx/KZyqNQME4wHQYDVR0OBBYEFPfFTUg9o3t6ehLsschSnC8Te8oaMB8G
A1UdIwQYMBaAFPfFTUg9o3t6ehLsschSnC8Te8oaMAwGA1UdEwQFMAMBAf8wCQYH
KoZIzj0EAQNIADBFAiA6p0YM5ZzfW+klHPRU2r13/IfKgeRfDR3dtBngmPvxUgIh
APTeSDeJvYWVBLzyrKTeSerNDKKHU2Rt7sufipv76+7s
-----END CERTIFICATE-----
''';

const _ed25519CertPem = '''
-----BEGIN CERTIFICATE-----
MIIBPDCB76ADAgECAhQkqENccCvOQyI4iKFuuOKwl860bTAFBgMrZXAwFDESMBAG
A1UEAwwJbG9jYWxob3N0MB4XDTIxMDcyNjE0MjcwN1oXDTIxMDgyNTE0MjcwN1ow
FDESMBAGA1UEAwwJbG9jYWxob3N0MCowBQYDK2VwAyEA1KMGmAZealfgakBuCx/E
n69fo072qm90eM40ulGex0ajUzBRMB0GA1UdDgQWBBTHKWv5l/SxnkkYJhh5r3Pv
ESAh1DAfBgNVHSMEGDAWgBTHKWv5l/SxnkkYJhh5r3PvESAh1DAPBgNVHRMBAf8E
BTADAQH/MAUGAytlcANBAF/vSBfOHAdRl29sWDTkuqy1dCuSf7j7jKE/Be8Fk7xs
WteXJmIa0HlRAZjxNfWbsSGLnTYbsGTbxKx3QU9H9g0=
-----END CERTIFICATE-----
''';

const _ed448CertPem = '''
-----BEGIN CERTIFICATE-----
MIIBiDCCAQigAwIBAgIUZoaDDgE5Cy2GuAMtk4lnsmrPF04wBQYDK2VxMBQxEjAQ
BgNVBAMMCWxvY2FsaG9zdDAeFw0yMTA3MjYxODAzMzhaFw0yMTA4MjUxODAzMzha
MBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBDMAUGAytlcQM6AKxTNGJ39O4kUx7BopPK
prb1Jkoo0csq0Cmpa+VhpDlbR9/gVsb3pchexzjxXyRkNv71naHmOkQvAKNTMFEw
HQYDVR0OBBYEFBb153yRh5IZOfBxoakGVuviFKujMB8GA1UdIwQYMBaAFBb153yR
h5IZOfBxoakGVuviFKujMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VxA3MAiXEqTPRb
u+56ebfiGjdE++H+YvHVxxxycqKAIAikfsLFfw2LUGQVBMhl+nzS4zRDOKa34uGz
DwEApFuOWurH/y8zqM5NFyXfwbHRlhG4xwUet52CbrtC7Dy1HYnvWdEjbKDSJXpJ
MmNSiO0oBtQ62CsA
-----END CERTIFICATE-----
''';
