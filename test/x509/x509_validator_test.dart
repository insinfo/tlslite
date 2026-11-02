@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/tlslite.dart';
import 'package:tlslite/src/utils/keyfactory.dart';

const _dir = 'test/certificates/validation';

X509 _cert(String name) => X509()..parse(File('$_dir/$name.pem').readAsStringSync());

X509CertChain _chain(List<String> names) =>
    X509CertChain([for (final n in names) _cert(n)]);

final _now = DateTime.utc(2026, 6, 1);

Matcher _fails(CertificateVerificationFailure reason) => throwsA(
    isA<TLSCertificateVerificationError>().having((e) => e.reason, 'reason', reason));

void main() {
  late X509Validator rsaValidator;
  late X509Validator ecValidator;
  late X509Validator bothValidator;

  setUpAll(() {
    rsaValidator = X509Validator([_cert('rsa_root')]);
    ecValidator = X509Validator([_cert('ec_root')]);
    bothValidator = X509Validator([_cert('rsa_root'), _cert('ec_root')]);
  });

  group('X509.verify', () {
    final cases = {
      'RSA PKCS#1 SHA-256 self-signed': ('rsa_root', 'rsa_root'),
      'RSA PKCS#1 SHA-384': ('rsa_int', 'rsa_root'),
      'RSA PKCS#1 SHA-256': ('rsa_leaf', 'rsa_int'),
      'RSA PKCS#1 SHA-512': ('rsa_leaf_sha512', 'rsa_int'),
      'RSA-PSS SHA-256 salt 32': ('rsa_leaf_pss', 'rsa_int'),
      'ECDSA P-384 SHA-384 self-signed': ('ec_root', 'ec_root'),
      'ECDSA P-384 key, SHA-384': ('ec_int', 'ec_root'),
      'ECDSA P-256 SHA-256': ('ec_leaf', 'ec_int'),
      'ECDSA P-256 SHA-512': ('ec_leaf_sha512', 'ec_int'),
    };
    cases.forEach((name, pair) {
      test(name, () {
        final cert = _cert(pair.$1);
        final issuer = _cert(pair.$2);
        expect(cert.verify(issuer.publicKey!), isTrue);
      });
    });

    test('rejects wrong issuer key and mismatched key type', () {
      expect(_cert('rsa_leaf').verify(_cert('rsa_root').publicKey!), isFalse);
      expect(_cert('ec_leaf').verify(_cert('ec_root').publicKey!), isFalse);
      expect(_cert('rsa_leaf').verify(_cert('ec_int').publicKey!), isFalse);
      expect(_cert('ec_leaf').verify(_cert('rsa_int').publicKey!), isFalse);
    });

    test('rejects a tampered signature', () {
      final cert = _cert('rsa_leaf');
      cert.signatureValue![10] ^= 0x01;
      expect(cert.verify(_cert('rsa_int').publicKey!), isFalse);
      final ec = _cert('ec_leaf');
      ec.signatureValue![ec.signatureValue!.length - 3] ^= 0x01;
      expect(ec.verify(_cert('ec_int').publicKey!), isFalse);
    });

    test('parses extensions', () {
      final leaf = _cert('rsa_leaf');
      expect(leaf.dnsNames, ['server.test', '*.wild.test']);
      expect(leaf.ipAddresses!.map((e) => e.length), [4, 16]);
      expect(leaf.isCA, isFalse);
      expect(leaf.keyUsage, {'digitalSignature', 'keyEncipherment'});
      expect(leaf.extendedKeyUsage, [oidServerAuth]);
      expect(leaf.subjectCommonNames, ['server.test']);
      final inter = _cert('rsa_int');
      expect(inter.isCA, isTrue);
      expect(inter.pathLenConstraint, 0);
      expect(inter.keyUsage, {'keyCertSign', 'cRLSign'});
      expect(inter.criticalExtensions, containsAll(['2.5.29.19', '2.5.29.15']));
      expect(inter.subjectString, 'O=tlslite test, CN=Test RSA Intermediate CA');
    });
  });

  group('X509Validator path validation', () {
    test('RSA root -> intermediate -> leaf', () {
      final path = rsaValidator.validate(_chain(['rsa_leaf', 'rsa_int']),
          hostname: 'server.test', now: _now);
      expect(path.map((c) => c.subjectCommonNames.single),
          ['server.test', 'Test RSA Intermediate CA', 'Test RSA Root CA']);
    });

    test('RSA chain including the root and with SHA-512 / PSS leaves', () {
      rsaValidator.validate(_chain(['rsa_leaf', 'rsa_int', 'rsa_root']),
          hostname: 'server.test', now: _now);
      rsaValidator.validate(_chain(['rsa_leaf_sha512', 'rsa_int']),
          hostname: 'server.test', now: _now);
      rsaValidator.validate(_chain(['rsa_leaf_pss', 'rsa_int']),
          hostname: 'server.test', now: _now);
    });

    test('out-of-order intermediates and unrelated extras are tolerated', () {
      bothValidator.validate(
          _chain(['rsa_leaf', 'ec_int', 'evil_root', 'rsa_int']),
          hostname: 'server.test',
          now: _now);
    });

    test('ECDSA P-384 root -> P-256 intermediate -> P-256 leaf', () {
      final path = ecValidator.validate(_chain(['ec_leaf', 'ec_int']),
          hostname: 'server.test', now: _now);
      expect(path, hasLength(3));
      ecValidator.validate(_chain(['ec_leaf_sha512', 'ec_int']),
          hostname: 'server.test', now: _now);
    });

    test('uses the current time by default', () {
      rsaValidator.validate(_chain(['rsa_leaf', 'rsa_int']),
          hostname: 'server.test');
    });

    test('trust anchor can be an intermediate', () {
      X509Validator([_cert('rsa_int')]).validate(_chain(['rsa_leaf']),
          hostname: 'server.test', now: _now);
    });

    test('missing intermediate -> unknownIssuer', () {
      expect(
          () => rsaValidator.validate(_chain(['rsa_leaf']), now: _now),
          _fails(CertificateVerificationFailure.unknownIssuer));
    });

    test('untrusted CA -> unknownIssuer', () {
      expect(
          () => rsaValidator.validate(_chain(['evil_leaf', 'evil_root']),
              hostname: 'server.test', now: _now),
          _fails(CertificateVerificationFailure.unknownIssuer));
    });

    test('ECDSA chain against RSA anchors -> unknownIssuer', () {
      expect(
          () => rsaValidator.validate(_chain(['ec_leaf', 'ec_int']), now: _now),
          _fails(CertificateVerificationFailure.unknownIssuer));
    });

    test('expired leaf', () {
      expect(
          () => rsaValidator.validate(_chain(['rsa_expired', 'rsa_int']),
              hostname: 'server.test', now: _now),
          _fails(CertificateVerificationFailure.expired));
    });

    test('not yet valid / expired intermediate', () {
      expect(
          () => rsaValidator.validate(_chain(['rsa_leaf', 'rsa_int']),
              now: DateTime.utc(2024, 1, 1)),
          _fails(CertificateVerificationFailure.notYetValid));
      expect(
          () => rsaValidator.validate(_chain(['rsa_leaf', 'rsa_int']),
              now: DateTime.utc(2046, 1, 1)),
          _fails(CertificateVerificationFailure.expired));
    });

    test('issuer that is not a CA -> notCA', () {
      expect(
          () => rsaValidator.validate(
              _chain(['rsa_by_leaf', 'rsa_leaf', 'rsa_int']),
              now: _now),
          _fails(CertificateVerificationFailure.notCA));
    });

    test('pathLenConstraint violation', () {
      expect(
          () => rsaValidator.validate(
              _chain(['rsa_subleaf', 'rsa_subca', 'rsa_int']),
              now: _now),
          _fails(CertificateVerificationFailure.pathLengthExceeded));
    });

    test('issuer keyUsage without keyCertSign', () {
      expect(
          () => rsaValidator.validate(
              _chain(['rsa_noksign_leaf', 'rsa_noksign']),
              now: _now),
          _fails(CertificateVerificationFailure.keyUsage));
    });

    test('leaf EKU without serverAuth', () {
      expect(
          () => rsaValidator.validate(_chain(['rsa_clientauth', 'rsa_int']),
              now: _now),
          _fails(CertificateVerificationFailure.extendedKeyUsage));
      // Accepted when validating a client certificate.
      X509Validator([_cert('rsa_root')], requiredExtendedKeyUsage: oidClientAuth)
          .validate(_chain(['rsa_clientauth', 'rsa_int']), now: _now);
    });

    test('tampered leaf signature -> badSignature', () {
      final leaf = _cert('rsa_leaf');
      leaf.signatureValue![20] ^= 0xff;
      expect(
          () => rsaValidator.validateCertificates([leaf, _cert('rsa_int')],
              now: _now),
          _fails(CertificateVerificationFailure.badSignature));
    });

    test('empty chain -> noCertificate', () {
      expect(() => rsaValidator.validate(null),
          _fails(CertificateVerificationFailure.noCertificate));
      expect(() => rsaValidator.validate(X509CertChain()),
          _fails(CertificateVerificationFailure.noCertificate));
    });

    test('maxDepth', () {
      expect(
          () => X509Validator([_cert('rsa_root')], maxDepth: 2)
              .validate(_chain(['rsa_leaf', 'rsa_int']), now: _now),
          _fails(CertificateVerificationFailure.chainTooLong));
    });

    test('errors are TLSAuthenticationError with a clear message', () {
      try {
        rsaValidator.validate(_chain(['evil_leaf', 'evil_root']), now: _now);
        fail('should throw');
      } on TLSAuthenticationError catch (e) {
        expect(e.toString(), contains('Untrusted Root CA'));
      }
    });
  });

  group('self-signed certificate (sqlserver.crt)', () {
    late X509 selfSigned;
    setUpAll(() => selfSigned = _cert('sqlserver_selfsigned'));

    test('trusted when it is itself the anchor', () {
      final v = X509Validator([selfSigned]);
      v.validate(X509CertChain([selfSigned]), hostname: 'localhost', now: _now);
      v.validate(X509CertChain([selfSigned]), hostname: '127.0.0.1', now: _now);
      v.validate(X509CertChain([selfSigned]), hostname: 'LOCALHOST.', now: _now);
    });

    test('rejected when not an anchor', () {
      expect(
          () => rsaValidator.validate(X509CertChain([selfSigned]),
              hostname: 'localhost', now: _now),
          _fails(CertificateVerificationFailure.selfSigned));
    });

    test('hostname mismatch', () {
      final v = X509Validator([selfSigned]);
      expect(
          () => v.validate(X509CertChain([selfSigned]),
              hostname: 'db.example.com', now: _now),
          _fails(CertificateVerificationFailure.hostnameMismatch));
      expect(
          () => v.validate(X509CertChain([selfSigned]),
              hostname: '127.0.0.2', now: _now),
          _fails(CertificateVerificationFailure.hostnameMismatch));
    });
  });

  group('hostname matching', () {
    late X509 leaf;
    setUpAll(() => leaf = _cert('rsa_leaf'));

    test('DNS names, case-insensitive, trailing dot', () {
      expect(X509Validator.matchesHostname(leaf, 'server.test'), isTrue);
      expect(X509Validator.matchesHostname(leaf, 'SERVER.Test'), isTrue);
      expect(X509Validator.matchesHostname(leaf, 'server.test.'), isTrue);
      expect(X509Validator.matchesHostname(leaf, 'other.test'), isFalse);
      expect(X509Validator.matchesHostname(leaf, 'sub.server.test'), isFalse);
    });

    test('wildcard covers exactly one left-most label', () {
      expect(X509Validator.matchesHostname(leaf, 'a.wild.test'), isTrue);
      expect(X509Validator.matchesHostname(leaf, 'A.WILD.TEST'), isTrue);
      expect(X509Validator.matchesHostname(leaf, 'wild.test'), isFalse);
      expect(X509Validator.matchesHostname(leaf, 'a.b.wild.test'), isFalse);
      expect(X509Validator.matchesHostname(leaf, '.wild.test'), isFalse);
    });

    test('IP addresses only match iPAddress SANs', () {
      expect(X509Validator.matchesHostname(leaf, '127.0.0.1'), isTrue);
      expect(X509Validator.matchesHostname(leaf, '::1'), isTrue);
      expect(X509Validator.matchesHostname(leaf, '[::1]'), isTrue);
      expect(X509Validator.matchesHostname(leaf, '0:0:0:0:0:0:0:1'), isTrue);
      expect(X509Validator.matchesHostname(leaf, '127.0.0.2'), isFalse);
      expect(X509Validator.matchesHostname(leaf, '::2'), isFalse);
    });

    test('leaf for another host is rejected', () {
      expect(
          () => rsaValidator.validate(_chain(['rsa_other', 'rsa_int']),
              hostname: 'server.test', now: _now),
          _fails(CertificateVerificationFailure.hostnameMismatch));
      rsaValidator.validate(_chain(['rsa_other', 'rsa_int']),
          hostname: 'other.test', now: _now);
    });

    test('CN fallback only without DNS/IP SANs', () {
      final cnOnly = _cert('rsa_cn_only');
      expect(cnOnly.dnsNames, isNull);
      expect(X509Validator.matchesHostname(cnOnly, 'cn-only.test'), isTrue);
      expect(X509Validator.matchesHostname(cnOnly, 'other.test'), isFalse);
      // rsa_leaf has CN=server.test *and* SANs: CN is not consulted for a
      // name that is only in the CN.
      expect(X509Validator.matchesHostname(_cert('rsa_other'), 'other.test'),
          isTrue);
      rsaValidator.validate(_chain(['rsa_cn_only', 'rsa_int']),
          hostname: 'cn-only.test', now: _now);
    });

    test('hostname null skips the host check', () {
      rsaValidator.validate(_chain(['rsa_other', 'rsa_int']), now: _now);
    });
  });

  group('trust anchor loading', () {
    test('loadPemCertificates handles bundles with other blocks', () {
      final bundle = [
        'some comment',
        File('$_dir/rsa_root.pem').readAsStringSync(),
        File('$_dir/sqlserver_selfsigned.key').readAsStringSync(),
        'garbage between blocks',
        File('$_dir/ec_root.pem').readAsStringSync(),
      ].join('\n');
      final certs = loadPemCertificates(bundle);
      expect(certs, hasLength(2));
      expect(certs[0], equals(_cert('rsa_root')));
      expect(certs[1], equals(_cert('ec_root')));
    });

    test('/etc/ssl/cert.pem parses into > 50 anchors', () {
      final anchors =
          loadPemCertificatesFromFile('/etc/ssl/cert.pem');
      expect(anchors.length, greaterThan(50));
      final system = loadSystemTrustAnchors();
      expect(system, isNotNull);
      expect(system!.length, greaterThan(50));
      for (final a in system) {
        expect(a.subject, isNotNull);
        expect(a.publicKey, isNotNull);
      }
    }, skip: File('/etc/ssl/cert.pem').existsSync()
        ? false
        : '/etc/ssl/cert.pem not present on this system');
  });

  group('handshake integration (checker)', () {
    late X509CertChain serverChain;
    late Object serverKey;

    setUpAll(() {
      serverChain = X509CertChain()
        ..parsePemList(File('$_dir/sqlserver_selfsigned.pem').readAsStringSync());
      serverKey = parsePrivateKey(
          File('$_dir/sqlserver_selfsigned.key').readAsStringSync());
    });

    Future<Object?> runHandshake(Checker checker, (int, int) version) async {
      final serverSocket = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      final serverResult = Completer<Object?>();
      serverSocket.listen((socket) async {
        final tls = TlsConnection(socket);
        try {
          await tls.handshakeServer(
            settings: HandshakeSettings(minVersion: version, maxVersion: version),
            certChain: serverChain,
            privateKey: serverKey,
          );
          final data = await tls.read();
          await tls.write(data);
          serverResult.complete(null);
        } catch (e) {
          if (!serverResult.isCompleted) serverResult.complete(e);
        } finally {
          await socket.close();
          await serverSocket.close();
        }
      });

      final socket = await Socket.connect(InternetAddress.loopbackIPv4, serverSocket.port);
      final client = TlsConnection(socket);
      try {
        await client.handshakeClient(
          settings: HandshakeSettings(minVersion: version, maxVersion: version),
          serverName: 'localhost',
          checker: checker,
        );
        await client.write(Uint8List.fromList(utf8.encode('ping')));
        final echoed = await client.read();
        expect(utf8.decode(echoed), 'ping');
        expect(await serverResult.future, isNull);
        return null;
      } catch (e) {
        return e;
      } finally {
        await socket.close();
        await serverSocket.close();
      }
    }

    for (final version in [(3, 3), (3, 4)]) {
      final label = version == (3, 4) ? 'TLS 1.3' : 'TLS 1.2';

      test('$label: trusted self-signed server certificate', () async {
        final checker =
            X509Validator(serverChain.x509List).checker(hostname: 'localhost');
        expect(await runHandshake(checker, version), isNull);
      }, timeout: const Timeout(Duration(seconds: 30)));

      test('$label: untrusted server certificate aborts the handshake',
          () async {
        final checker =
            X509Validator([_cert('rsa_root')]).checker(hostname: 'localhost');
        final error = await runHandshake(checker, version);
        expect(error, isA<TLSCertificateVerificationError>());
        expect((error as TLSCertificateVerificationError).reason,
            CertificateVerificationFailure.selfSigned);
      }, timeout: const Timeout(Duration(seconds: 30)));

      test('$label: hostname mismatch aborts the handshake', () async {
        final checker = X509Validator(serverChain.x509List)
            .checker(hostname: 'sql.example.com');
        final error = await runHandshake(checker, version);
        expect(error, isA<TLSCertificateVerificationError>());
        expect((error as TLSCertificateVerificationError).reason,
            CertificateVerificationFailure.hostnameMismatch);
      }, timeout: const Timeout(Duration(seconds: 30)));
    }
  });
}
