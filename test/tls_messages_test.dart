import 'dart:typed_data';
import 'dart:io' as io;
import 'package:test/test.dart';
import 'package:tlslite/src/constants.dart' as tls_constants;
import 'package:tlslite/src/net/security/pure_dart_with_ffi_socket/dart_tls_types.dart';
import 'package:tlslite/src/net/security/pure_dart_with_ffi_socket/tls_extensions.dart';
import 'package:tlslite/src/messages.dart';
import 'package:tlslite/src/tls_protocol.dart';

void main() {
  group('TlsCertificate', () {
    test('tls12 roundtrip', () {
      final message = TlsCertificate.tls12(
        certificateChain: <Uint8List>[
          Uint8List.fromList(<int>[0x30, 0x82, 0x01, 0x0a, 0x02]),
          Uint8List.fromList(<int>[0x30, 0x10, 0x00, 0x01]),
        ],
      );

      final parsed = TlsHandshakeMessage.parseFragment(message.serialize())
          .single as TlsCertificate;

      expect(parsed.certificateChain, hasLength(2));
      expect(parsed.certificateChain[0], equals(message.certificateChain[0]));
      expect(parsed.certificateChain[1], equals(message.certificateChain[1]));
    });

    test('build from PEM fixture', () {
      final certPem =
          io.File('tlslite-ng/tests/serverX509Cert.pem').readAsStringSync();
      final keyPem =
          io.File('tlslite-ng/tests/serverX509Key.pem').readAsStringSync();

      final config = PureDartTlsConfig(
        certificateChainPem: certPem,
        privateKeyPem: keyPem,
      );

      final message = config.buildServerCertificateMessage();
      final parsed = TlsHandshakeMessage.parseFragment(message.serialize())
          .single as TlsCertificate;

      expect(parsed.certificateChain.length,
          equals(config.certificateChainDer.length));
      expect(parsed.certificateChain.first,
          equals(config.certificateChainDer.first));
    });

    test('tls13 roundtrip', () {
      final entries = <TlsCertificateEntry>[
        TlsCertificateEntry(
          certificate: Uint8List.fromList(<int>[0x01, 0x02, 0x03]),
          extensions: Uint8List.fromList(<int>[0x00, 0x00]),
        ),
      ];

      final message = TlsCertificate.tls13(
        certificateEntries: entries,
        certificateRequestContext: Uint8List.fromList(<int>[0xAA]),
      );

      final parsed = TlsHandshakeMessage.parseFragment(
        message.serialize(),
        recordVersion: TlsProtocolVersion.tls13,
      ).single as TlsCertificate;

      expect(parsed.isTls13, isTrue);
      expect(parsed.certificateEntries.single.certificate,
          equals(entries.single.certificate));
      expect(parsed.certificateRequestContext.single, equals(0xAA));
    });
  });

  test('CertificateRequest tls12 roundtrip', () {
    final req = TlsCertificateRequest(
      version: TlsProtocolVersion.tls12,
      certificateTypes: <int>[
        tls_constants.ClientCertificateType.rsa_sign,
        tls_constants.ClientCertificateType.ecdsa_sign,
      ],
      signatureAlgorithms: <int>[0x0401, 0x0503],
      certificateAuthorities: <Uint8List>[
        Uint8List.fromList(<int>[0x30, 0x31, 0x32]),
      ],
    );

    final parsed = (TlsHandshakeMessage.parseFragment(req.serialize()).single)
        as TlsCertificateRequest;

    expect(parsed.certificateTypes, equals(req.certificateTypes));
    expect(parsed.signatureAlgorithms, equals(req.signatureAlgorithms));
    expect(parsed.certificateAuthorities.single,
        equals(req.certificateAuthorities.single));
  });

  test('CertificateVerify tls12 roundtrip', () {
    final verify = TlsCertificateVerify(
      version: TlsProtocolVersion.tls12,
      signature: Uint8List.fromList(<int>[1, 2, 3, 4]),
      signatureScheme: 0x0403,
    );

    final parsed = (TlsHandshakeMessage.parseFragment(verify.serialize())
        .single) as TlsCertificateVerify;

    expect(parsed.signatureScheme, equals(0x0403));
    expect(parsed.signature, equals(verify.signature));
  });

  test('KeyUpdate toggles flag', () {
    final update = TlsKeyUpdate(updateRequested: true);
    final parsed = (TlsHandshakeMessage.parseFragment(update.serialize())
        .single) as TlsKeyUpdate;

    expect(parsed.updateRequested, isTrue);
  });

  test('ClientHello parses supported_versions extension', () {
    final block = TlsExtensionBlock(extensions: <TlsExtension>[
      TlsSupportedVersionsExtension.client(<TlsProtocolVersion>[
        TlsProtocolVersion.tls13,
        TlsProtocolVersion.tls12,
      ]),
    ]);
    final hello = TlsClientHello(
      clientVersion: TlsProtocolVersion.tls12,
      random: Uint8List(32),
      sessionId: Uint8List(0),
      cipherSuites: <int>[0x1301],
      compressionMethods: <int>[0],
      extensions: block,
    );

    final parsed = TlsHandshakeMessage.parseFragment(
      hello.serialize(),
      recordVersion: TlsProtocolVersion.tls12,
    ).single as TlsClientHello;

    expect(parsed.supportedVersions, hasLength(2));
    expect(parsed.supportedVersions.first, equals(TlsProtocolVersion.tls13));
    expect(parsed.supportedVersions.last, equals(TlsProtocolVersion.tls12));
  });

  test('ServerHello captures selected supported_version', () {
    final block = TlsExtensionBlock(extensions: <TlsExtension>[
      TlsSupportedVersionsExtension.server(TlsProtocolVersion.tls13),
    ]);
    final hello = TlsServerHello(
      serverVersion: TlsProtocolVersion.tls12,
      random: Uint8List(32),
      sessionId: Uint8List(0),
      cipherSuite: 0x1301,
      compressionMethod: 0,
      extensions: block,
    );

    final parsed = TlsHandshakeMessage.parseFragment(
      hello.serialize(),
      recordVersion: TlsProtocolVersion.tls12,
    ).single as TlsServerHello;

    expect(parsed.selectedSupportedVersion, equals(TlsProtocolVersion.tls13));
  });

  test('ChangeCipherSpec serialization', () {
    final ccs = TlsChangeCipherSpec();
    final copy = TlsChangeCipherSpec.parse(ccs.serialize());

    expect(copy.value, equals(1));
  });

  test('ClientHello exposes SNI and ALPN', () {
    final block = TlsExtensionBlock(extensions: <TlsExtension>[
      TlsServerNameExtension(hostNames: <String>['example.com']),
      TlsAlpnExtension(protocols: <String>['h2', 'http/1.1']),
    ]);

    final hello = TlsClientHello(
      clientVersion: TlsProtocolVersion.tls12,
      random: Uint8List(32),
      sessionId: Uint8List(0),
      cipherSuites: <int>[0x1301],
      compressionMethods: <int>[0],
      extensions: block,
    );

    final parsed = TlsHandshakeMessage.parseFragment(
      hello.serialize(),
      recordVersion: TlsProtocolVersion.tls12,
    ).single as TlsClientHello;

    expect(parsed.serverNames, contains('example.com'));
    expect(
        parsed.applicationProtocols, containsAll(<String>['h2', 'http/1.1']));
  });

  test('ClientHello surfaces TLS 1.3 extensions', () {
    final keyShareEntry = TlsKeyShareEntry(
      group: tls_constants.GroupName.x25519,
      keyExchange: Uint8List.fromList(<int>[0xAA, 0xBB]),
    );
    final block = TlsExtensionBlock(extensions: <TlsExtension>[
      TlsKeyShareExtension.client(<TlsKeyShareEntry>[keyShareEntry]),
      TlsStatusRequestExtension.request(
        statusType: tls_constants.CertificateStatusType.ocsp,
        responderIds: <Uint8List>[
          Uint8List.fromList(<int>[0x01])
        ],
        requestExtensions: Uint8List.fromList(<int>[0x02, 0x03]),
      ),
      TlsSignatureAlgorithmsCertExtension(
        signatureSchemes: <int>[0x0403, 0x0807],
      ),
    ]);

    final hello = TlsClientHello(
      clientVersion: TlsProtocolVersion.tls12,
      random: Uint8List(32),
      sessionId: Uint8List(0),
      cipherSuites: <int>[0x1301],
      compressionMethods: <int>[0],
      extensions: block,
    );

    final parsed = TlsHandshakeMessage.parseFragment(
      hello.serialize(),
      recordVersion: TlsProtocolVersion.tls12,
    ).single as TlsClientHello;

    expect(parsed.keyShares, hasLength(1));
    expect(parsed.keyShares.single.group, equals(keyShareEntry.group));
    expect(parsed.statusRequest, isNotNull);
    expect(parsed.statusRequest!.statusType,
        equals(tls_constants.CertificateStatusType.ocsp));
    expect(parsed.signatureAlgorithmsCert, contains(0x0403));
    expect(parsed.signatureAlgorithmsCert, contains(0x0807));
  });

  test('ServerHello exposes key_share selection', () {
    final entry = TlsKeyShareEntry(
      group: tls_constants.GroupName.x25519,
      keyExchange: Uint8List.fromList(<int>[0x10, 0x11]),
    );
    final block = TlsExtensionBlock(extensions: <TlsExtension>[
      TlsKeyShareExtension.server(entry),
    ]);

    final hello = TlsServerHello(
      serverVersion: TlsProtocolVersion.tls12,
      random: Uint8List(32),
      sessionId: Uint8List(0),
      cipherSuite: 0x1301,
      compressionMethod: 0,
      extensions: block,
    );

    final parsed = TlsHandshakeMessage.parseFragment(
      hello.serialize(),
      recordVersion: TlsProtocolVersion.tls12,
    ).single as TlsServerHello;

    expect(parsed.keyShare, isNotNull);
    expect(parsed.keyShare!.group, equals(entry.group));
  });

  test('EncryptedExtensions roundtrip', () {
    final block = TlsExtensionBlock(extensions: <TlsExtension>[
      TlsAlpnExtension(protocols: <String>['h2']),
    ]);
    final ee = TlsEncryptedExtensions(extensions: block);

    final parsed = TlsHandshakeMessage.parseFragment(
      ee.serialize(),
      recordVersion: TlsProtocolVersion.tls13,
    ).single as TlsEncryptedExtensions;

    expect(parsed.applicationProtocols, equals(<String>['h2']));
  });

  test('NewSessionTicket roundtrip', () {
    final ticket = TlsNewSessionTicket(
      ticketLifetime: 7200,
      ticketAgeAdd: 0x11223344,
      ticketNonce: Uint8List.fromList(<int>[1, 2]),
      ticket: Uint8List.fromList(<int>[3, 4, 5]),
      extensions: Uint8List.fromList(<int>[0x00, 0x00]),
    );

    final parsed = TlsHandshakeMessage.parseFragment(
      ticket.serialize(),
      recordVersion: TlsProtocolVersion.tls13,
    ).single as TlsNewSessionTicket;

    expect(parsed.ticketLifetime, equals(7200));
    expect(parsed.ticketAgeAdd, equals(0x11223344));
    expect(parsed.ticketNonce, equals(ticket.ticketNonce));
    expect(parsed.ticket, equals(ticket.ticket));
    expect(parsed.extensions, equals(ticket.extensions));
  });

  test('CertificateRequest TLS 1.3 exposes extensions', () {
    final block = TlsExtensionBlock(extensions: <TlsExtension>[
      TlsSignatureAlgorithmsCertExtension(signatureSchemes: <int>[0x0403]),
      TlsStatusRequestExtension.request(
        statusType: tls_constants.CertificateStatusType.ocsp,
        responderIds: const <Uint8List>[],
        requestExtensions: Uint8List.fromList(<int>[0xEE]),
      ),
    ]);
    final request = TlsCertificateRequest(
      version: TlsProtocolVersion.tls13,
      certificateRequestContext: Uint8List(0),
      extensions: block,
    );

    final parsed = TlsHandshakeMessage.parseFragment(
      request.serialize(),
      recordVersion: TlsProtocolVersion.tls13,
    ).single as TlsCertificateRequest;

    expect(parsed.signatureAlgorithmsCert, contains(0x0403));
    expect(parsed.statusRequest, isNotNull);
    expect(parsed.statusRequest!.statusType,
        equals(tls_constants.CertificateStatusType.ocsp));
  });
}
