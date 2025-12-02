import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/net/security/pure_dart/pure_dart_tls_types.dart';
import 'package:tlslite/src/net/security/pure_dart/tls_handshake_state.dart';
import 'package:tlslite/src/net/security/pure_dart/tls_messages.dart';

void main() {
  TlsClientHello sampleClientHello() => TlsClientHello(
        clientVersion: TlsProtocolVersion.tls12,
        random: Uint8List(32),
        sessionId: Uint8List(0),
        cipherSuites: <int>[0x0033],
        compressionMethods: <int>[0],
      );

  TlsServerHello sampleServerHello() => TlsServerHello(
        serverVersion: TlsProtocolVersion.tls12,
        random: Uint8List(32),
        sessionId: Uint8List(0),
        cipherSuite: 0x0033,
        compressionMethod: 0,
      );

  TlsFinished sampleFinished() => TlsFinished(
        verifyData: Uint8List(12),
      );
  TlsNewSessionTicket sampleTicket() => TlsNewSessionTicket(
        ticketLifetime: 3600,
        ticketAgeAdd: 0x01020304,
        ticketNonce: Uint8List.fromList(<int>[1, 2, 3]),
        ticket: Uint8List.fromList(<int>[4, 5, 6, 7]),
        extensions: Uint8List(0),
      );

  group('PureDartTlsHandshakeStateMachine', () {
    test('server completes after ClientHello + Finished', () {
      final machine =
          PureDartTlsHandshakeStateMachine(mode: PureDartTlsMode.server);

      expect(machine.processIncoming(<TlsHandshakeMessage>[sampleClientHello()]),
          isFalse);
      expect(machine.hasSeenHello, isTrue);
      expect(machine.negotiatedVersion, equals(TlsProtocolVersion.tls12));

      final completed = machine.processIncoming(<TlsHandshakeMessage>[
        sampleFinished(),
      ]);
      expect(completed, isTrue);
      expect(machine.isHandshakeComplete, isTrue);
    });

    test('client validates first ServerHello', () {
      final machine =
          PureDartTlsHandshakeStateMachine(mode: PureDartTlsMode.client);

      expect(machine.processIncoming(<TlsHandshakeMessage>[sampleServerHello()]),
          isFalse);
      expect(machine.negotiatedVersion, equals(TlsProtocolVersion.tls12));

      final completed = machine.processIncoming(<TlsHandshakeMessage>[
        sampleFinished(),
      ]);
      expect(completed, isTrue);
    });

    test('unexpected initial message throws', () {
      final machine =
          PureDartTlsHandshakeStateMachine(mode: PureDartTlsMode.server);

      expect(
        () => machine.processIncoming(<TlsHandshakeMessage>[sampleServerHello()]),
        throwsA(isA<StateError>()),
      );
    });

    test('client tolerates post-handshake ticket/key updates', () {
      final machine =
          PureDartTlsHandshakeStateMachine(mode: PureDartTlsMode.client);
      machine.processIncoming(<TlsHandshakeMessage>[sampleServerHello()]);
      machine.processIncoming(<TlsHandshakeMessage>[sampleFinished()]);
      expect(machine.isHandshakeComplete, isTrue);

      final ticket = sampleTicket();
      expect(
        machine.processIncoming(<TlsHandshakeMessage>[ticket]),
        isTrue,
      );

      final keyUpdate = TlsKeyUpdate(updateRequested: true);
      expect(
        machine.processIncoming(<TlsHandshakeMessage>[keyUpdate]),
        isTrue,
      );
    });

    test('server tolerates post-handshake client auth', () {
      final machine =
          PureDartTlsHandshakeStateMachine(mode: PureDartTlsMode.server);
      machine.processIncoming(<TlsHandshakeMessage>[sampleClientHello()]);
      machine.processIncoming(<TlsHandshakeMessage>[sampleFinished()]);
      expect(machine.isHandshakeComplete, isTrue);

      final certificate = TlsCertificate.tls13(
        certificateRequestContext: Uint8List(0),
        certificateEntries: <TlsCertificateEntry>[
          TlsCertificateEntry(
            certificate: Uint8List.fromList(<int>[0x01, 0x02]),
          ),
        ],
      );
      final verify = TlsCertificateVerify(
        version: TlsProtocolVersion.tls13,
        signature: Uint8List.fromList(<int>[9, 9, 9]),
        signatureScheme: 0x0804,
      );

      expect(
        machine.processIncoming(<TlsHandshakeMessage>[certificate, verify]),
        isTrue,
      );

      expect(
        machine.processIncoming(<TlsHandshakeMessage>[sampleFinished()]),
        isTrue,
      );
    });

    test('server prefers TLS1.3 from supported_versions', () {
      final machine =
          PureDartTlsHandshakeStateMachine(mode: PureDartTlsMode.server);
      final hello = TlsClientHello(
        clientVersion: TlsProtocolVersion.tls12,
        random: Uint8List(32),
        sessionId: Uint8List(0),
        cipherSuites: <int>[0x1301],
        compressionMethods: <int>[0],
        supportedVersions: <TlsProtocolVersion>[ 
          TlsProtocolVersion.tls12,
          TlsProtocolVersion.tls13,
        ],
      );

      machine.processIncoming(<TlsHandshakeMessage>[hello]);
      expect(machine.negotiatedVersion, equals(TlsProtocolVersion.tls13));
    });

    test('client uses supported_versions selection from ServerHello', () {
      final machine =
          PureDartTlsHandshakeStateMachine(mode: PureDartTlsMode.client);
      final hello = TlsServerHello(
        serverVersion: TlsProtocolVersion.tls12,
        random: Uint8List(32),
        sessionId: Uint8List(0),
        cipherSuite: 0x1301,
        compressionMethod: 0,
        selectedSupportedVersion: TlsProtocolVersion.tls13,
      );

      machine.processIncoming(<TlsHandshakeMessage>[hello]);
      expect(machine.negotiatedVersion, equals(TlsProtocolVersion.tls13));
    });
  });
}
