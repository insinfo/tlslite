import 'dart:collection';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:tlslite/src/constants.dart';
import 'package:tlslite/src/defragmenter.dart';
import 'package:tlslite/src/errors.dart';
import 'package:tlslite/src/handshake_helpers.dart';
import 'package:tlslite/src/handshake_settings.dart';
import 'package:tlslite/src/keyexchange.dart';
import 'package:tlslite/src/messages.dart';
import 'package:tlslite/src/mathtls.dart';
import 'package:tlslite/src/tls_extensions.dart';
import 'package:tlslite/src/recordlayer.dart';
import 'package:tlslite/src/session.dart';
import 'package:tlslite/src/sessioncache.dart';
import 'package:tlslite/src/tls_protocol.dart';
import 'package:tlslite/src/tlsconnection.dart';
import 'package:tlslite/src/utils/codec.dart';
import 'package:tlslite/src/utils/cryptomath.dart';

void main() {
  group('TlsConnection handshake draining', () {
    test('collects handshake fragments across SSLv2 and TLS records', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final tlsFragment = _handshakeFragment([0xAA, 0xBB]);
      final tlsHeader = RecordHeader3().create(const TlsProtocolVersion(3, 1),
          ContentType.handshake, tlsFragment.length);
      harness.connection.queueRecord(tlsHeader, tlsFragment);

      final ssl2Fragment = _handshakeFragment([0xCC]);
      final ssl2Header = RecordHeader2().create(ssl2Fragment.length, 0)
        ..type = ContentType.handshake;
      harness.connection.queueRecord(ssl2Header, ssl2Fragment);

      final fragments =
          await harness.connection.drainHandshakeMessages(maxMessages: 2);

      expect(fragments, hasLength(2));
      expect(fragments[0], equals(tlsFragment));
      expect(fragments[1], equals(ssl2Fragment));
    });

    test('handshake transcript preserves on-the-wire bytes per message',
        () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final conn = harness.connection;
      conn.version = TlsProtocolVersion.tls12;

      final first = _handshakeFragment(
        <int>[0x01, 0x02, 0x03],
        handshakeType: TlsHandshakeType.helloRequest.code,
      );
      final second = _handshakeFragment(
        <int>[0xAA, 0xBB],
        handshakeType: TlsHandshakeType.serverHelloDone.code,
      );
      final combined = Uint8List.fromList(<int>[...first, ...second]);
      final header = RecordHeader3().create(
        TlsProtocolVersion.tls12,
        ContentType.handshake,
        combined.length,
      );
      conn.queueRecord(header, combined);

      await conn.recvHandshakeMessage();
      await conn.recvHandshakeMessage();

      final transcript = conn.handshakeHashes.digest('intrinsic');
      expect(transcript, equals(combined));
    });
  });

  group('TlsConnection session cache integration', () {
    test('resumes and stores sessions via SessionCache', () async {
      final cache = SessionCache(maxEntries: 4, maxAgeSeconds: 3600);
      final resumedSession = Session()
        ..sessionID = Uint8List.fromList([0x01])
        ..resumable = true;
      cache[resumedSession.sessionID] = resumedSession;

      final harness = await _TlsConnectionHarness.create(cache: cache);
      addTearDown(() async => harness.dispose());

      final resumed =
          harness.connection.tryResumeSession(resumedSession.sessionID);
      expect(resumed, isTrue);
      expect(harness.connection.session, same(resumedSession));

      final newSession = Session()
        ..sessionID = Uint8List.fromList([0xAA])
        ..resumable = true;
      harness.connection.session = newSession;
      harness.connection.cacheCurrentSession();

      final fetched = cache.getOrNull(newSession.sessionID);
      expect(fetched, same(newSession));
    });
  });

  group('TlsConnection handshake crypto helpers', () {
    test('buildFinishedVerifyData matches calcFinished for TLS 1.2', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final conn = harness.connection;
      conn.version = TlsProtocolVersion.tls12;

      final message = _rawHandshakeMessage(
        TlsHandshakeType.serverHelloDone,
        Uint8List.fromList([0xA5, 0x5A]),
      );
      _queueHandshakeMessage(conn, message,
          version: TlsProtocolVersion.tls12);
      await conn.recvHandshakeMessage();

      final session = Session()
        ..sessionID = Uint8List.fromList([0x10])
        ..cipherSuite = 0x0035
        ..masterSecret = Uint8List.fromList(
            List<int>.generate(48, (index) => index + 1))
        ..resumable = true;
      conn.session = session;

      final verifyData = conn.buildFinishedVerifyData(forClient: true);
      final expected = calcFinished(
        [TlsProtocolVersion.tls12.major, TlsProtocolVersion.tls12.minor],
        session.masterSecret,
        session.cipherSuite,
        conn.handshakeHashes,
        true,
      );
      expect(verifyData, equals(expected));
    });

    test('buildFinishedVerifyData handles TLS 1.3 traffic secrets', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final conn = harness.connection;
      conn.version = TlsProtocolVersion.tls13;
      conn.handshakeEstablished = true;

      conn.handshakeHashes.update(
        _handshakeFragment(
          List<int>.filled(12, 0x22),
          handshakeType: TlsHandshakeType.helloRequest.code,
        ),
      );

      final clientHs = Uint8List.fromList(List<int>.filled(32, 0x11));
      final serverHs = Uint8List.fromList(List<int>.filled(32, 0x22));

      final session = Session()
        ..sessionID = Uint8List.fromList([0x20])
        ..cipherSuite = 0x1301
        ..clHandshakeSecret = clientHs
        ..srHandshakeSecret = serverHs
        ..resumable = true;
      conn.session = session;

      final verifyData = conn.buildFinishedVerifyData(forClient: true);
      final finishedKey = HKDF_expand_label(
        clientHs,
        Uint8List.fromList('finished'.codeUnits),
        Uint8List(0),
        32,
        'sha256',
      );
      final expected = secureHMAC(
        finishedKey,
        conn.handshakeHashes.digest('sha256'),
        'sha256',
      );
      expect(verifyData, equals(expected));
    });

    test('buildCertificateVerifyBytes mirrors KeyExchange helper', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final conn = harness.connection;
      conn.version = TlsProtocolVersion.tls13;

      conn.handshakeHashes.update(
        _handshakeFragment(
          List<int>.filled(4, 0xA5),
          handshakeType: TlsHandshakeType.helloRequest.code,
        ),
      );

      final scheme = SignatureScheme.valueOf('ed25519')!;
      final bytes = conn.buildCertificateVerifyBytes(
        signatureScheme: scheme,
        peerTag: 'server',
      );
      final expected = KeyExchange.calcVerifyBytes(
        TlsProtocolVersion.tls13,
        conn.handshakeHashes,
        scheme,
        prfName: 'sha256',
        peerTag: 'server',
      );
      expect(bytes, equals(expected));
    });
  });

  group('TlsClientHello PSK helpers', () {
    test('pskTruncate strips encoded binder vector', () {
      final clientHello = _clientHelloWithSinglePsk();
        final pskExt =
          clientHello.extensions!.last as TlsPreSharedKeyExtension;

      final truncated = clientHello.pskTruncate();
      final full = clientHello.serialize();

      expect(truncated.length,
          full.length - pskExt.encodedBindersLength);
    });
  });

  group('TlsConnection PSK binder helpers', () {
    test('updateClientHelloPskBinders fills binders deterministically',
        () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final conn = harness.connection;
      conn.version = TlsProtocolVersion.tls13;
      final clientHello = _clientHelloWithSinglePsk();
        final identity =
          (clientHello.extensions!.last as TlsPreSharedKeyExtension)
              .identities
              .single
              .identity;
      final config = PskConfig(
        identity: identity,
        secret: List<int>.filled(32, 0x42),
        hash: 'sha256',
      );

      conn.updateClientHelloPskBinders(
        clientHello: clientHello,
        pskConfigs: [config],
      );

        final updatedExt =
          clientHello.extensions!.last as TlsPreSharedKeyExtension;
      expect(updatedExt.binders.single.contains(0), isFalse);

      final hh = conn.handshakeHashes.copy();
      hh.update(clientHello.pskTruncate());
      final expected = HandshakeHelpers.calcBinder(
        'sha256',
        config.secret,
        hh,
      );
      expect(updatedExt.binders.single, equals(expected));
    });

    test('verifyClientHelloPskBinder succeeds and rejects mismatches',
        () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final conn = harness.connection;
      conn.version = TlsProtocolVersion.tls13;
      final clientHello = _clientHelloWithSinglePsk();
        final pskExt =
          clientHello.extensions!.last as TlsPreSharedKeyExtension;
      final identity = pskExt.identities.single.identity;
      final config = PskConfig(
        identity: identity,
        secret: List<int>.filled(32, 0x24),
        hash: 'sha256',
      );
      conn.updateClientHelloPskBinders(
        clientHello: clientHello,
        pskConfigs: [config],
      );

      conn.snapshotPreClientHelloHash();
      expect(
        () =>
            conn.verifyClientHelloPskBinder(
              clientHello: clientHello,
              binderIndex: 0,
              secret: config.secret,
              hashName: 'sha256',
            ),
        returnsNormally,
      );

      // Tamper with the binder to trigger verification failure.
      pskExt.binders[0][0] ^= 0xff;
      conn.snapshotPreClientHelloHash();
      expect(
        () => conn.verifyClientHelloPskBinder(
          clientHello: clientHello,
          binderIndex: 0,
          secret: config.secret,
          hashName: 'sha256',
        ),
        throwsA(isA<TLSIllegalParameterException>()),
      );
    });
  });

  group('TlsConnection PSK handshake integration', () {
    test('client auto-populates binders for static PSKs', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final conn = harness.connection;
      conn.version = TlsProtocolVersion.tls13;

      final clientHello = _clientHelloWithSinglePsk();
      final pskExt =
          clientHello.extensions!.last as TlsPreSharedKeyExtension;
      final identity = pskExt.identities.single.identity;
      final config = PskConfig(
        identity: identity,
        secret: List<int>.filled(32, 0x42),
        hash: 'sha256',
      );
      conn.configureHandshakeSettings(
        HandshakeSettings(pskConfigs: [config]),
      );

      final hh = conn.handshakeHashes.copy();
      hh.update(clientHello.pskTruncate());
      final expected = HandshakeHelpers.calcBinder(
        'sha256',
        config.secret,
        hh,
      );

      await conn.sendHandshakeMessage(clientHello);

      expect(pskExt.binders.single, equals(expected));
    });

    test('client reuses cached TLS 1.3 tickets for binders', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final conn = harness.connection;
      conn.version = TlsProtocolVersion.tls13;

      final ticket = _newSessionTicket();
      conn.session.resumptionMasterSecret =
          Uint8List.fromList(List<int>.filled(32, 0x33));
      conn.session.tls13Tickets = [ticket];

      final clientHello = _clientHelloWithSinglePsk(
        identityBytes: ticket.ticket,
      );
      final pskExt =
          clientHello.extensions!.last as TlsPreSharedKeyExtension;
      final hh = conn.handshakeHashes.copy();
      hh.update(clientHello.pskTruncate());

      final psk = HandshakeHelpers.calcResBinderPsk(
        pskExt.identities.single,
        conn.session.resumptionMasterSecret,
        [ticket],
      );
      final expected = HandshakeHelpers.calcBinder(
        'sha256',
        psk,
        hh,
        external: false,
      );

      await conn.sendHandshakeMessage(clientHello);

      expect(pskExt.binders.single, equals(expected));
    });

    test('server validates inbound binders and records negotiation', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final conn = harness.connection;
      conn.version = TlsProtocolVersion.tls13;
      conn.client = false;

      final clientHello = _clientHelloWithSinglePsk();
      final pskExt =
          clientHello.extensions!.last as TlsPreSharedKeyExtension;
      final identity = pskExt.identities.single.identity;
      final config = PskConfig(
        identity: identity,
        secret: List<int>.filled(32, 0x21),
        hash: 'sha256',
      );
      conn.configureHandshakeSettings(
        HandshakeSettings(pskConfigs: [config]),
      );

      final hh = conn.handshakeHashes.copy();
      HandshakeHelpers.updateBinders(clientHello, hh, [config]);

      _queueHandshakeMessage(conn, clientHello,
          version: TlsProtocolVersion.tls13);

      final msg = await conn.recvHandshakeMessage();
      expect(msg, isA<TlsClientHello>());
      expect(conn.negotiatedClientHelloPskIndex, equals(0));
      expect(conn.negotiatedExternalPsk, same(config));
      expect(conn.negotiatedClientHelloPskIdentity, equals(identity));
    });

    test('server rejects mismatched binders with alerts', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final conn = harness.connection;
      conn.version = TlsProtocolVersion.tls13;
      conn.client = false;

      final clientHello = _clientHelloWithSinglePsk();
      final pskExt =
          clientHello.extensions!.last as TlsPreSharedKeyExtension;
      final identity = pskExt.identities.single.identity;
      final config = PskConfig(
        identity: identity,
        secret: List<int>.filled(32, 0x99),
        hash: 'sha256',
      );
      conn.configureHandshakeSettings(
        HandshakeSettings(pskConfigs: [config]),
      );

      final hh = conn.handshakeHashes.copy();
      HandshakeHelpers.updateBinders(clientHello, hh, [config]);
      pskExt.binders.single[0] ^= 0xff;

      _queueHandshakeMessage(conn, clientHello,
          version: TlsProtocolVersion.tls13);

      await expectLater(
        () => conn.recvHandshakeMessage(),
        throwsA(isA<TLSIllegalParameterException>()),
      );
        final alertRecord = conn.sentRecords
          .firstWhere((msg) => msg.contentType == ContentType.alert);
        expect(alertRecord.data.length, equals(2));
    });
  });

  group('TlsConnection handshake parsing API', () {
    test('recvHandshakeMessage parses buffered fragments respecting filters',
        () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final payloadA = _handshakeFragment([
        0x01,
        0x02,
      ], handshakeType: TlsHandshakeType.helloRequest.code);
      final headerA = RecordHeader3().create(const TlsProtocolVersion(3, 3),
          ContentType.handshake, payloadA.length);
      harness.connection.queueRecord(headerA, payloadA);

      final payloadB = _handshakeFragment([
        0xAA,
      ], handshakeType: TlsHandshakeType.helloRequest.code);
      final headerB = RecordHeader3().create(const TlsProtocolVersion(3, 3),
          ContentType.handshake, payloadB.length);
      harness.connection.queueRecord(headerB, payloadB);

      final msg = await harness.connection
          .recvHandshakeMessage(allowedTypes: {TlsHandshakeType.helloRequest});
      expect(msg.handshakeType, equals(TlsHandshakeType.helloRequest));

      final next = await harness.connection.recvHandshakeMessage();
      expect(next.handshakeType, equals(TlsHandshakeType.helloRequest));
      expect(next, isNot(same(msg)));
    });

    test('recvHandshakeMessage converts SSLv2 ClientHello to TLS message',
        () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final conn = harness.connection;
      conn.client = false;

      final challenge = List<int>.generate(16, (index) => index);
      final ssl2Fragment = _ssl2ClientHelloFragment(
        version: const TlsProtocolVersion(3, 1),
        cipherSuites: const <int>[0x002f],
        challenge: challenge,
      );
      final header = RecordHeader2().create(ssl2Fragment.length, 0);
      conn.queueRecord(header, ssl2Fragment);

      final message = await conn.recvHandshakeMessage();
      expect(message, isA<TlsClientHello>());
      final hello = message as TlsClientHello;
      expect(hello.clientVersion, equals(const TlsProtocolVersion(3, 1)));
      expect(hello.cipherSuites, equals(const <int>[0x002f]));
      expect(hello.compressionMethods, equals(const <int>[0]));
      expect(hello.random.sublist(16), equals(challenge));
    });

    test('recvHandshakeMessage surfaces pending alerts', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final alertPayload = Uint8List.fromList([
        AlertLevel.warning,
        AlertDescription.close_notify,
      ]);
      final alertHeader = RecordHeader3().create(const TlsProtocolVersion(3, 1),
          ContentType.alert, alertPayload.length);
      harness.connection.queueRecord(alertHeader, alertPayload);

      final handshakePayload = _handshakeFragment([
        0x42,
      ], handshakeType: TlsHandshakeType.helloRequest.code);
      final handshakeHeader = RecordHeader3().create(
          const TlsProtocolVersion(3, 1),
          ContentType.handshake,
          handshakePayload.length);
      harness.connection.queueRecord(handshakeHeader, handshakePayload);

      await expectLater(() => harness.connection.recvHandshakeMessage(),
          throwsA(isA<TLSRemoteAlert>()));

      final msg = await harness.connection.recvHandshakeMessage();
      expect(msg.handshakeType, equals(TlsHandshakeType.helloRequest));
    });

    test('sendHandshakeFlight batches multiple handshake payloads', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final first = _rawHandshakeMessage(
          TlsHandshakeType.helloRequest, Uint8List.fromList([0x10]));
      final second = _rawHandshakeMessage(
          TlsHandshakeType.helloRequest, Uint8List.fromList([0x20, 0x21]));

      await harness.connection.sendHandshakeFlight([first, second]);

      expect(harness.connection.sentRecords, hasLength(1));
      final record = harness.connection.sentRecords.first;
      final expectedPayload = Uint8List.fromList([
        ...first.serialize(),
        ...second.serialize(),
      ]);
      expect(record.contentType, equals(ContentType.handshake));
      expect(record.data, equals(expectedPayload));
    });

    test('heartbeat request handled transparently when negotiated', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      harness.connection.heartbeatSupported = true;
      harness.connection.heartbeatCanReceive = true;

      final request = TlsHeartbeat(
        messageType: HeartbeatMessageType.heartbeat_request,
        payload: const [0x01, 0x02],
        padding: List<int>.filled(16, 0xAB),
      );
      final requestBytes = request.serialize();
      final hbHeader = RecordHeader3().create(const TlsProtocolVersion(3, 3),
          ContentType.heartbeat, requestBytes.length);
      harness.connection.queueRecord(hbHeader, requestBytes);

      final handshakePayload = _handshakeFragment([
        0x33,
      ], handshakeType: TlsHandshakeType.helloRequest.code);
      final handshakeHeader = RecordHeader3().create(
          const TlsProtocolVersion(3, 3),
          ContentType.handshake,
          handshakePayload.length);
      harness.connection.queueRecord(handshakeHeader, handshakePayload);

      final msg = await harness.connection.recvHandshakeMessage();
      expect(msg.handshakeType, equals(TlsHandshakeType.helloRequest));

      final hbRecord = harness.connection.sentRecords
          .firstWhere((m) => m.contentType == ContentType.heartbeat);
      final response = TlsHeartbeat.parse(hbRecord.data);
      expect(response.messageType,
          equals(HeartbeatMessageType.heartbeat_response));
      expect(response.payload, equals(request.payload));
      expect(response.padding.length, equals(request.padding.length));
    });

    test('renegotiation attempts emit warning alert and are skipped', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      harness.connection.handshakeEstablished = true;

      final helloRequest = _handshakeFragment(
        const <int>[],
        handshakeType: TlsHandshakeType.helloRequest.code,
      );
      final helloHeader = RecordHeader3().create(const TlsProtocolVersion(3, 3),
          ContentType.handshake, helloRequest.length);
      harness.connection.queueRecord(helloHeader, helloRequest);

      final followUp = _handshakeFragment(
        const <int>[],
        handshakeType: TlsHandshakeType.serverHelloDone.code,
      );
      final followUpHeader = RecordHeader3().create(
          const TlsProtocolVersion(3, 3),
          ContentType.handshake,
          followUp.length);
      harness.connection.queueRecord(followUpHeader, followUp);

      final msg = await harness.connection.recvHandshakeMessage();
      expect(msg.handshakeType, equals(TlsHandshakeType.serverHelloDone));

      final alertRecord = harness.connection.sentRecords
          .firstWhere((m) => m.contentType == ContentType.alert);
      expect(
          alertRecord.data,
          equals(Uint8List.fromList([
            AlertLevel.warning,
            AlertDescription.no_renegotiation,
          ])));
    });

    test('recvHandshakeMessage skips application data while buffering',
        () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      final appPayload = Uint8List.fromList([0x99, 0x00]);
      final appHeader = RecordHeader3().create(const TlsProtocolVersion(3, 3),
          ContentType.application_data, appPayload.length);
      harness.connection.queueRecord(appHeader, appPayload);

      final handshakePayload = _handshakeFragment([
        0x55,
      ], handshakeType: TlsHandshakeType.helloRequest.code);
      final handshakeHeader = RecordHeader3().create(
          const TlsProtocolVersion(3, 3),
          ContentType.handshake,
          handshakePayload.length);
      harness.connection.queueRecord(handshakeHeader, handshakePayload);

      final msg = await harness.connection.recvHandshakeMessage();
      expect(msg.handshakeType, equals(TlsHandshakeType.helloRequest));

      final (header, parser) = await harness.connection.recvMessage();
      expect(header.type, equals(ContentType.application_data));
      expect(parser.getRemainingLength(), equals(appPayload.length));
      expect(parser.getFixBytes(appPayload.length), equals(appPayload));
    });

      test('handshake transcript tracks buffered messages', () async {
        final harness = await _TlsConnectionHarness.create();
        addTearDown(() async => harness.dispose());

        final message = _rawHandshakeMessage(
          TlsHandshakeType.serverHelloDone,
          Uint8List(0),
        );
        _queueHandshakeMessage(harness.connection, message,
            version: const TlsProtocolVersion(3, 3));

        final parsed = await harness.connection.recvHandshakeMessage();
        expect(parsed.handshakeType, equals(TlsHandshakeType.serverHelloDone));

        final digest = harness.connection.handshakeHashes.digest('intrinsic');
        expect(digest, equals(message.serialize()));
      });

      test('key updates handled post-handshake and acked', () async {
        final harness = await _TlsConnectionHarness.create();
        addTearDown(() async => harness.dispose());

        final conn = harness.connection;
        conn.version = TlsProtocolVersion.tls13;
        conn.handshakeEstablished = true;
        conn.session = Session()
          ..cipherSuite = 0x1301
          ..clAppSecret = Uint8List.fromList(
              List<int>.generate(32, (index) => index + 1))
          ..srAppSecret = Uint8List.fromList(
              List<int>.generate(32, (index) => 0x80 + index));

        final originalClient = Uint8List.fromList(conn.session.clAppSecret);
        final originalServer = Uint8List.fromList(conn.session.srAppSecret);

        final keyUpdate = TlsKeyUpdate(updateRequested: true);
        _queueHandshakeMessage(conn, keyUpdate, version: TlsProtocolVersion.tls13);

        final finished = TlsFinished(
          verifyData: Uint8List.fromList(List<int>.filled(12, 0x44)),
        );
        _queueHandshakeMessage(conn, finished, version: TlsProtocolVersion.tls13);

        final parsed = await conn.recvHandshakeMessage();
        expect(parsed.handshakeType, equals(TlsHandshakeType.finished));

        final digest = conn.handshakeHashes.digest('intrinsic');
        expect(digest, equals(finished.serialize()));

        expect(conn.session.clAppSecret, isNot(equals(originalClient)));
        expect(conn.session.srAppSecret, isNot(equals(originalServer)));

        final ackRecord = conn.sentRecords
            .lastWhere((msg) => msg.contentType == ContentType.handshake);
        final ackMessages = TlsHandshakeMessage.parseFragment(
          ackRecord.data,
          recordVersion: TlsProtocolVersion.tls13,
        );
        expect(ackMessages.single, isA<TlsKeyUpdate>());
        expect((ackMessages.single as TlsKeyUpdate).updateRequested, isFalse);
      });

      test('new session tickets stored after handshake completes', () async {
        final harness = await _TlsConnectionHarness.create();
        addTearDown(() async => harness.dispose());

        final conn = harness.connection;
        conn.version = TlsProtocolVersion.tls13;
        conn.handshakeEstablished = true;

        final ticket = TlsNewSessionTicket(
          ticketLifetime: 7200,
          ticketAgeAdd: 0x01020304,
          ticketNonce: Uint8List.fromList(<int>[1, 2, 3]),
          ticket: Uint8List.fromList(<int>[4, 5, 6, 7]),
          extensions: Uint8List(0),
        );
        _queueHandshakeMessage(conn, ticket, version: TlsProtocolVersion.tls13);

        final finished = TlsFinished(
          verifyData: Uint8List.fromList(List<int>.filled(12, 0x55)),
        );
        _queueHandshakeMessage(conn, finished, version: TlsProtocolVersion.tls13);

        final parsed = await conn.recvHandshakeMessage();
        expect(parsed.handshakeType, equals(TlsHandshakeType.finished));

        expect(conn.tls13Tickets, hasLength(1));
        expect(conn.tls13Tickets.single.ticket, equals(ticket.ticket));

        final digest = conn.handshakeHashes.digest('intrinsic');
        expect(digest, equals(finished.serialize()));
      });

      test('handshake completion toggles via state machine', () async {
        final harness = await _TlsConnectionHarness.create();
        addTearDown(() async => harness.dispose());

        final conn = harness.connection;

        final serverHello = _serverHello();
        _queueHandshakeMessage(conn, serverHello,
            version: TlsProtocolVersion.tls12);

        final finished = TlsFinished(
          verifyData: Uint8List.fromList(List<int>.filled(12, 0x11)),
        );
        _queueHandshakeMessage(conn, finished,
            version: TlsProtocolVersion.tls12);

        expect(conn.handshakeEstablished, isFalse);
        final hello = await conn.recvHandshakeMessage();
        expect(hello.handshakeType, equals(TlsHandshakeType.serverHello));
        expect(conn.handshakeEstablished, isFalse);

        final done = await conn.recvHandshakeMessage();
        expect(done.handshakeType, equals(TlsHandshakeType.finished));
        expect(conn.handshakeEstablished, isTrue);
      });

      test('server mode enforces ClientHello ordering', () async {
        final harness = await _TlsConnectionHarness.create();
        addTearDown(() async => harness.dispose());

        final conn = harness.connection;
        conn.client = false;

        final serverHello = _serverHello();
        _queueHandshakeMessage(conn, serverHello,
            version: TlsProtocolVersion.tls12);

        await expectLater(() => conn.recvHandshakeMessage(),
            throwsA(isA<TLSUnexpectedMessage>()));
      });

      test('tls13 tickets propagate into cached sessions', () async {
        final cache = SessionCache(maxEntries: 4, maxAgeSeconds: 3600);
        final harness = await _TlsConnectionHarness.create(cache: cache);
        addTearDown(() async => harness.dispose());

        final conn = harness.connection;
        conn.version = TlsProtocolVersion.tls13;
        conn.handshakeEstablished = true;
        conn.session = Session()
          ..sessionID = Uint8List.fromList(<int>[0xAA])
          ..cipherSuite = 0x1301
          ..resumable = true
          ..clAppSecret = Uint8List.fromList(List<int>.filled(32, 1))
          ..srAppSecret = Uint8List.fromList(List<int>.filled(32, 2));

        final ticket = _newSessionTicket();
        _queueHandshakeMessage(conn, ticket, version: TlsProtocolVersion.tls13);

        final finished = TlsFinished(
          verifyData: Uint8List.fromList(List<int>.filled(12, 0x77)),
        );
        _queueHandshakeMessage(conn, finished, version: TlsProtocolVersion.tls13);

        await conn.recvHandshakeMessage();

        expect(conn.session.tls13Tickets, hasLength(1));
        expect(conn.session.tls13Tickets.single.ticket,
            equals(ticket.ticket));

        conn.cacheCurrentSession();
        final cached = cache.getOrNull(conn.session.sessionID);
        expect(cached, isNotNull);
        expect(cached!.tls13Tickets, hasLength(1));
        expect(cached.tls13Tickets.single.ticket, equals(ticket.ticket));
      });

    test('tls13 rejects interleaved records during handshake', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      harness.connection.version = TlsProtocolVersion.tls13;

      final fullFragment = _handshakeFragment(
        List<int>.filled(8, 0x01),
        handshakeType: TlsHandshakeType.finished.code,
      );
      final splitIndex = fullFragment.length - 2;
      final firstChunk = Uint8List.fromList(fullFragment.sublist(0, splitIndex));

      final firstHeader = RecordHeader3().create(const TlsProtocolVersion(3, 3),
          ContentType.handshake, firstChunk.length);
      harness.connection.queueRecord(firstHeader, firstChunk);

      final appPayload = Uint8List.fromList([0xDE, 0xAD]);
      final appHeader = RecordHeader3().create(const TlsProtocolVersion(3, 3),
          ContentType.application_data, appPayload.length);
      harness.connection.queueRecord(appHeader, appPayload);

      await expectLater(() => harness.connection.recvHandshakeMessage(),
          throwsA(isA<TLSUnexpectedMessage>()));

      final alertRecord = harness.connection.sentRecords
          .firstWhere((m) => m.contentType == ContentType.alert);
      expect(
          alertRecord.data,
          equals(Uint8List.fromList([
            AlertLevel.fatal,
            AlertDescription.unexpected_message,
          ])));
    });

    test('tls13 enforces exclusive handshake records', () async {
      final harness = await _TlsConnectionHarness.create();
      addTearDown(() async => harness.dispose());

      harness.connection.version = TlsProtocolVersion.tls13;

      final finished = TlsFinished(
        verifyData: Uint8List.fromList(List<int>.filled(12, 0x22)),
      );
      final trailing = _rawHandshakeMessage(
        TlsHandshakeType.helloRequest,
        Uint8List.fromList([0x00]),
      );
      final combined = Uint8List.fromList([
        ...finished.serialize(),
        ...trailing.serialize(),
      ]);
      final header = RecordHeader3().create(const TlsProtocolVersion(3, 3),
          ContentType.handshake, combined.length);
      harness.connection.queueRecord(header, combined);

      await expectLater(() => harness.connection.recvHandshakeMessage(),
          throwsA(isA<TLSUnexpectedMessage>()));

      final alertRecord = harness.connection.sentRecords
          .firstWhere((m) => m.contentType == ContentType.alert);
      expect(
          alertRecord.data,
          equals(Uint8List.fromList([
            AlertLevel.fatal,
            AlertDescription.unexpected_message,
          ])));
    });
  });

  group('TlsConnection TLS 1.3 resumption', () {
    test('reuses cached tickets and handles post-handshake updates', () async {
      final cache = SessionCache(maxEntries: 4, maxAgeSeconds: 3600);
      final firstHarness = await _TlsConnectionHarness.create(cache: cache);
      addTearDown(() async => firstHarness.dispose());

      final firstConn = firstHarness.connection;
      firstConn.version = TlsProtocolVersion.tls13;
      firstConn.handshakeEstablished = true;
      final initialSession = Session()
        ..sessionID = Uint8List.fromList([0x33])
        ..cipherSuite = 0x1301
        ..resumable = true
        ..clAppSecret = Uint8List.fromList(List<int>.filled(32, 0x01))
        ..srAppSecret = Uint8List.fromList(List<int>.filled(32, 0x02))
        ..clHandshakeSecret = Uint8List.fromList(List<int>.filled(32, 0x03))
        ..srHandshakeSecret = Uint8List.fromList(List<int>.filled(32, 0x04))
        ..resumptionMasterSecret =
            Uint8List.fromList(List<int>.filled(32, 0x05));
      firstConn.session = initialSession;

      final ticket = _newSessionTicket();
      _queueHandshakeMessage(firstConn, ticket,
          version: TlsProtocolVersion.tls13);
      final finished = TlsFinished(
        verifyData: Uint8List.fromList(List<int>.filled(12, 0x66)),
      );
      _queueHandshakeMessage(firstConn, finished,
          version: TlsProtocolVersion.tls13);
      await firstConn.recvHandshakeMessage();
      firstConn.cacheCurrentSession();

      final secondHarness = await _TlsConnectionHarness.create(cache: cache);
      addTearDown(() async => secondHarness.dispose());
      final resumedConn = secondHarness.connection;
      resumedConn.version = TlsProtocolVersion.tls13;
      final resumed = resumedConn.tryResumeSession(initialSession.sessionID);
      expect(resumed, isTrue);
      resumedConn.handshakeEstablished = true;
      resumedConn.session.clAppSecret =
          Uint8List.fromList(List<int>.filled(32, 0x10));
      resumedConn.session.srAppSecret =
          Uint8List.fromList(List<int>.filled(32, 0x11));

      final keyUpdate = TlsKeyUpdate(updateRequested: true);
      final newTicket = _newSessionTicket();
      _queueHandshakeMessage(resumedConn, keyUpdate,
          version: TlsProtocolVersion.tls13);
      _queueHandshakeMessage(resumedConn, newTicket,
          version: TlsProtocolVersion.tls13);
      final finalFinished = TlsFinished(
        verifyData: Uint8List.fromList(List<int>.filled(12, 0x55)),
      );
      _queueHandshakeMessage(resumedConn, finalFinished,
          version: TlsProtocolVersion.tls13);

      await resumedConn.recvHandshakeMessage();

      expect(resumedConn.session.tls13Tickets, hasLength(2));
      final ackRecord = resumedConn.sentRecords
          .where((msg) => msg.contentType == ContentType.handshake)
          .last;
      final ackMessages = TlsHandshakeMessage.parseFragment(
        ackRecord.data,
        recordVersion: TlsProtocolVersion.tls13,
      );
      expect(ackMessages.single, isA<TlsKeyUpdate>());
      expect((ackMessages.single as TlsKeyUpdate).updateRequested, isFalse);

      resumedConn.cacheCurrentSession();
      final cached = cache.getOrNull(resumedConn.session.sessionID);
      expect(cached, isNotNull);
      expect(cached!.tls13Tickets, hasLength(2));
    });
  });
}

class _TlsConnectionHarness {
  _TlsConnectionHarness(this.connection, this._peerSocket);

  final _FakeTlsConnection connection;
  final Socket _peerSocket;

  static Future<_TlsConnectionHarness> create({SessionCache? cache}) async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final client = await Socket.connect(server.address, server.port);
    final serverSide = await server.first;
    await server.close();

    final connection = _FakeTlsConnection(serverSide, cache: cache);
    return _TlsConnectionHarness(connection, client);
  }

  Future<void> dispose() async {
    await connection.sock?.close();
    await _peerSocket.close();
  }
}

class _FakeTlsConnection extends TlsConnection {
  _FakeTlsConnection(Socket socket, {SessionCache? cache})
      : super.testing(socket,
            sessionCache: cache, defragmenter: _testDefragmenter());

  final Queue<(dynamic, Parser)> _records = Queue();
  final List<Message> sentRecords = [];

  void queueRecord(dynamic header, Uint8List payload) {
    _records.addLast((header, Parser(payload)));
  }

  @override
  Future<(dynamic, Parser)> recvRecord() async {
    if (_records.isEmpty) {
      throw StateError('No queued records available');
    }
    return _records.removeFirst();
  }

  @override
  Future<void> sendRecord(Message msg) async {
    sentRecords.add(
      Message(msg.contentType, Uint8List.fromList(msg.write())),
    );
  }
}

Defragmenter _testDefragmenter() {
  final defragmenter = Defragmenter();
  defragmenter.addDynamicSize(ContentType.handshake, 1, 3);
  defragmenter.addStaticSize(ContentType.alert, 2);
  defragmenter.addStaticSize(ContentType.change_cipher_spec, 1);
  return defragmenter;
}

Uint8List _handshakeFragment(List<int> body, {int handshakeType = 1}) {
  final length = body.length;
  final builder = BytesBuilder();
  builder.add([handshakeType]);
  builder.add([(length >> 16) & 0xff, (length >> 8) & 0xff, length & 0xff]);
  builder.add(body);
  return builder.toBytes();
}

Uint8List _ssl2ClientHelloFragment({
  required TlsProtocolVersion version,
  required List<int> cipherSuites,
  required List<int> challenge,
  List<int>? sessionId,
}) {
  final cipherWriter = BytesBuilder();
  for (final suite in cipherSuites) {
    cipherWriter.add(<int>[0x00, (suite >> 8) & 0xff, suite & 0xff]);
  }
  final cipherBytes = cipherWriter.toBytes();
  final sessionBytes = Uint8List.fromList(sessionId ?? const <int>[]);
  final challengeBytes = Uint8List.fromList(challenge);

  final writer = BytesBuilder();
  writer.add(<int>[TlsHandshakeType.clientHello.code]);
  writer.add(<int>[version.major, version.minor]);
  writer.add(<int>[(cipherBytes.length >> 8) & 0xff, cipherBytes.length & 0xff]);
  writer.add(<int>[(sessionBytes.length >> 8) & 0xff, sessionBytes.length & 0xff]);
  writer.add(<int>[(challengeBytes.length >> 8) & 0xff, challengeBytes.length & 0xff]);
  writer.add(cipherBytes);
  writer.add(sessionBytes);
  writer.add(challengeBytes);
  return writer.toBytes();
}

RawTlsHandshakeMessage _rawHandshakeMessage(
    TlsHandshakeType type, Uint8List body) {
  return RawTlsHandshakeMessage(type: type, body: body);
}

TlsClientHello _clientHelloWithSinglePsk({
  int binderLength = 32,
  List<int>? identityBytes,
}) {
  final identity = TlsPskIdentity(
    identity: identityBytes ?? const <int>[0xAA, 0xBB],
    obfuscatedTicketAge: 0,
  );
  final preSharedKey = TlsPreSharedKeyExtension(
    identities: [identity],
    binders: [Uint8List(binderLength)],
  );
  final extensions = TlsExtensionBlock(extensions: <TlsExtension>[
    TlsSupportedVersionsExtension.client([TlsProtocolVersion.tls13]),
    preSharedKey,
  ]);
  return TlsClientHello(
    clientVersion: TlsProtocolVersion.tls13,
    random: Uint8List.fromList(List<int>.filled(32, 0x11)),
    sessionId: Uint8List.fromList(List<int>.filled(32, 0x22)),
    cipherSuites: const <int>[0x1301],
    compressionMethods: const <int>[0],
    extensions: extensions,
  );
}

void _queueHandshakeMessage(_FakeTlsConnection connection,
    TlsHandshakeMessage message,
    {TlsProtocolVersion version = TlsProtocolVersion.tls13}) {
  final payload = message.serialize();
  final header =
      RecordHeader3().create(version, ContentType.handshake, payload.length);
  connection.queueRecord(header, payload);
}

TlsServerHello _serverHello() {
  return TlsServerHello(
    serverVersion: TlsProtocolVersion.tls12,
    random: Uint8List(32),
    sessionId: Uint8List(32),
    cipherSuite: 0x1301,
    compressionMethod: 0,
    selectedSupportedVersion: TlsProtocolVersion.tls13,
  );
}

TlsNewSessionTicket _newSessionTicket() {
  return TlsNewSessionTicket(
    ticketLifetime: 7200,
    ticketAgeAdd: 0x01020304,
    ticketNonce: Uint8List.fromList(<int>[1, 2, 3, 4]),
    ticket: Uint8List.fromList(<int>[4, 5, 6, 7, 8]),
    extensions: Uint8List(0),
  );
}
