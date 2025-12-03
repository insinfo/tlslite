import 'dart:collection';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:tlslite/src/constants.dart';
import 'package:tlslite/src/defragmenter.dart';
import 'package:tlslite/src/errors.dart';
import 'package:tlslite/src/messages.dart';
import 'package:tlslite/src/recordlayer.dart';
import 'package:tlslite/src/session.dart';
import 'package:tlslite/src/sessioncache.dart';
import 'package:tlslite/src/tls_protocol.dart';
import 'package:tlslite/src/tlsconnection.dart';
import 'package:tlslite/src/utils/codec.dart';

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
    await connection.sock.close();
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

RawTlsHandshakeMessage _rawHandshakeMessage(
    TlsHandshakeType type, Uint8List body) {
  return RawTlsHandshakeMessage(type: type, body: body);
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
