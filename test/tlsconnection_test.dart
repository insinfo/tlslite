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
          throwsA(isA<TLSUnexpectedMessage>()));

      final (header, parser) = await harness.connection.recvMessage();
      expect(header.type, equals(ContentType.alert));
      expect(parser.getRemainingLength(), equals(alertPayload.length));

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
