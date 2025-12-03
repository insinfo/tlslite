import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/constants.dart' as tls_constants;
import 'package:tlslite/src/errors.dart';
import 'package:tlslite/src/messages.dart';
import 'package:tlslite/src/session.dart';
import 'package:tlslite/src/tls_protocol.dart';
import 'package:tlslite/src/tls_record_layer.dart';

void main() {
  group('KeyUpdate', () {
    test('handleKeyUpdateRequest rotates secrets and responds when requested',
        () async {
      final harness = await _RecordLayerHarness.client();
      addTearDown(harness.dispose);

      final initialClientSecret = Uint8List.fromList(harness.session.clAppSecret);
      final initialServerSecret = Uint8List.fromList(harness.session.srAppSecret);

      await harness.layer.handleKeyUpdateRequest(
        TlsKeyUpdate(updateRequested: true),
      );

      final recordBytes = await _readTlsRecord(harness.peer);
      final messages = TlsHandshakeMessage.parseFragment(
        recordBytes.sublist(5),
        recordVersion: TlsProtocolVersion.tls13,
      );
      final response = messages.single as TlsKeyUpdate;

      expect(response.updateRequested, isFalse);
      expect(harness.session.srAppSecret, isNot(equals(initialServerSecret)));
      expect(harness.session.clAppSecret, isNot(equals(initialClientSecret)));
    });

    test('sendKeyUpdate emits records and updates local sending secret',
        () async {
      final harness = await _RecordLayerHarness.client();
      addTearDown(harness.dispose);

      final initialClientSecret = Uint8List.fromList(harness.session.clAppSecret);
      final initialServerSecret = Uint8List.fromList(harness.session.srAppSecret);

      await harness.layer.sendKeyUpdate(updateRequested: true);
      final recordBytes = await _readTlsRecord(harness.peer);
      final messages = TlsHandshakeMessage.parseFragment(
        recordBytes.sublist(5),
        recordVersion: TlsProtocolVersion.tls13,
      );
      final outbound = messages.single as TlsKeyUpdate;

      expect(outbound.updateRequested, isTrue);
      expect(harness.session.clAppSecret, isNot(equals(initialClientSecret)));
      expect(harness.session.srAppSecret, equals(initialServerSecret));
    });
  });

  group('Heartbeat', () {
    test('incoming heartbeat request triggers automatic response', () async {
      final harness = await _RecordLayerHarness.client();
      addTearDown(harness.dispose);

      harness.layer
        ..heartbeatSupported = true
        ..heartbeatCanReceive = true;

      final requestPayload = Uint8List.fromList(<int>[0x10, 0x20]);
      final requestPadding = Uint8List.fromList(List<int>.generate(18, (i) => i));
      final request = TlsHeartbeat(
        messageType: tls_constants.HeartbeatMessageType.heartbeat_request,
        payload: requestPayload,
        padding: requestPadding,
      );

      await _sendHeartbeatRecord(harness.peer, request);
      await _sendApplicationDataRecord(
        harness.peer,
        Uint8List.fromList(<int>[0x41]),
      );

      final appData = await harness.layer.read(max: 1, min: 1);
      expect(appData.single, equals(0x41));

      final responseRecord = await _readTlsRecord(harness.peer);
      expect(responseRecord.first, equals(tls_constants.ContentType.heartbeat));
      final response = TlsHeartbeat.parse(responseRecord.sublist(5));
      expect(
        response.messageType,
        equals(tls_constants.HeartbeatMessageType.heartbeat_response),
      );
      expect(response.payload, equals(requestPayload));
      expect(response.padding.length, equals(requestPadding.length));
    });

    test('heartbeat request rejected when peer is not allowed to send', () async {
      final harness = await _RecordLayerHarness.client();
      addTearDown(harness.dispose);

      harness.layer
        ..heartbeatSupported = true
        ..heartbeatCanReceive = false;

      final request = TlsHeartbeat(
        messageType: tls_constants.HeartbeatMessageType.heartbeat_request,
        payload: Uint8List.fromList(<int>[0x01]),
        padding: Uint8List.fromList(List<int>.filled(16, 0xAA)),
      );

      await _sendHeartbeatRecord(harness.peer, request);

      expect(
        () => harness.layer.read(max: 1, min: 1),
        throwsA(isA<TLSLocalAlert>()),
      );
    });

    test('heartbeat response notifies callback', () async {
      final harness = await _RecordLayerHarness.client();
      addTearDown(harness.dispose);

      harness.layer.heartbeatSupported = true;
      final payload = Uint8List.fromList(<int>[9, 9]);
      final response = TlsHeartbeat(
        messageType: tls_constants.HeartbeatMessageType.heartbeat_response,
        payload: payload,
        padding: Uint8List.fromList(List<int>.filled(20, 0xFF)),
      );

      final callbackCompleter = Completer<TlsHeartbeat>();
      harness.layer.heartbeatResponseCallback = callbackCompleter.complete;

      await _sendHeartbeatRecord(harness.peer, response);
      await _sendApplicationDataRecord(
        harness.peer,
        Uint8List.fromList(<int>[0x55]),
      );

      final data = await harness.layer.read(max: 1, min: 1);
      expect(data.single, equals(0x55));

      final notified = await callbackCompleter.future.timeout(
        const Duration(seconds: 1),
      );
      expect(notified.payload, equals(payload));
    });

    test('sendHeartbeatRequest transmits payload and padding', () async {
      final harness = await _RecordLayerHarness.client();
      addTearDown(harness.dispose);

      harness.layer
        ..heartbeatSupported = true
        ..heartbeatCanSend = true;

      final payload = Uint8List.fromList(<int>[0xAA, 0xBB]);
      await harness.layer.sendHeartbeatRequest(payload, 18);

      final recordBytes = await _readTlsRecord(harness.peer);
      expect(recordBytes.first, equals(tls_constants.ContentType.heartbeat));

      final message = TlsHeartbeat.parse(recordBytes.sublist(5));
      expect(
        message.messageType,
        equals(tls_constants.HeartbeatMessageType.heartbeat_request),
      );
      expect(message.payload, equals(payload));
      expect(message.padding.length, equals(18));
    });

    test('sendHeartbeatRequest rejects closed connection', () async {
      final harness = await _RecordLayerHarness.client();
      addTearDown(harness.dispose);

      harness.layer.closed = true;
      expect(
        () => harness.layer.sendHeartbeatRequest(Uint8List(0), 16),
        throwsA(isA<TLSClosedConnectionError>()),
      );
    });

    test('sendHeartbeatRequest enforces capability flags', () async {
      final harness = await _RecordLayerHarness.client();
      addTearDown(harness.dispose);

      harness.layer
        ..heartbeatSupported = false
        ..heartbeatCanSend = true;

      expect(
        () => harness.layer.sendHeartbeatRequest(Uint8List(0), 16),
        throwsA(isA<TLSInternalError>()),
      );

      harness.layer
        ..heartbeatSupported = true
        ..heartbeatCanSend = false;

      expect(
        () => harness.layer.sendHeartbeatRequest(Uint8List(0), 16),
        throwsA(isA<TLSInternalError>()),
      );
    });

    test('sendHeartbeatRequest validates arguments', () async {
      final harness = await _RecordLayerHarness.client();
      addTearDown(harness.dispose);

      harness.layer
        ..heartbeatSupported = true
        ..heartbeatCanSend = true;

      expect(
        () => harness.layer.sendHeartbeatRequest(Uint8List(0), -1),
        throwsA(isA<ArgumentError>()),
      );

      final bigPayload = Uint8List(0x10000);
      expect(
        () => harness.layer.sendHeartbeatRequest(bigPayload, 16),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}

class _RecordLayerHarness {
  _RecordLayerHarness(this.layer, this.peer, this.session);

  final TLSRecordLayer layer;
  final Socket peer;
  final Session session;

  Socket get _client => layer.sock;

  static Future<_RecordLayerHarness> client() async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final client = await Socket.connect(server.address, server.port);
    final peer = await server.first;
    await server.close();

    final layer = TLSRecordLayer(client)
      ..version = TlsProtocolVersion.tls13
      ..isClient = true
      ..closed = false;

    final session = Session()
      ..cipherSuite = tls_constants.CipherSuite.TLS_AES_128_GCM_SHA256
      ..clAppSecret = Uint8List.fromList(List<int>.generate(32, (i) => i + 1))
      ..srAppSecret = Uint8List.fromList(List<int>.generate(32, (i) => i + 65));
    layer.session = session;

    return _RecordLayerHarness(layer, peer, session);
  }

  Future<void> dispose() async {
    await Future.wait<dynamic>(<Future<dynamic>>[
      _client.close(),
      peer.close(),
    ]);
  }
}

Future<Uint8List> _readTlsRecord(Socket socket) {
  final completer = Completer<Uint8List>();
  final buffer = <int>[];
  int? expectedLength;
  late StreamSubscription<Uint8List> sub;
  sub = socket.listen(
    (chunk) {
      buffer.addAll(chunk);
      if (expectedLength == null && buffer.length >= 5) {
        final bodyLength = (buffer[3] << 8) | buffer[4];
        expectedLength = bodyLength + 5;
      }
      if (expectedLength != null && buffer.length >= expectedLength!) {
        sub.cancel();
        completer.complete(
          Uint8List.fromList(buffer.sublist(0, expectedLength!)),
        );
      }
    },
    onError: (Object error, StackTrace stackTrace) {
      if (!completer.isCompleted) {
        completer.completeError(error, stackTrace);
      }
    },
    onDone: () {
      if (!completer.isCompleted) {
        completer.completeError(
          StateError('socket closed before full record arrived'),
        );
      }
    },
    cancelOnError: true,
  );
  return completer.future;
}

Future<void> _sendHeartbeatRecord(Socket socket, TlsHeartbeat heartbeat) {
  return _sendPlaintextRecord(
    socket,
    tls_constants.ContentType.heartbeat,
    heartbeat.serialize(),
  );
}

Future<void> _sendApplicationDataRecord(Socket socket, Uint8List data) {
  return _sendPlaintextRecord(
    socket,
    tls_constants.ContentType.application_data,
    data,
  );
}

Future<void> _sendPlaintextRecord(
  Socket socket,
  int contentType,
  Uint8List fragment,
) async {
  final header = Uint8List(5);
  header[0] = contentType;
  header[1] = TlsProtocolVersion.tls12.major;
  header[2] = TlsProtocolVersion.tls12.minor;
  header[3] = (fragment.length >> 8) & 0xff;
  header[4] = fragment.length & 0xff;

  socket.add(header);
  socket.add(fragment);
  await socket.flush();
}
