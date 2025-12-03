import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/constants.dart' as tls_constants;
import 'package:tlslite/src/messages.dart';
import 'package:tlslite/src/session.dart';
import 'package:tlslite/src/tls_protocol.dart';
import 'package:tlslite/src/tls_record_layer.dart';

void main() {
  test('handleKeyUpdateRequest rotates secrets and responds when requested', () async {
    final harness = await _KeyUpdateHarness.client();
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

  test('sendKeyUpdate emits records and updates local sending secret', () async {
    final harness = await _KeyUpdateHarness.client();
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
}

class _KeyUpdateHarness {
  _KeyUpdateHarness(this.layer, this.peer, this.session);

  final TLSRecordLayer layer;
  final Socket peer;
  final Session session;

  Socket get _client => layer.sock;

  static Future<_KeyUpdateHarness> client() async {
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

    return _KeyUpdateHarness(layer, peer, session);
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
