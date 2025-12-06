import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/constants.dart';
import 'package:tlslite/src/errors.dart';
import 'package:tlslite/src/session.dart';
import 'package:tlslite/src/tls_protocol.dart';
import 'package:tlslite/src/tls_record_layer.dart';

void main() {
  group('TLSRecordLayer', () {
    test('constructor initializes state correctly', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      expect(layer, isNotNull);
      expect(layer, isA<TLSRecordLayer>());
      expect(layer.closed, isTrue);
      expect(layer.resumed, isFalse);
      expect(layer.closeSocket, isTrue);
      expect(layer.ignoreAbruptClose, isFalse);
      expect(layer.heartbeatSupported, isFalse);
      expect(layer.heartbeatCanReceive, isFalse);
      expect(layer.heartbeatCanSend, isFalse);
    });

    test('getVersionName returns correct version strings', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      layer.version = const TlsProtocolVersion(3, 0);
      expect(layer.getVersionName(), equals('SSL 3.0'));

      layer.version = const TlsProtocolVersion(3, 1);
      expect(layer.getVersionName(), equals('TLS 1.0'));

      layer.version = const TlsProtocolVersion(3, 2);
      expect(layer.getVersionName(), equals('TLS 1.1'));

      layer.version = const TlsProtocolVersion(3, 3);
      expect(layer.getVersionName(), equals('TLS 1.2'));

      layer.version = const TlsProtocolVersion(3, 4);
      expect(layer.getVersionName(), equals('TLS 1.3'));
    });

    test('recordSize respects userRecordLimit', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      // Default record size is 2^14 = 16384
      expect(layer.recordSize, lessThanOrEqualTo(16384));

      // Set a lower limit
      layer.recordSize = 1024;
      expect(layer.recordSize, equals(1024));
    });

    test('recordSize throws on invalid values', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      expect(() => layer.recordSize = 0, throwsArgumentError);
      expect(() => layer.recordSize = -1, throwsArgumentError);
    });

    test('handshakeStart prepares for new handshake', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      layer.handshakeStart(client: true);

      expect(layer.isClient, isTrue);
      expect(layer.closed, isTrue);
      expect(layer.resumed, isFalse);

      layer.handshakeStart(client: false);

      expect(layer.isClient, isFalse);
    });

    test('handshakeStart throws on active connection', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      // Mark connection as open
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);

      expect(
        () => layer.handshakeStart(client: true),
        throwsStateError,
      );
    });

    test('handshakeDone marks connection as established', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      layer.handshakeStart(client: true);
      expect(layer.closed, isTrue);

      layer.handshakeDone(false);

      expect(layer.closed, isFalse);
      expect(layer.resumed, isFalse);
    });

    test('handshakeDone marks connection as resumed', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      layer.handshakeStart(client: true);
      layer.handshakeDone(true);

      expect(layer.closed, isFalse);
      expect(layer.resumed, isTrue);
    });

    test('clearReadBuffer resets buffered plaintext', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      layer.clearReadBuffer();
      expect(layer.bufferedPlaintext, isEmpty);
    });

    test('isClient property reflects client mode', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      layer.isClient = true;
      expect(layer.isClient, isTrue);

      layer.isClient = false;
      expect(layer.isClient, isFalse);
    });

    test('version setter updates protocol version', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      layer.version = const TlsProtocolVersion(3, 3);
      expect(layer.version, equals(const TlsProtocolVersion(3, 3)));

      layer.version = const TlsProtocolVersion(3, 4);
      expect(layer.version, equals(const TlsProtocolVersion(3, 4)));
    });

    test('encryptThenMAC property can be set', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      // encryptThenMAC setter modifies pending state; it doesn't
      // immediately change the active read/write state. This is
      // the expected behavior matching tlslite-ng.
      expect(layer.encryptThenMAC, isFalse); // Default is false

      // Setting encryptThenMAC only affects pending states
      layer.encryptThenMAC = true;
      // The getter returns the current write state, not pending
      // so this remains false until changeWriteState is called
      expect(layer.encryptThenMAC, isFalse);
    });

    test('handshakeHashes exposes transcript state', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);

      expect(layer.handshakeHashes, isNotNull);
    });

    test('session can be set and retrieved', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      expect(layer.session, isNull);

      final session = Session();
      layer.session = session;

      expect(layer.session, same(session));
    });

    test('tickets list starts empty', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      expect(layer.tickets, isEmpty);
    });

    test('tls13Tickets list starts empty', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      expect(layer.tls13Tickets, isEmpty);
    });

    test('maxEarlyData defaults to zero', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      expect(layer.maxEarlyData, equals(0));
    });

    test('clientCertRequired defaults to false', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      expect(layer.clientCertRequired, isFalse);
    });

    test('heartbeat callback can be set', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      expect(layer.heartbeatResponseCallback, isNull);

      layer.heartbeatResponseCallback = (_) {
        // Callback can be set
      };

      expect(layer.heartbeatResponseCallback, isNotNull);
    });
  });

  group('TLSRecordLayer read', () {
    test('read with min=0 returns empty when no data available', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);
      layer.ignoreAbruptClose = true;

      // Close peer socket to trigger close
      await harness.closeClientSocket();

      final result = await layer.read(min: 0, max: 100);
      expect(result, isEmpty);
    });

    test('read throws on negative min', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);

      expect(
        () async => layer.read(min: -1),
        throwsArgumentError,
      );
    });

    test('read throws on negative max', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);

      expect(
        () async => layer.read(max: -1),
        throwsArgumentError,
      );
    });

    test('read throws on max less than min', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);

      expect(
        () async => layer.read(min: 10, max: 5),
        throwsArgumentError,
      );
    });
  });

  group('TLSRecordLayer write', () {
    test('write with empty data does nothing', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);
      layer.version = const TlsProtocolVersion(3, 3);

      // Should complete without error
      await layer.write(Uint8List(0));
    });
  });

  group('TLSRecordLayer compatibility wrappers', () {
    test('send returns length of data', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);
      layer.version = const TlsProtocolVersion(3, 3);

      final data = Uint8List.fromList([1, 2, 3, 4, 5]);
      final result = await layer.send(data);

      expect(result, equals(5));
    });

    test('recv is alias for read', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);
      layer.ignoreAbruptClose = true;

      await harness.closeClientSocket();

      final result = await layer.recv(100);
      expect(result, isEmpty);
    });
  });

  group('TLSRecordLayer heartbeat', () {
    test('sendHeartbeatRequest throws when connection closed', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.heartbeatSupported = true;
      layer.heartbeatCanSend = true;

      expect(
        () async => layer.sendHeartbeatRequest(Uint8List(10), 16),
        throwsA(isA<TLSClosedConnectionError>()),
      );
    });

    test('sendHeartbeatRequest throws when not supported', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);
      layer.heartbeatSupported = false;

      expect(
        () async => layer.sendHeartbeatRequest(Uint8List(10), 16),
        throwsA(isA<TLSInternalError>()),
      );
    });

    test('sendHeartbeatRequest throws when cannot send', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);
      layer.heartbeatSupported = true;
      layer.heartbeatCanSend = false;

      expect(
        () async => layer.sendHeartbeatRequest(Uint8List(10), 16),
        throwsA(isA<TLSInternalError>()),
      );
    });

    test('sendHeartbeatRequest throws on invalid padding', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);
      layer.heartbeatSupported = true;
      layer.heartbeatCanSend = true;

      expect(
        () async => layer.sendHeartbeatRequest(Uint8List(10), -1),
        throwsArgumentError,
      );
    });

    test('sendHeartbeatRequest throws on oversized payload', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);
      layer.heartbeatSupported = true;
      layer.heartbeatCanSend = true;

      expect(
        () async => layer.sendHeartbeatRequest(Uint8List(70000), 16),
        throwsArgumentError,
      );
    });
  });

  group('TLSRecordLayer KeyUpdate', () {
    test('sendKeyUpdate throws when connection closed', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;

      expect(
        () async => layer.sendKeyUpdate(),
        throwsA(isA<TLSClosedConnectionError>()),
      );
    });

    test('sendKeyUpdate throws on non-TLS 1.3 connection', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);
      layer.version = const TlsProtocolVersion(3, 3); // TLS 1.2

      expect(
        () async => layer.sendKeyUpdate(),
        throwsA(isA<TLSIllegalParameterException>()),
      );
    });

    test('sendKeyUpdate throws without session', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);
      layer.version = const TlsProtocolVersion(3, 4); // TLS 1.3

      expect(
        () async => layer.sendKeyUpdate(),
        throwsA(isA<TLSInternalError>()),
      );
    });

    test('sendKeyUpdate throws without traffic secrets', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);
      layer.version = const TlsProtocolVersion(3, 4); // TLS 1.3

      final session = Session();
      session.clAppSecret = Uint8List(0);
      session.srAppSecret = Uint8List(0);
      layer.session = session;

      expect(
        () async => layer.sendKeyUpdate(),
        throwsA(isA<TLSInternalError>()),
      );
    });
  });

  group('TLSRecordLayer close', () {
    test('close initiates graceful shutdown', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.handshakeStart(client: true);
      layer.handshakeDone(false);

      await layer.close();

      expect(layer.closed, isTrue);
    });
  });

  group('TLSRecordLayer calcPendingStates', () {
    test('calcPendingStates configures cipher suite', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.version = const TlsProtocolVersion(3, 3);

      // This should not throw
      layer.calcPendingStates(
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        Uint8List(48), // master secret
        Uint8List(32), // client random
        Uint8List(32), // server random
      );
    });

    test('changeWriteState activates pending write state', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.version = const TlsProtocolVersion(3, 3);

      layer.calcPendingStates(
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        Uint8List(48),
        Uint8List(32),
        Uint8List(32),
      );

      // This should not throw
      layer.changeWriteState();
    });

    test('changeReadState activates pending read state', () async {
      final harness = await _TlsRecordLayerHarness.create();
      addTearDown(() => harness.dispose());

      final layer = harness.recordLayer;
      layer.version = const TlsProtocolVersion(3, 3);

      layer.calcPendingStates(
        CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
        Uint8List(48),
        Uint8List(32),
        Uint8List(32),
      );

      // This should not throw
      layer.changeReadState();
    });
  });
}

/// Test harness providing isolated socket pairs for TLSRecordLayer testing.
class _TlsRecordLayerHarness {
  _TlsRecordLayerHarness._(
    this.recordLayer,
    this._server,
    this._serverSocket,
    this._clientSocket,
  );

  final TLSRecordLayer recordLayer;
  final ServerSocket _server;
  final Socket _serverSocket;
  final Socket _clientSocket;

  static Future<_TlsRecordLayerHarness> create() async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final clientFuture = Socket.connect(server.address, server.port);
    final serverSocket = await server.first;
    final clientSocket = await clientFuture;

    final recordLayer = TLSRecordLayer(serverSocket);
    return _TlsRecordLayerHarness._(
      recordLayer,
      server,
      serverSocket,
      clientSocket,
    );
  }

  /// Send raw bytes from the client side (peer).
  void sendFromPeer(Uint8List data) {
    _clientSocket.add(data);
  }

  /// Close the client socket to simulate peer disconnect.
  Future<void> closeClientSocket() async {
    await _clientSocket.close();
  }

  Future<void> dispose() async {
    try {
      await _serverSocket.close();
    } catch (_) {}
    try {
      await _clientSocket.close();
    } catch (_) {}
    try {
      await _server.close();
    } catch (_) {}
  }
}
