import 'dart:async';
import 'dart:isolate';
import 'dart:typed_data';
import 'dart:io' as io;

import 'package:test/test.dart';
import 'package:tlslite/src/net_ffi/async/secure_socket_openssl_async.dart';
import 'package:tlslite/src/net_ffi/sync/socket_native_ffi.dart';
import 'package:tlslite/src/net_ffi/sync/secure_socket_openssl.dart';

void main() {
  late String certPath;
  late String keyPath;

  setUpAll(() {
    certPath = io.File('test/certificates/serverX509Cert.pem').absolute.path;
    keyPath = io.File('test/certificates/serverX509Key.pem').absolute.path;
  });

  test('SecureSocketOpenSSLIsolateClient performs TLS ping-pong', () async {
    final harness = _FfiServerHarness(
      certPath: certPath,
      keyPath: keyPath,
      behavior: _ServerBehavior.echoOnce,
    );
    await harness.start();

    final client = await SecureSocketOpenSSLIsolateClient.connect(
      host: '127.0.0.1',
      port: harness.port,
    );
    addTearDown(client.close);

    final payload = Uint8List.fromList('ping'.codeUnits);
    await client.send(payload);
    final response = await client.recv(4);
    expect(String.fromCharCodes(response), equals('pong'));

    await client.close();
    await harness.done;
    await harness.dispose();
  }, timeout: const Timeout(Duration(seconds: 20)));

  test('Client observes EOF when server closes after handshake', () async {
    final harness = _FfiServerHarness(
      certPath: certPath,
      keyPath: keyPath,
      behavior: _ServerBehavior.closeAfterHandshake,
    );
    await harness.start();

    final client = await SecureSocketOpenSSLIsolateClient.connect(
      host: '127.0.0.1',
      port: harness.port,
    );
    addTearDown(client.close);

    final data = await client.recv(8);
    expect(data, isEmpty);

    await client.close();
    await harness.done;
    await harness.dispose();
  }, timeout: const Timeout(Duration(seconds: 20)));
}

enum _ServerBehavior { echoOnce, closeAfterHandshake }

class _FfiServerHarness {
  _FfiServerHarness({
    required this.certPath,
    required this.keyPath,
    required this.behavior,
  });

  final String certPath;
  final String keyPath;
  final _ServerBehavior behavior;
  final ReceivePort _receivePort = ReceivePort();
  StreamSubscription<dynamic>? _subscription;
  final Completer<int> _portCompleter = Completer<int>();
  final Completer<void> _doneCompleter = Completer<void>();
  Isolate? _isolate;
  int? _port;

  int get port {
    final value = _port;
    if (value == null) {
      throw StateError('Server port is not ready');
    }
    return value;
  }

  Future<void> get done => _doneCompleter.future;

  Future<void> start() async {
    _subscription = _receivePort.listen((dynamic message) {
      if (message is! Map<String, Object?>) {
        return;
      }
      switch (message['type']) {
        case 'ready':
          _port ??= message['port'] as int;
          if (!_portCompleter.isCompleted) {
            _portCompleter.complete(_port);
          }
          break;
        case 'done':
          if (!_doneCompleter.isCompleted) {
            _doneCompleter.complete();
          }
          break;
        case 'error':
          final details = message['message'] as String? ?? 'unknown error';
          if (!_doneCompleter.isCompleted) {
            _doneCompleter.completeError(StateError(details));
          }
          break;
      }
    });

    _isolate = await Isolate.spawn<_FfiServerConfig>(
      _ffiServerEntry,
      _FfiServerConfig(
        sendPort: _receivePort.sendPort,
        certPath: certPath,
        keyPath: keyPath,
        behavior: behavior,
      ),
    );

    await _portCompleter.future;
  }

  Future<void> dispose() async {
    _isolate?.kill(priority: Isolate.immediate);
    await _subscription?.cancel();
    _receivePort.close();
  }
}

class _FfiServerConfig {
  const _FfiServerConfig({
    required this.sendPort,
    required this.certPath,
    required this.keyPath,
    required this.behavior,
  });

  final SendPort sendPort;
  final String certPath;
  final String keyPath;
  final _ServerBehavior behavior;
}

void _ffiServerEntry(_FfiServerConfig config) {
  final sendPort = config.sendPort;
  try {
    final listener = SecureFFISocketOpenSSL.server(
      AF_INET,
      SOCK_STREAM,
      IPPROTO_TCP,
      config.certPath,
      config.keyPath,
    );
    listener.bind('127.0.0.1', 0);
    final port = listener.port;
    sendPort.send(<String, Object?>{'type': 'ready', 'port': port});
    listener.listen(1);

    final session = listener.accept() as SecureFFISocketOpenSSL;
    switch (config.behavior) {
      case _ServerBehavior.echoOnce:
        final request = session.recv(4);
        final payload = String.fromCharCodes(request);
        if (payload != 'ping') {
          throw StateError('Unexpected payload: $payload');
        }
        session.sendall(Uint8List.fromList('pong'.codeUnits));
        break;
      case _ServerBehavior.closeAfterHandshake:
        break;
    }
    session.close();
    listener.close();
    sendPort.send(<String, Object?>{'type': 'done'});
  } catch (error, stackTrace) {
    sendPort.send(<String, Object?>{
      'type': 'error',
      'message': error.toString(),
      'stack': stackTrace.toString(),
    });
  }
}
