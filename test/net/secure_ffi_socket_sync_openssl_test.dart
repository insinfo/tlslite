import 'dart:async';
import 'dart:isolate';
import 'dart:typed_data';
import 'dart:io' as io;

import 'package:test/test.dart';
import 'package:tlslite/src/net_ffi/sync/socket_native_ffi.dart';
import 'package:tlslite/src/net_ffi/sync/secure_socket_openssl.dart';

void main() {
  late String certPath;
  late String keyPath;

  setUpAll(() {
    certPath = io.File('test/certificates/serverX509Cert.pem').absolute.path;
    keyPath = io.File('test/certificates/serverX509Key.pem').absolute.path;
  });

  test('SecureFFISocketOpenSSL performs TLS handshake against server isolate', () async {
    final receivePort = ReceivePort();
    final readyCompleter = Completer<int>();
    final resultCompleter = Completer<void>();

    final subscription = receivePort.listen((dynamic message) {
      if (message is Map<String, Object?>) {
        switch (message['type']) {
          case 'ready':
            if (!readyCompleter.isCompleted) {
              readyCompleter.complete(message['port'] as int);
            }
            break;
          case 'done':
            if (!resultCompleter.isCompleted) {
              resultCompleter.complete();
            }
            break;
          case 'error':
            if (!resultCompleter.isCompleted) {
              final details = message['message'] as String? ?? 'unknown error';
              resultCompleter.completeError(StateError(details));
            }
            break;
        }
      }
    });

    await Isolate.spawn<_FfiServerConfig>(
      _ffiServerEntry,
      _FfiServerConfig(
        sendPort: receivePort.sendPort,
        certPath: certPath,
        keyPath: keyPath,
      ),
    );

    final port = await readyCompleter.future;
    final client = SecureFFISocketOpenSSL(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    addTearDown(client.close);
    client.connect('127.0.0.1', port);
    client.ensureHandshakeCompleted();

    final payload = Uint8List.fromList('ping'.codeUnits);
    client.sendall(payload);
    final response = client.recv(4);
    expect(String.fromCharCodes(response), equals('pong'));
    client.close();

    await resultCompleter.future;
    await subscription.cancel();
    receivePort.close();
  }, timeout: const Timeout(Duration(seconds: 20)));
}

class _FfiServerConfig {
  const _FfiServerConfig({
    required this.sendPort,
    required this.certPath,
    required this.keyPath,
  });

  final SendPort sendPort;
  final String certPath;
  final String keyPath;
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
    final request = session.recv(4);
    final payload = String.fromCharCodes(request);
    if (payload != 'ping') {
      throw StateError('Unexpected payload: $payload');
    }
    session.sendall(Uint8List.fromList('pong'.codeUnits));
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
