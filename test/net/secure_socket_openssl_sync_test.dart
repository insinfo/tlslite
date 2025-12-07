import 'dart:async';
import 'dart:isolate';
import 'dart:io' as io;
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/net/secure_socket_openssl_async.dart';
import 'package:tlslite/src/net/secure_socket_openssl_sync.dart';

void main() {
  late String certPath;
  late String keyPath;

  setUpAll(() {
    certPath = io.File('test/certificates/serverX509Cert.pem').absolute.path;
    keyPath = io.File('test/certificates/serverX509Key.pem').absolute.path;
  });

  test('SecureSocketOpenSSLSync completes handshake and echoes data', () async {
    final eventPort = ReceivePort();
    final errorPort = ReceivePort();

    final serverReady = Completer<int>();
    final serverDone = Completer<void>();
    final eventSubscription = eventPort.listen((dynamic message) {
      if (message is Map<String, Object?>) {
        switch (message['event']) {
          case 'listening':
            if (!serverReady.isCompleted) {
              serverReady.complete(message['port'] as int);
            }
            break;
          case 'done':
            if (!serverDone.isCompleted) {
              serverDone.complete();
            }
            break;
          case 'error':
            final details = message['message'] as String? ?? 'server error';
            if (!serverDone.isCompleted) {
              serverDone.completeError(StateError(details));
            }
            break;
        }
      }
    });

    final args = _SecureServerArgs(
      certPath: certPath,
      keyPath: keyPath,
      controlPort: eventPort.sendPort,
    );
    await Isolate.spawn<_SecureServerArgs>(
      _runSecureServer,
      args,
      onError: errorPort.sendPort,
    );

    final port = await serverReady.future;
    print('test: server listening on $port');

    final errorSubscription = errorPort.listen((dynamic message) {
      fail('server isolate error: $message');
    });

    final clientResultPort = ReceivePort();
    final clientErrorPort = ReceivePort();

    final clientArgs = _SecureClientArgs(
      port: port,
      resultPort: clientResultPort.sendPort,
    );

    await Isolate.spawn<_SecureClientArgs>(
      _runSecureClient,
      clientArgs,
      onError: clientErrorPort.sendPort,
    );

    final clientResultFuture = clientResultPort.first;
    final clientErrorSubscription = clientErrorPort.listen((dynamic message) {
      fail('client isolate error: $message');
    });
    print('test: waiting for client result...');
    final clientResult = await clientResultFuture;
    print('test: got client result $clientResult');
    clientResultPort.close();
    if (clientResult is Map && clientResult.containsKey('error')) {
      fail('client isolate error: ${clientResult['error']}');
    }
    expect(clientResult, equals('pong'));
    await clientErrorSubscription.cancel();
    clientErrorPort.close();

    await serverDone.future;
    await eventSubscription.cancel();
    eventPort.close();
    await errorSubscription.cancel();
    errorPort.close();
  }, timeout: const Timeout(Duration(seconds: 20)));
}

class _SecureServerArgs {
  const _SecureServerArgs({
    required this.certPath,
    required this.keyPath,
    required this.controlPort,
  });

  final String certPath;
  final String keyPath;
  final SendPort controlPort;
}

Future<void> _runSecureServer(_SecureServerArgs args) async {
  final server = await io.ServerSocket.bind('127.0.0.1', 0);
  print('secure server listening on ${server.port}');
  args.controlPort.send({'event': 'listening', 'port': server.port});
  try {
    await for (final socket in server) {
      try {
        print('server: accepted client');
        final secureServer = SecureSocketOpenSSLAsync.serverFromSocket(
          socket,
          certFile: args.certPath,
          keyFile: args.keyPath,
        );
        print('server: starting TLS handshake');
        await secureServer.ensureHandshakeCompleted();
        print('server: handshake complete, reading request');
        final request = await secureServer.recv(4);
        print('server: got ${String.fromCharCodes(request)}');
        if (String.fromCharCodes(request) != 'ping') {
          throw StateError('unexpected handshake payload');
        }
        print('server: sending pong');
        await secureServer.send(Uint8List.fromList('pong'.codeUnits));
        await secureServer.close();
        print('server: notify done');
        args.controlPort.send({'event': 'done'});
      } catch (error, stackTrace) {
        args.controlPort.send({
          'event': 'error',
          'message': error.toString(),
          'stackTrace': stackTrace.toString(),
        });
      }
      break;
    }
  } finally {
    await server.close();
  }
}

class _SecureClientArgs {
  const _SecureClientArgs({
    required this.port,
    required this.resultPort,
  });

  final int port;
  final SendPort resultPort;
}

Future<void> _runSecureClient(_SecureClientArgs args) async {
  try {
    final client = SecureSocketOpenSSLSync.connect(
      '127.0.0.1',
      args.port,
    );
    print('client isolate: connected to ${args.port}');
    try {
      await client.ensureHandshakeCompleted();
      print('client isolate: handshake complete');
      await client.send(Uint8List.fromList('ping'.codeUnits));
      print('client isolate: sent ping');
      final response = await client.recv(4);
      print('client isolate: got ${String.fromCharCodes(response)}');
      args.resultPort.send(String.fromCharCodes(response));
    } finally {
      await client.close();
    }
  } catch (error, stackTrace) {
    args.resultPort.send({
      'error': error.toString(),
      'stackTrace': stackTrace.toString(),
    });
  }
}
