import 'dart:async';
import 'dart:io' as io;
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/net/secure_socket_openssl_async.dart';

void main() {
  late String certPath;
  late String keyPath;

  setUpAll(() {
    certPath = io.File('test/certificates/serverX509Cert.pem').absolute.path;
    keyPath = io.File('test/certificates/serverX509Key.pem').absolute.path;
  });

  test('SecureSocketOpenSSLAsync completes handshake and echoes data', () async {
    final server = await io.ServerSocket.bind('127.0.0.1', 0);
    final serverCompletion = Completer<void>();

    final subscription = server.listen(
      (io.Socket socket) async {
        try {
          final secureServer = SecureSocketOpenSSLAsync.serverFromSocket(
            socket,
            certFile: certPath,
            keyFile: keyPath,
          );
          await secureServer.ensureHandshakeCompleted();
          final request = await secureServer.recv(4);
          expect(String.fromCharCodes(request), equals('ping'));
          await secureServer.send(Uint8List.fromList('pong'.codeUnits));
          await secureServer.close();
          if (!serverCompletion.isCompleted) {
            serverCompletion.complete();
          }
        } catch (error, stackTrace) {
          if (!serverCompletion.isCompleted) {
            serverCompletion.completeError(error, stackTrace);
          }
        }
      },
      onError: (Object error, StackTrace stackTrace) {
        if (!serverCompletion.isCompleted) {
          serverCompletion.completeError(error, stackTrace);
        }
      },
      cancelOnError: true,
    );

    final client = await SecureSocketOpenSSLAsync.connect(
      '127.0.0.1',
      server.port,
    );
    addTearDown(() => client.close());
    await client.ensureHandshakeCompleted();
    await client.send(Uint8List.fromList('ping'.codeUnits));
    final response = await client.recv(4);
    expect(String.fromCharCodes(response), equals('pong'));
    await client.close();

    await serverCompletion.future;
    await subscription.cancel();
    await server.close();
  }, timeout: const Timeout(Duration(seconds: 20)));
}
