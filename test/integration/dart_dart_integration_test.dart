// ignore_for_file: avoid_print
/// Integração Dart x Dart usando TLSConnection dos dois lados.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/handshake_settings.dart';
import 'package:tlslite/src/tlsconnection.dart';
import 'package:tlslite/src/utils/keyfactory.dart';
import 'package:tlslite/src/x509certchain.dart';

void main() {
  group('Dart-Dart TLS Integration', () {
    final variants = [
      (
        name: 'RSA + AES128-GCM',
        ciphers: const ['aes128gcm'],
        kx: const ['rsa'],
        curves: const <String>[],
      ),
      (
        name: 'ECDHE_RSA + AES128-GCM',
        ciphers: const ['aes128gcm'],
        kx: const ['ecdhe_rsa'],
        curves: const ['secp256r1', 'x25519'],
      ),
      (
        name: 'ECDHE_RSA + CHACHA20-POLY1305',
        ciphers: const ['chacha20-poly1305'],
        kx: const ['ecdhe_rsa'],
        curves: const ['secp256r1', 'x25519'],
      ),
    ];

    for (final variant in variants) {
      test('TLS 1.2 handshake (${variant.name})', () async {
        // Certificados do nginx local (já presentes no repo).
        final certPem = await File('scripts/nginx/server.crt').readAsString();
        final keyPem = await File('scripts/nginx/server.key').readAsString();
        final certChain = X509CertChain()..parsePemList(certPem);
        final privateKey = parsePrivateKey(keyPem);

        final serverSocket =
            await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);

        final serverDone = Completer<String>();

        serverSocket.listen((socket) async {
          final tlsServer = TlsConnection(socket);
          try {
            await tlsServer.handshakeServer(
              settings: HandshakeSettings(
                minVersion: (3, 3),
                maxVersion: (3, 3),
                alpnProtos: const ['dart-test'],
                keyExchangeNames: variant.kx,
                cipherNames: variant.ciphers,
                eccCurves: variant.curves.isNotEmpty ? variant.curves : null,
              ),
              certChain: certChain,
              privateKey: privateKey,
              alpn: const ['dart-test'],
            );

            final data = await tlsServer.read();
            await tlsServer.write(data); // eco simples
            serverDone.complete(utf8.decode(data));
          } catch (e, st) {
            if (!serverDone.isCompleted) {
              serverDone.completeError(e, st);
            }
          } finally {
            await socket.close();
            await serverSocket.close();
          }
        });

        final clientSocket = await Socket.connect(
          InternetAddress.loopbackIPv4,
          serverSocket.port,
        );
        final tlsClient = TlsConnection(clientSocket);

        final message = 'ping from dart';

        await tlsClient.handshakeClient(
          settings: HandshakeSettings(
            minVersion: (3, 3),
            maxVersion: (3, 3),
            alpnProtos: const ['dart-test'],
            keyExchangeNames: variant.kx,
            cipherNames: variant.ciphers,
            eccCurves: variant.curves.isNotEmpty ? variant.curves : null,
          ),
          serverName: 'localhost',
          alpn: const ['dart-test'],
        );

        await tlsClient.write(Uint8List.fromList(utf8.encode(message)));
        final echoed = await tlsClient.read();

        expect(utf8.decode(echoed), equals(message));
        expect(await serverDone.future, equals(message));

        await clientSocket.close();
      }, timeout: const Timeout(Duration(seconds: 20)));
    }
  });
}
