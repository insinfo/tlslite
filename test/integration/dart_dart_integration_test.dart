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
    final variants = <Map<String, dynamic>>[
      {
        'name': 'TLS 1.0 RSA + AES128-CBC',
        'minVer': (3, 1),
        'maxVer': (3, 1),
        'ciphers': const ['aes128'],
        'kx': const ['rsa'],
        'curves': const <String>[],
        'useEtm': false,
      },
      {
        'name': 'TLS 1.0 RSA + 3DES-CBC',
        'minVer': (3, 1),
        'maxVer': (3, 1),
        'ciphers': const ['3des'],
        'kx': const ['rsa'],
        'curves': const <String>[],
        'useEtm': false,
      },
      {
        'name': 'TLS 1.1 RSA + AES128-CBC',
        'minVer': (3, 2),
        'maxVer': (3, 2),
        'ciphers': const ['aes128'],
        'kx': const ['rsa'],
        'curves': const <String>[],
        'useEtm': false,
      },
      {
        'name': 'TLS 1.2 RSA + AES128-GCM',
        'minVer': (3, 3),
        'maxVer': (3, 3),
        'ciphers': const ['aes128gcm'],
        'kx': const ['rsa'],
        'curves': const <String>[],
      },
      {
        'name': 'TLS 1.2 ECDHE_RSA + AES128-GCM',
        'minVer': (3, 3),
        'maxVer': (3, 3),
        'ciphers': const ['aes128gcm'],
        'kx': const ['ecdhe_rsa'],
        'curves': const ['secp256r1', 'x25519'],
      },
      {
        'name': 'TLS 1.2 ECDHE_RSA + CHACHA20-POLY1305',
        'minVer': (3, 3),
        'maxVer': (3, 3),
        'ciphers': const ['chacha20-poly1305'],
        'kx': const ['ecdhe_rsa'],
        'curves': const ['secp256r1', 'x25519'],
      },
      {
        'name': 'TLS 1.3 ECDHE_RSA + CHACHA20-POLY1305',
        'minVer': (3, 4),
        'maxVer': (3, 4),
        'ciphers': const ['chacha20-poly1305'],
        'kx': const ['ecdhe_rsa'],
        'curves': const ['secp256r1', 'x25519'],
      },
      // Post-Quantum Hybrid Tests (ML-KEM + ECDH)
      {
        'name': 'TLS 1.3 X25519+ML-KEM-768 Hybrid + AES256-GCM',
        'minVer': (3, 4),
        'maxVer': (3, 4),
        'ciphers': const ['aes256gcm'],
        'kx': const ['ecdhe_rsa'],
        'curves': const ['x25519mlkem768', 'x25519'],
      },
      {
        'name': 'TLS 1.3 P-256+ML-KEM-768 Hybrid + AES256-GCM',
        'minVer': (3, 4),
        'maxVer': (3, 4),
        'ciphers': const ['aes256gcm'],
        'kx': const ['ecdhe_rsa'],
        'curves': const ['secp256r1mlkem768', 'secp256r1'],
      },
      {
        'name': 'TLS 1.3 P-384+ML-KEM-1024 Hybrid + AES256-GCM',
        'minVer': (3, 4),
        'maxVer': (3, 4),
        'ciphers': const ['aes256gcm'],
        'kx': const ['ecdhe_rsa'],
        'curves': const ['secp384r1mlkem1024', 'secp384r1'],
      },
      // Ed448 Signature Test
      {
        'name': 'TLS 1.3 Ed448 Signature + AES256-GCM',
        'minVer': (3, 4),
        'maxVer': (3, 4),
        'ciphers': const ['aes256gcm'],
        'kx': const ['ecdhe_ecdsa'],  // Ed448 uses ECDHE key exchange
        'curves': const ['x25519'],
        'certFile': 'test/certificates/serverEd448Cert.pem',
        'keyFile': 'test/certificates/serverEd448Key.pem',
        'sigSchemes': const ['Ed448'],
      },
    ];

    for (final variant in variants) {
      test('Handshake (${variant['name']})', () async {
        // Certificados - use custom se especificado, senão usa nginx padrão
        final certPath = (variant['certFile'] as String?) ?? 'scripts/nginx/server.crt';
        final keyPath = (variant['keyFile'] as String?) ?? 'scripts/nginx/server.key';
        final certPem = await File(certPath).readAsString();
        final keyPem = await File(keyPath).readAsString();
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
                minVersion: variant['minVer'] as (int, int),
                maxVersion: variant['maxVer'] as (int, int),
                alpnProtos: const ['dart-test'],
                keyExchangeNames:
                    (variant['kx'] as List<String>).cast<String>(),
                cipherNames:
                    (variant['ciphers'] as List<String>).cast<String>(),
                eccCurves: (variant['curves'] as List<String>).isNotEmpty
                    ? (variant['curves'] as List<String>).cast<String>()
                    : null,
                useEncryptThenMAC:
                  (variant['useEtm'] as bool?) ?? true,
                moreSigSchemes: variant['sigSchemes'] as List<String>?,
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
            minVersion: variant['minVer'] as (int, int),
            maxVersion: variant['maxVer'] as (int, int),
            alpnProtos: const ['dart-test'],
            keyExchangeNames:
                (variant['kx'] as List<String>).cast<String>(),
            cipherNames:
                (variant['ciphers'] as List<String>).cast<String>(),
            eccCurves: (variant['curves'] as List<String>).isNotEmpty
                ? (variant['curves'] as List<String>).cast<String>()
                : null,
            useEncryptThenMAC: (variant['useEtm'] as bool?) ?? true,
            moreSigSchemes: variant['sigSchemes'] as List<String>?,
          ),
          serverName: 'localhost',
          alpn: const ['dart-test'],
        );

        await tlsClient.write(Uint8List.fromList(utf8.encode(message)));
        final echoed = await tlsClient.read();

        expect(utf8.decode(echoed), equals(message));
        expect(await serverDone.future, equals(message));

        await clientSocket.close();
      },
          timeout: const Timeout(Duration(seconds: 20)),
          skip: variant['skip'] as String?);
    }
  });
}
