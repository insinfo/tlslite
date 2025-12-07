// ignore_for_file: avoid_print
/// Integration tests for HttpTlsConnection accessing real HTTPS sites.
///
/// These tests require internet connectivity and verify that the TLS handshake
/// and HTTP communication work correctly with real-world servers like Google.

import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/integration/http_tls_connection.dart';
import 'package:tlslite/src/handshake_settings.dart';
import 'package:tlslite/src/tlsconnection.dart';
import 'package:tlslite/src/recordlayer.dart';
import 'package:tlslite/src/constants.dart';

void main() {
  group('HttpTlsConnection Real Integration Tests', () {
    test('connects to google.com and receives HTTP response', () async {
      final conn = HttpTlsConnection(
        'www.google.com',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 3),
        ),
      );

      try {
        await conn.connect();
        print('✓ TLS handshake completed with www.google.com');

        await conn.request('GET', '/', headers: {
          'User-Agent': 'TlsLite-Dart/1.0',
          'Accept': '*/*',
          'Connection': 'close',
        });
        print('✓ HTTP GET request sent');

        final response = await conn.getResponse();
        print('✓ HTTP response received');
        print('  Status: ${response.status} ${response.reason}');
        print('  Headers: ${response.headers.keys.join(", ")}');
        print('  Body length: ${response.body.length} bytes');

        expect(response.status, anyOf(equals(200), equals(301), equals(302)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('connects to cloudflare.com and receives HTTP response', () async {
      final conn = HttpTlsConnection(
        'www.cloudflare.com',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 3),
        ),
      );

      try {
        await conn.connect();
        print('✓ TLS handshake completed with www.cloudflare.com');

        await conn.request('GET', '/', headers: {
          'User-Agent': 'TlsLite-Dart/1.0',
          'Accept': '*/*',
          'Connection': 'close',
        });
        print('✓ HTTP GET request sent');

        final response = await conn.getResponse();
        print('✓ HTTP response received');
        print('  Status: ${response.status} ${response.reason}');

        expect(response.status,
            anyOf(equals(200), equals(301), equals(302), equals(403)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('connects to github.com API and receives JSON response', () async {
      final conn = HttpTlsConnection(
        'api.github.com',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 3),
        ),
      );

      try {
        await conn.connect();
        print('✓ TLS handshake completed with api.github.com');

        await conn.request('GET', '/zen', headers: {
          'User-Agent': 'TlsLite-Dart/1.0',
          'Accept': 'application/json',
          'Connection': 'close',
        });
        print('✓ HTTP GET request sent to /zen');

        final response = await conn.getResponse();
        print('✓ HTTP response received');
        print('  Status: ${response.status} ${response.reason}');

        if (response.status == 200 && response.body.isNotEmpty) {
          final bodyText = utf8.decode(response.body, allowMalformed: true);
          print('  Zen: $bodyText');
        }

        expect(response.status, equals(200));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('TLS 1.2 only connection to google.com', () async {
      final conn = HttpTlsConnection(
        'www.google.com',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 3), // TLS 1.2
          maxVersion: (3, 3), // TLS 1.2
        ),
      );

      try {
        await conn.connect();
        print('✓ TLS 1.2 handshake completed with www.google.com');

        await conn.request('GET', '/', headers: {
          'User-Agent': 'TlsLite-Dart/1.0 (TLS 1.2)',
          'Accept': '*/*',
          'Connection': 'close',
        });

        final response = await conn.getResponse();
        print('✓ HTTP response: ${response.status} ${response.reason}');

        expect(response.status, anyOf(equals(200), equals(301), equals(302)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('TLS 1.3 only connection to google.com', () async {
      final conn = HttpTlsConnection(
        'www.google.com',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 4), // TLS 1.3
          maxVersion: (3, 4), // TLS 1.3
        ),
      );

      try {
        await conn.connect();
        print('✓ TLS 1.3 handshake completed with www.google.com');

        await conn.request('GET', '/', headers: {
          'User-Agent': 'TlsLite-Dart/1.0 (TLS 1.3)',
          'Accept': '*/*',
          'Connection': 'close',
        });

        final response = await conn.getResponse();
        print('✓ HTTP response: ${response.status} ${response.reason}');

        expect(response.status, anyOf(equals(200), equals(301), equals(302)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));
  });

  group('Direct TlsConnection Integration Tests', () {
    test('raw TlsConnection handshake with google.com', () async {
      final socket = await Socket.connect('www.google.com', 443);
      final tls = TlsConnection(socket);

      try {
        await tls.handshakeClient(
          settings: HandshakeSettings(
            minVersion: (3, 3),
          ),
          serverName: 'www.google.com',
        );

        print('✓ Direct TLS handshake completed');
        print('  Negotiated version: ${tls.version}');
        print('  Cipher suite: 0x${tls.session.cipherSuite.toRadixString(16)}');

        // Send HTTP request
        final request = 'GET / HTTP/1.1\r\n'
            'Host: www.google.com\r\n'
            'User-Agent: TlsLite-Dart/1.0\r\n'
            'Connection: close\r\n'
            '\r\n';
        await tls.sendRecord(Message(
          ContentType.application_data,
          Uint8List.fromList(utf8.encode(request)),
        ));

        print('✓ HTTP request sent via direct TlsConnection');

        // Read response
        final (header, parser) = await tls.recvMessage();
        final data = parser.getFixBytes(parser.getRemainingLength());
        final responseStart = utf8.decode(data, allowMalformed: true);

        print('✓ Response received (first 200 chars):');
        print(
            '  ${responseStart.substring(0, responseStart.length > 200 ? 200 : responseStart.length)}...');

        expect(responseStart, contains('HTTP/1.1'));
      } finally {
        await socket.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('raw TlsConnection handshake with cloudflare.com', () async {
      final socket = await Socket.connect('www.cloudflare.com', 443);
      final tls = TlsConnection(socket);

      try {
        await tls.handshakeClient(
          settings: HandshakeSettings(minVersion: (3, 3)),
          serverName: 'www.cloudflare.com',
        );

        print('✓ Direct TLS handshake (cloudflare.com) completed');
        print('  Negotiated version: ${tls.version}');
        print('  Cipher suite: 0x${tls.session.cipherSuite.toRadixString(16)}');

        final request = 'GET / HTTP/1.1\r\n'
            'Host: www.cloudflare.com\r\n'
            'User-Agent: TlsLite-Dart/1.0\r\n'
            'Connection: close\r\n'
            '\r\n';
        await tls.sendRecord(Message(
          ContentType.application_data,
          Uint8List.fromList(utf8.encode(request)),
        ));

        print('✓ HTTP request sent via direct TlsConnection (cloudflare.com)');

        final (header, parser) = await tls.recvMessage();
        final data = parser.getFixBytes(parser.getRemainingLength());
        final responseStart = utf8.decode(data, allowMalformed: true);

        print('✓ Response received (cloudflare.com, first 200 chars):');
        print(
            '  ${responseStart.substring(0, responseStart.length > 200 ? 200 : responseStart.length)}...');

        expect(responseStart, contains('HTTP/1.'));
      } finally {
        await socket.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('raw TlsConnection handshake with api.github.com', () async {
      final socket = await Socket.connect('api.github.com', 443);
      final tls = TlsConnection(socket);

      try {
        await tls.handshakeClient(
          settings: HandshakeSettings(minVersion: (3, 3)),
          serverName: 'api.github.com',
        );

        print('✓ Direct TLS handshake (api.github.com) completed');
        print('  Negotiated version: ${tls.version}');
        print('  Cipher suite: 0x${tls.session.cipherSuite.toRadixString(16)}');

        final request = 'GET /zen HTTP/1.1\r\n'
            'Host: api.github.com\r\n'
            'User-Agent: TlsLite-Dart/1.0\r\n'
            'Accept: application/json\r\n'
            'Connection: close\r\n'
            '\r\n';
        await tls.sendRecord(Message(
          ContentType.application_data,
          Uint8List.fromList(utf8.encode(request)),
        ));

        print('✓ HTTP request sent via direct TlsConnection (api.github.com)');

        final (header, parser) = await tls.recvMessage();
        final data = parser.getFixBytes(parser.getRemainingLength());
        final responseStart = utf8.decode(data, allowMalformed: true);

        print('✓ Response received (api.github.com, first 200 chars):');
        print(
            '  ${responseStart.substring(0, responseStart.length > 200 ? 200 : responseStart.length)}...');

        expect(responseStart, contains('HTTP/1.'));
      } finally {
        await socket.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));
  });

  group('Rio das Ostras Government Site Tests', () {
    // This server uses RSA-PSS signature in TLS 1.2 ServerKeyExchange
    // which tests the "intrinsic" hash algorithm support (0x0804-0x0806)

    test('TLS 1.2 connection to www.riodasostras.rj.gov.br', () async {
      final conn = HttpTlsConnection(
        'www.riodasostras.rj.gov.br',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 3), // TLS 1.2
          maxVersion: (3, 3), // TLS 1.2 only
        ),
      );

      try {
        await conn.connect();
        print('✓ TLS 1.2 handshake completed with www.riodasostras.rj.gov.br');

        await conn.request('GET', '/', headers: {
          'Host': 'www.riodasostras.rj.gov.br',
          'User-Agent': 'TlsLite-Dart/1.0 (TLS 1.2)',
          'Accept': 'text/html,application/xhtml+xml',
          'Connection': 'close',
        });

        final response = await conn.getResponse();
        print('✓ HTTP response: ${response.status} ${response.reason}');

        // Accept 400 - the TLS handshake worked, HTTP layer may reject for other reasons
        expect(
            response.status,
            anyOf(equals(200), equals(301), equals(302), equals(400),
                equals(403)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('TLS 1.3 connection to www.riodasostras.rj.gov.br', () async {
      // This server does NOT support TLS 1.3 - expect protocol_version alert
      final conn = HttpTlsConnection(
        'www.riodasostras.rj.gov.br',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 4), // TLS 1.3
          maxVersion: (3, 4), // TLS 1.3 only
        ),
      );

      try {
        await expectLater(
          conn.connect(),
          throwsA(predicate((e) =>
              e.toString().contains('protocol_version') ||
              e.toString().contains('handshake_failure'))),
        );
        print('✓ Server correctly rejected TLS 1.3 (does not support it)');
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('Auto-negotiate TLS version with www.riodasostras.rj.gov.br',
        () async {
      final conn = HttpTlsConnection(
        'www.riodasostras.rj.gov.br',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 1), // TLS 1.0
          maxVersion: (3, 4), // TLS 1.3
        ),
      );

      try {
        await conn.connect();
        print(
            '✓ TLS handshake completed with www.riodasostras.rj.gov.br (auto-negotiate)');

        await conn.request('GET', '/', headers: {
          'Host': 'www.riodasostras.rj.gov.br',
          'User-Agent': 'TlsLite-Dart/1.0 (Auto TLS)',
          'Accept': 'text/html,application/xhtml+xml',
          'Connection': 'close',
        });

        final response = await conn.getResponse();
        print('✓ HTTP response: ${response.status} ${response.reason}');

        // Accept 400 - the TLS handshake worked, HTTP layer may reject for other reasons
        expect(
            response.status,
            anyOf(equals(200), equals(301), equals(302), equals(400),
                equals(403)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('Direct TlsConnection with www.riodasostras.rj.gov.br', () async {
      final socket = await Socket.connect('www.riodasostras.rj.gov.br', 443);
      final tls = TlsConnection(socket);

      try {
        await tls.handshakeClient(
          settings: HandshakeSettings(
            minVersion: (3, 3), // TLS 1.2 minimum
            maxVersion: (3, 4), // Allow TLS 1.3
          ),
          serverName: 'www.riodasostras.rj.gov.br',
        );

        print('✓ Direct TLS handshake (www.riodasostras.rj.gov.br) completed');
        print('  Negotiated version: ${tls.version}');
        print('  Cipher suite: 0x${tls.session.cipherSuite.toRadixString(16)}');

        final request = 'GET / HTTP/1.1\r\n'
            'Host: www.riodasostras.rj.gov.br\r\n'
            'User-Agent: TlsLite-Dart/1.0\r\n'
            'Accept: text/html\r\n'
            'Connection: close\r\n'
            '\r\n';
        await tls.sendRecord(Message(
          ContentType.application_data,
          Uint8List.fromList(utf8.encode(request)),
        ));

        print('✓ HTTP request sent via direct TlsConnection');

        final (header, parser) = await tls.recvMessage();
        final data = parser.getFixBytes(parser.getRemainingLength());
        final responseStart = utf8.decode(data, allowMalformed: true);

        print('✓ Response received (first 200 chars):');
        print(
            '  ${responseStart.substring(0, responseStart.length > 200 ? 200 : responseStart.length)}...');

        expect(responseStart, contains('HTTP/1.'));
      } finally {
        await socket.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));
  });

  group('BadSSL.com TLS Version Tests', () {
    // Tests using badssl.com's version-specific endpoints
    // See: https://badssl.com/

    test('TLS 1.0 only - tls-v1-0.badssl.com:1010', () async {
      final conn = HttpTlsConnection(
        'tls-v1-0.badssl.com',
        port: 1010,
        settings: HandshakeSettings(
          minVersion: (3, 1), // TLS 1.0
          maxVersion: (3, 1), // TLS 1.0 only
        ),
      );

      try {
        await conn.connect();
        print('✓ TLS 1.0 handshake completed with tls-v1-0.badssl.com:1010');

        await conn.request('GET', '/', headers: {
          'Host': 'tls-v1-0.badssl.com',
          'User-Agent': 'TlsLite-Dart/1.0 (TLS 1.0 test)',
          'Accept': 'text/html',
          'Connection': 'close',
        });

        final response = await conn.getResponse();
        print('✓ HTTP response: ${response.status} ${response.reason}');

        expect(response.status,
            anyOf(equals(200), equals(301), equals(302), equals(400)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('TLS 1.1 only – tls-v1-1.badssl.com:1011', () async {
      final conn = HttpTlsConnection(
        'tls-v1-1.badssl.com',
        port: 1011,
        settings: HandshakeSettings(
          minVersion: (3, 2), // TLS 1.1
          maxVersion: (3, 2), // TLS 1.1 only
        ),
      );

      try {
        await conn.connect();
        print('✓ TLS 1.1 handshake completed with tls-v1-1.badssl.com:1011');

        await conn.request('GET', '/', headers: {
          'Host': 'tls-v1-1.badssl.com',
          'User-Agent': 'TlsLite-Dart/1.0 (TLS 1.1 test)',
          'Accept': 'text/html',
          'Connection': 'close',
        });

        final response = await conn.getResponse();
        print('✓ HTTP response: ${response.status} ${response.reason}');

        expect(response.status,
            anyOf(equals(200), equals(301), equals(302), equals(400)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('TLS 1.2 only – tls-v1-2.badssl.com:1012', () async {
      final conn = HttpTlsConnection(
        'tls-v1-2.badssl.com',
        port: 1012,
        settings: HandshakeSettings(
          minVersion: (3, 3), // TLS 1.2
          maxVersion: (3, 3), // TLS 1.2 only
        ),
      );

      try {
        await conn.connect();
        print('✓ TLS 1.2 handshake completed with tls-v1-2.badssl.com:1012');

        await conn.request('GET', '/', headers: {
          'Host': 'tls-v1-2.badssl.com',
          'User-Agent': 'TlsLite-Dart/1.0 (TLS 1.2 test)',
          'Accept': 'text/html',
          'Connection': 'close',
        });

        final response = await conn.getResponse();
        print('✓ HTTP response: ${response.status} ${response.reason}');

        expect(response.status,
            anyOf(equals(200), equals(301), equals(302), equals(400)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('Reject TLS 1.0 server when client requires >= TLS 1.2', () async {
      // Negative test: client requires TLS 1.2+ but server only supports TLS 1.0
      final conn = HttpTlsConnection(
        'tls-v1-0.badssl.com',
        port: 1010,
        settings: HandshakeSettings(
          minVersion: (3, 3), // TLS 1.2 minimum
          maxVersion: (3, 4), // up to TLS 1.3
        ),
      );

      try {
        await expectLater(
          conn.connect(),
          throwsA(predicate((e) =>
              e.toString().contains('protocol_version') ||
              e.toString().contains('handshake_failure') ||
              e.toString().contains('alert'))),
        );
        print('✓ Correctly rejected TLS 1.0 server (client requires >= 1.2)');
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('Reject TLS 1.1 server when client requires >= TLS 1.2', () async {
      // Negative test: client requires TLS 1.2+ but server only supports TLS 1.1
      final conn = HttpTlsConnection(
        'tls-v1-1.badssl.com',
        port: 1011,
        settings: HandshakeSettings(
          minVersion: (3, 3), // TLS 1.2 minimum
          maxVersion: (3, 4), // up to TLS 1.3
        ),
      );

      try {
        await expectLater(
          conn.connect(),
          throwsA(predicate((e) =>
              e.toString().contains('protocol_version') ||
              e.toString().contains('handshake_failure') ||
              e.toString().contains('alert'))),
        );
        print('✓ Correctly rejected TLS 1.1 server (client requires >= 1.2)');
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));
  });

  group('BadSSL.com Legacy Configuration Tests', () {
    // Tests using badssl.com's legacy cipher/config endpoints
    // mozilla-old supports TLS 1.0-1.3 with old cipher suites

    test('mozilla-old.badssl.com – Old backward compatibility config',
        () async {
      final conn = HttpTlsConnection(
        'mozilla-old.badssl.com',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 1), // TLS 1.0
          maxVersion: (3, 4), // TLS 1.3
        ),
      );

      try {
        await conn.connect();
        print('✓ Handshake OK with mozilla-old.badssl.com (old config)');

        await conn.request('GET', '/', headers: {
          'Host': 'mozilla-old.badssl.com',
          'User-Agent': 'TlsLite-Dart/1.0 (Mozilla Old test)',
          'Accept': 'text/html',
          'Connection': 'close',
        });

        final response = await conn.getResponse();
        print('✓ HTTP response: ${response.status} ${response.reason}');

        expect(response.status,
            anyOf(equals(200), equals(301), equals(302), equals(400)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('cbc.badssl.com – CBC cipher suites', () async {
      final conn = HttpTlsConnection(
        'cbc.badssl.com',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 1), // TLS 1.0
          maxVersion: (3, 3), // TLS 1.2 (CBC not in 1.3)
        ),
      );

      try {
        await conn.connect();
        print('✓ Handshake OK with cbc.badssl.com (CBC ciphers)');

        await conn.request('GET', '/', headers: {
          'Host': 'cbc.badssl.com',
          'User-Agent': 'TlsLite-Dart/1.0 (CBC test)',
          'Accept': 'text/html',
          'Connection': 'close',
        });

        final response = await conn.getResponse();
        print('✓ HTTP response: ${response.status} ${response.reason}');

        expect(response.status,
            anyOf(equals(200), equals(301), equals(302), equals(400)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('sha256.badssl.com – SHA-256 certificates', () async {
      final conn = HttpTlsConnection(
        'sha256.badssl.com',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 3), // TLS 1.2
          maxVersion: (3, 4), // TLS 1.3
        ),
      );

      try {
        await conn.connect();
        print('✓ Handshake OK with sha256.badssl.com');

        await conn.request('GET', '/', headers: {
          'Host': 'sha256.badssl.com',
          'User-Agent': 'TlsLite-Dart/1.0 (SHA-256 test)',
          'Accept': 'text/html',
          'Connection': 'close',
        });

        final response = await conn.getResponse();
        print('✓ HTTP response: ${response.status} ${response.reason}');

        expect(response.status,
            anyOf(equals(200), equals(301), equals(302), equals(400)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('rsa2048.badssl.com – RSA 2048-bit key', () async {
      final conn = HttpTlsConnection(
        'rsa2048.badssl.com',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 3), // TLS 1.2
          maxVersion: (3, 4), // TLS 1.3
        ),
      );

      try {
        await conn.connect();
        print('✓ Handshake OK with rsa2048.badssl.com');

        await conn.request('GET', '/', headers: {
          'Host': 'rsa2048.badssl.com',
          'User-Agent': 'TlsLite-Dart/1.0 (RSA 2048 test)',
          'Accept': 'text/html',
          'Connection': 'close',
        });

        final response = await conn.getResponse();
        print('✓ HTTP response: ${response.status} ${response.reason}');

        expect(response.status,
            anyOf(equals(200), equals(301), equals(302), equals(400)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('ecc256.badssl.com – ECC P-256 key', () async {
      final conn = HttpTlsConnection(
        'ecc256.badssl.com',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 3), // TLS 1.2
          maxVersion: (3, 4), // TLS 1.3
        ),
      );

      try {
        await conn.connect();
        print('✓ Handshake OK with ecc256.badssl.com (ECDSA P-256)');

        await conn.request('GET', '/', headers: {
          'Host': 'ecc256.badssl.com',
          'User-Agent': 'TlsLite-Dart/1.0 (ECC P-256 test)',
          'Accept': 'text/html',
          'Connection': 'close',
        });

        final response = await conn.getResponse();
        print('✓ HTTP response: ${response.status} ${response.reason}');

        expect(response.status,
            anyOf(equals(200), equals(301), equals(302), equals(400)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));

    test('ecc384.badssl.com – ECC P-384 key', () async {
      final conn = HttpTlsConnection(
        'ecc384.badssl.com',
        port: 443,
        settings: HandshakeSettings(
          minVersion: (3, 3), // TLS 1.2
          maxVersion: (3, 4), // TLS 1.3
        ),
      );

      try {
        await conn.connect();
        print('✓ Handshake OK with ecc384.badssl.com (ECDSA P-384)');

        await conn.request('GET', '/', headers: {
          'Host': 'ecc384.badssl.com',
          'User-Agent': 'TlsLite-Dart/1.0 (ECC P-384 test)',
          'Accept': 'text/html',
          'Connection': 'close',
        });

        final response = await conn.getResponse();
        print('✓ HTTP response: ${response.status} ${response.reason}');

        expect(response.status,
            anyOf(equals(200), equals(301), equals(302), equals(400)));
      } finally {
        await conn.close();
      }
    }, timeout: const Timeout(Duration(seconds: 30)));
  });
}
