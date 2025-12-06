/// Integration tests: Dart TLS client vs OpenSSL s_server
///
/// These tests start an OpenSSL s_server and connect to it with the Dart TLS client
/// to test real TLS 1.2 handshakes and data exchange.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:tlslite/src/tlsconnection.dart';
import 'package:tlslite/src/handshake_settings.dart';

/// OpenSSL server wrapper
class OpenSSLServer {
  Process? _process;
  final int _port;
  final String _cipher;
  final bool _verbose;
  final String _protocolFlag;
  final String? _tls13Cipher;
  final List<String> _stdout = [];
  final List<String> _stderr = [];
  bool _ready = false;
  String? _keyFile;
  String? _certFile;
  String? _keyLogFile;
  Directory? _tempDir;

  OpenSSLServer({
    required int port,
    required String cipher,
    bool verbose = false,
    String protocolFlag = '-tls1_2',
    String? tls13Cipher,
  })
      : _port = port,
        _cipher = cipher,
        _verbose = verbose,
        _protocolFlag = protocolFlag,
        _tls13Cipher = tls13Cipher;

  int get port => _port;
  List<String> get stdout => _stdout;
  List<String> get stderr => _stderr;
  String? get keyLogFile => _keyLogFile;

  Future<void> start() async {
    final processEnv = _buildOpenSslEnv();

    // Generate test certificate on the fly
    _tempDir = await Directory.systemTemp.createTemp('tlstest_');
    _keyFile = '${_tempDir!.path}/server.key';
    _certFile = '${_tempDir!.path}/server.crt';
    _keyLogFile = '${_tempDir!.path}/sslkeylog.log';

    // Generate RSA key and self-signed certificate
    final genKeyResult = await Process.run('openssl', [
      'req',
      '-x509',
      '-newkey', 'rsa:2048',
      '-keyout', _keyFile!,
      '-out', _certFile!,
      '-days', '1',
      '-nodes',
      '-subj', '/CN=localhost',
    ], environment: processEnv);
    
    if (genKeyResult.exitCode != 0) {
      throw Exception('Failed to generate test certificate: ${genKeyResult.stderr}');
    }

    // Start OpenSSL s_server
    final args = [
      's_server',
      '-accept', '$_port',
      '-key', _keyFile!,
      '-cert', _certFile!,
      _protocolFlag,
      '-cipher', _cipher,
      '-no_dhe',  // Disable DHE to force ECDHE
      '-keylogfile',
      _keyLogFile!,
    ];

    final tls13Cipher = _tls13Cipher;
    if (tls13Cipher != null && tls13Cipher.isNotEmpty) {
      args.add('-ciphersuites');
      args.add(tls13Cipher);
    }

    if (_verbose) {
      args.add('-debug');
    }

    _process = await Process.start('openssl', args, environment: processEnv);

    // Capture stdout
    _process!.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      _stdout.add(line);
      if (_verbose) print('[OpenSSL OUT] $line');
      if (line.contains('ACCEPT')) {
        _ready = true;
      }
    });

    // Capture stderr
    _process!.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) {
      _stderr.add(line);
      if (_verbose) print('[OpenSSL ERR] $line');
      // OpenSSL prints "Using default temp DH parameters" and other info to stderr
      if (line.contains('ACCEPT') || line.contains('Using')) {
        _ready = true;
      }
    });

    // Wait for server to be ready
    final startTime = DateTime.now();
    while (!_ready) {
      await Future.delayed(const Duration(milliseconds: 100));
      if (DateTime.now().difference(startTime) > const Duration(seconds: 10)) {
        throw Exception('OpenSSL server did not start in time');
      }
    }
    
    // Extra delay for server to fully bind
    await Future.delayed(const Duration(milliseconds: 300));
  }

  Future<void> stop() async {
    _process?.kill();
    await _process?.exitCode;
    
    // Cleanup temp files
    try {
      if (_tempDir != null) {
        await _tempDir!.delete(recursive: true);
      }
    } catch (_) {}
  }
}

Map<String, String> _buildOpenSslEnv() {
  final env = Map<String, String>.from(Platform.environment);
  env.remove('OPENSSL_CONF');
  env.remove('OPENSSL_MODULES');
  return env;
}

class _OpenSslScenario {
  const _OpenSslScenario({
    required this.name,
    required this.cipher,
    required this.settingsBuilder,
    this.protocolFlag = '-tls1_2',
    this.port,
    this.verbose = false,
    this.exerciseDataPath = false,
    this.testMessage = 'hello from dart',
    this.tls13Cipher,
  });

  final String name;
  final String cipher;
  final HandshakeSettings Function() settingsBuilder;
  final String protocolFlag;
  final int? port;
  final bool verbose;
  final bool exerciseDataPath;
  final String testMessage;
  final String? tls13Cipher;
}

Future<void> _printServerDiagnostics(OpenSSLServer server) async {
  print('\n=== OpenSSL Server Output ===');
  for (final line in server.stdout) {
    print(line);
  }
  print('\n=== OpenSSL Server Errors ===');
  for (final line in server.stderr) {
    print(line);
  }

  final keyLogPath = server.keyLogFile;
  if (keyLogPath != null) {
    final keyLog = File(keyLogPath);
    if (await keyLog.exists()) {
      print('\n=== OpenSSL KeyLog ===');
      print(await keyLog.readAsString());
    }
  }
}

void main() {
  group('Dart-OpenSSL TLS Integration', () {
    final scenarios = <_OpenSslScenario>[
      _OpenSslScenario(
        name: 'TLS 1.2 ECDHE-RSA + CHACHA20-POLY1305',
        cipher: 'ECDHE-RSA-CHACHA20-POLY1305',
        protocolFlag: '-tls1_2',
        port: 14433,
        verbose: true,
        exerciseDataPath: true,
        testMessage: 'Hello from Dart!',
        settingsBuilder: () => HandshakeSettings(
          minVersion: (3, 3),
          maxVersion: (3, 3),
          cipherNames: const ['chacha20-poly1305'],
          keyExchangeNames: const ['ecdhe_rsa'],
          eccCurves: const ['secp256r1', 'x25519'],
        ),
      ),
      _OpenSslScenario(
        name: 'TLS 1.2 ECDHE-RSA + AES128-GCM',
        cipher: 'ECDHE-RSA-AES128-GCM-SHA256',
        protocolFlag: '-tls1_2',
        port: 14434,
        settingsBuilder: () => HandshakeSettings(
          minVersion: (3, 3),
          maxVersion: (3, 3),
          cipherNames: const ['aes128gcm'],
          keyExchangeNames: const ['ecdhe_rsa'],
          eccCurves: const ['secp256r1', 'x25519'],
        ),
      ),
      _OpenSslScenario(
        name: 'TLS 1.2 ECDHE-RSA + AES256-GCM',
        cipher: 'ECDHE-RSA-AES256-GCM-SHA384',
        protocolFlag: '-tls1_2',
        port: 14439,
        settingsBuilder: () => HandshakeSettings(
          minVersion: (3, 3),
          maxVersion: (3, 3),
          cipherNames: const ['aes256gcm'],
          keyExchangeNames: const ['ecdhe_rsa'],
          eccCurves: const ['secp256r1', 'x25519'],
        ),
      ),
      _OpenSslScenario(
        name: 'TLS 1.2 RSA + AES256-CBC',
        cipher: 'AES256-SHA',
        protocolFlag: '-tls1_2',
        port: 14440,
        exerciseDataPath: true,
        testMessage: 'hello tls1.2 aes256',
        settingsBuilder: () => HandshakeSettings(
          minVersion: (3, 3),
          maxVersion: (3, 3),
          cipherNames: const ['aes256'],
          keyExchangeNames: const ['rsa'],
          useEncryptThenMAC: false,
        ),
      ),
      _OpenSslScenario(
        name: 'TLS 1.3 ECDHE-RSA + AES128-GCM',
        cipher: 'ECDHE-RSA-AES128-GCM-SHA256',
        protocolFlag: '-tls1_3',
        port: 14444,
        exerciseDataPath: true,
        testMessage: 'hello tls1.3 aes128gcm',
        tls13Cipher: 'TLS_AES_128_GCM_SHA256',
        settingsBuilder: () => HandshakeSettings(
          minVersion: (3, 4),
          maxVersion: (3, 4),
          cipherNames: const ['aes128gcm'],
          keyExchangeNames: const ['ecdhe_rsa'],
          eccCurves: const ['secp256r1', 'x25519'],
        ),
      ),
      _OpenSslScenario(
        name: 'TLS 1.3 ECDHE-RSA + CHACHA20-POLY1305',
        cipher: 'ECDHE-RSA-CHACHA20-POLY1305',
        protocolFlag: '-tls1_3',
        port: 14445,
        exerciseDataPath: true,
        testMessage: 'hello tls1.3 chacha',
        tls13Cipher: 'TLS_CHACHA20_POLY1305_SHA256',
        settingsBuilder: () => HandshakeSettings(
          minVersion: (3, 4),
          maxVersion: (3, 4),
          cipherNames: const ['chacha20-poly1305'],
          keyExchangeNames: const ['ecdhe_rsa'],
          eccCurves: const ['secp256r1', 'x25519'],
        ),
      ),
      _OpenSslScenario(
        name: 'TLS 1.2 ECDHE-RSA + AES128-CBC',
        cipher: 'ECDHE-RSA-AES128-SHA',
        protocolFlag: '-tls1_2',
        port: 14436,
        exerciseDataPath: true,
        testMessage: 'hello tls1.2 ecdhe aes128',
        settingsBuilder: () => HandshakeSettings(
          minVersion: (3, 3),
          maxVersion: (3, 3),
          cipherNames: const ['aes128'],
          keyExchangeNames: const ['ecdhe_rsa'],
          eccCurves: const ['secp256r1', 'x25519'],
          useEncryptThenMAC: false,
        ),
      ),
      _OpenSslScenario(
        name: 'TLS 1.1 RSA + AES128-CBC',
        cipher: 'AES128-SHA',
        protocolFlag: '-tls1_1',
        port: 14437,
        exerciseDataPath: true,
        testMessage: 'hello tls1.1',
        settingsBuilder: () => HandshakeSettings(
          minVersion: (3, 2),
          maxVersion: (3, 2),
          cipherNames: const ['aes128'],
          keyExchangeNames: const ['rsa'],
          useEncryptThenMAC: false,
        ),
      ),
      _OpenSslScenario(
        name: 'TLS 1.1 RSA + AES256-CBC',
        cipher: 'AES256-SHA',
        protocolFlag: '-tls1_1',
        port: 14441,
        exerciseDataPath: true,
        testMessage: 'hello tls1.1 aes256',
        settingsBuilder: () => HandshakeSettings(
          minVersion: (3, 2),
          maxVersion: (3, 2),
          cipherNames: const ['aes256'],
          keyExchangeNames: const ['rsa'],
          useEncryptThenMAC: false,
        ),
      ),
      _OpenSslScenario(
        name: 'TLS 1.0 RSA + AES128-CBC',
        cipher: 'AES128-SHA',
        protocolFlag: '-tls1',
        port: 14438,
        exerciseDataPath: true,
        testMessage: 'hello tls1.0',
        settingsBuilder: () => HandshakeSettings(
          minVersion: (3, 1),
          maxVersion: (3, 1),
          cipherNames: const ['aes128'],
          keyExchangeNames: const ['rsa'],
          useEncryptThenMAC: false,
        ),
      ),
      _OpenSslScenario(
        name: 'TLS 1.0 RSA + AES256-CBC',
        cipher: 'AES256-SHA',
        protocolFlag: '-tls1',
        port: 14443,
        exerciseDataPath: true,
        testMessage: 'hello tls1.0 aes256',
        settingsBuilder: () => HandshakeSettings(
          minVersion: (3, 1),
          maxVersion: (3, 1),
          cipherNames: const ['aes256'],
          keyExchangeNames: const ['rsa'],
          useEncryptThenMAC: false,
        ),
      ),
    ];

    for (var idx = 0; idx < scenarios.length; idx++) {
      final scenario = scenarios[idx];
      final assignedPort = scenario.port ?? (14430 + idx);
      test(scenario.name, () async {
        final server = OpenSSLServer(
          port: assignedPort,
          cipher: scenario.cipher,
          protocolFlag: scenario.protocolFlag,
          verbose: scenario.verbose,
          tls13Cipher: scenario.tls13Cipher,
        );

        Socket? socket;
        try {
          try {
            await server.start();
          } catch (e) {
            print('Failed to start OpenSSL for ${scenario.name}: $e');
            await _printServerDiagnostics(server);
            rethrow;
          }
          socket = await Socket.connect('127.0.0.1', server.port);

          final tlsConn = TlsConnection(socket);
          final settings = scenario.settingsBuilder();

          try {
            await tlsConn.handshakeClient(settings: settings);

            if (scenario.exerciseDataPath) {
              tlsConn.write(utf8.encode(scenario.testMessage));
              await tlsConn.flush();
              await Future.delayed(const Duration(milliseconds: 300));
            }

            expect(true, isTrue,
                reason: 'Handshake completed: ${scenario.name}');
          } catch (e) {
            print('TLS handshake FAILED (${scenario.name}): $e');
            await _printServerDiagnostics(server);
            rethrow;
          }
        } finally {
          socket?.destroy();
          await server.stop();
        }
      }, timeout: const Timeout(Duration(seconds: 60)));
    }

    test('Debug: Detailed handshake with packet capture', () async {
      final server = OpenSSLServer(
        port: 14435,
        cipher: 'ECDHE-RSA-CHACHA20-POLY1305',
        verbose: true,
      );

      Socket? socket;
      try {
        print('Starting OpenSSL server...');
        await server.start();
        print('OpenSSL server started on port ${server.port}');

        // Connect with Dart TLS client
        print('Connecting Dart TLS client...');
        socket = await Socket.connect('127.0.0.1', server.port);
        print('TCP connection established');

        // Create TLS connection
        final settings = HandshakeSettings(
          minVersion: (3, 3),  // TLS 1.2
          maxVersion: (3, 3),  // TLS 1.2
          cipherNames: ['chacha20-poly1305'],
        );
        
        final tlsConn = TlsConnection(socket);

        print('\n=== Starting TLS handshake ===');
        print('Settings:');
        print('  minVersion: ${settings.minVersion}');
        print('  maxVersion: ${settings.maxVersion}');
        print('  cipherNames: ${settings.cipherNames}');

        try {
          await tlsConn.handshakeClient(settings: settings);
          
          print('\n=== Handshake SUCCESSFUL ===');
          print('Negotiated cipher: ${tlsConn.session.cipherSuite}');
          print('Negotiated version: ${tlsConn.version}');
          
          // Send and receive data
          final testMessage = 'Test message from Dart client';
          print('\nSending: $testMessage');
          tlsConn.write(utf8.encode(testMessage));
          await tlsConn.flush();
          
          // Wait a bit
          await Future.delayed(const Duration(milliseconds: 500));
          
          expect(true, isTrue);
        } catch (e, stack) {
          print('\n=== Handshake FAILED ===');
          print('Error: $e');
          print('Stack: $stack');
          
          // Print all server output
          print('\n=== OpenSSL Server Stdout ===');
          for (final line in server.stdout) {
            print('  $line');
          }
          print('\n=== OpenSSL Server Stderr ===');
          for (final line in server.stderr) {
            print('  $line');
          }
          if (server.keyLogFile != null) {
            final keyLog = File(server.keyLogFile!);
            if (await keyLog.exists()) {
              print('\n=== OpenSSL KeyLog ===');
              print(await keyLog.readAsString());
            }
          }
          
          rethrow;
        }
      } finally {
        socket?.destroy();
        await server.stop();
      }
    });
  });
  
  group('Record Layer Encryption Test', () {
    test('Send encrypted data after handshake', () async {
      final server = OpenSSLServer(
        port: 14436,
        cipher: 'ECDHE-RSA-CHACHA20-POLY1305',
        verbose: true,
      );

      Socket? socket;
      try {
        await server.start();
        socket = await Socket.connect('127.0.0.1', server.port);
        
        final settings = HandshakeSettings(
          minVersion: (3, 3),  // TLS 1.2
          maxVersion: (3, 3),  // TLS 1.2
          cipherNames: ['chacha20-poly1305'],
        );
        
        final tlsConn = TlsConnection(socket);

        try {
          await tlsConn.handshakeClient(settings: settings);
          print('Handshake completed!');
          
          // Send multiple messages to test sequence number increment
          for (var i = 0; i < 3; i++) {
            final msg = 'Message $i from Dart';
            print('Sending: $msg');
            tlsConn.write(utf8.encode(msg + '\n'));
            await tlsConn.flush();
            await Future.delayed(const Duration(milliseconds: 100));
          }
          
          print('All messages sent successfully!');
          
          // If we get here without bad_record_mac, the encryption is working
          expect(true, isTrue);
        } catch (e) {
          print('Error during data exchange: $e');
          
          // Check if it's bad_record_mac
          if (e.toString().contains('bad_record_mac') || 
              e.toString().contains('TLSBadRecordMAC')) {
            print('\n*** FOUND THE BUG: bad_record_mac error ***');
            print('This means record layer encryption/decryption is failing.');
          }
          if (server.keyLogFile != null) {
            final keyLog = File(server.keyLogFile!);
            if (await keyLog.exists()) {
              print('\n=== OpenSSL KeyLog ===');
              print(await keyLog.readAsString());
            }
          }
          
          rethrow;
        }
      } finally {
        socket?.destroy();
        await server.stop();
      }
    });
  });
}
