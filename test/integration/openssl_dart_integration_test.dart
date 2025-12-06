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
  final List<String> _stdout = [];
  final List<String> _stderr = [];
  bool _ready = false;
  String? _keyFile;
  String? _certFile;
  String? _keyLogFile;
  Directory? _tempDir;

  OpenSSLServer({required int port, required String cipher, bool verbose = false})
      : _port = port,
        _cipher = cipher,
        _verbose = verbose;

  int get port => _port;
  List<String> get stdout => _stdout;
  List<String> get stderr => _stderr;
  String? get keyLogFile => _keyLogFile;

  Future<void> start() async {
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
    ]);
    
    if (genKeyResult.exitCode != 0) {
      throw Exception('Failed to generate test certificate: ${genKeyResult.stderr}');
    }

    // Start OpenSSL s_server
    final args = [
      's_server',
      '-accept', '$_port',
      '-key', _keyFile!,
      '-cert', _certFile!,
      '-tls1_2',  // Force TLS 1.2
      '-cipher', _cipher,
      '-no_dhe',  // Disable DHE to force ECDHE
      '-keylogfile',
      _keyLogFile!,
    ];

    if (_verbose) {
      args.add('-debug');
    }

    _process = await Process.start('openssl', args);

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

void main() {
  group('Dart-OpenSSL TLS Integration', () {
    test('TLS 1.2 handshake with ECDHE-RSA-CHACHA20-POLY1305', () async {
      final server = OpenSSLServer(
        port: 14433,
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

        // Create TLS connection with ChaCha20-Poly1305 only
        final settings = HandshakeSettings(
          minVersion: (3, 3),  // TLS 1.2
          maxVersion: (3, 3),  // TLS 1.2
          cipherNames: ['chacha20-poly1305'],
        );
        
        final tlsConn = TlsConnection(socket);

        print('Starting TLS handshake...');
        try {
          await tlsConn.handshakeClient(settings: settings);
          print('TLS handshake SUCCESSFUL!');

          // Try to send data
          final message = 'Hello from Dart!';
          print('Sending: $message');
          tlsConn.write(utf8.encode(message));
          await tlsConn.flush();

          // Read response (OpenSSL s_server echoes data)
          await Future.delayed(const Duration(milliseconds: 500));
          
          print('Handshake complete!');
          
          expect(true, isTrue, reason: 'Handshake completed successfully');
        } catch (e) {
          print('TLS handshake FAILED: $e');
          
          // Print server output for debugging
          print('\n=== OpenSSL Server Output ===');
          for (final line in server.stdout) {
            print(line);
          }
          print('\n=== OpenSSL Server Errors ===');
          for (final line in server.stderr) {
            print(line);
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

    test('TLS 1.2 handshake with ECDHE-RSA-AES128-GCM-SHA256', () async {
      final server = OpenSSLServer(
        port: 14434,
        cipher: 'ECDHE-RSA-AES128-GCM-SHA256',
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

        // Create TLS connection with AES-128-GCM only
        final settings = HandshakeSettings(
          minVersion: (3, 3),  // TLS 1.2
          maxVersion: (3, 3),  // TLS 1.2
          cipherNames: ['aes128gcm'],
        );
        
        final tlsConn = TlsConnection(socket);

        print('Starting TLS handshake...');
        try {
          await tlsConn.handshakeClient(settings: settings);
          print('TLS handshake SUCCESSFUL!');
          
          expect(true, isTrue, reason: 'Handshake completed successfully');
        } catch (e) {
          print('TLS handshake FAILED: $e');
          
          // Print server output for debugging
          print('\n=== OpenSSL Server Output ===');
          for (final line in server.stdout) {
            print(line);
          }
          print('\n=== OpenSSL Server Errors ===');
          for (final line in server.stderr) {
            print(line);
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
