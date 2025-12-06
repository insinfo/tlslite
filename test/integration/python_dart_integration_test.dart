// Integration test: Dart TLS client connecting to Python tlslite-ng server
// This test helps identify where the TLS handshake is failing

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/tlsconnection.dart';
import 'package:tlslite/src/handshake_settings.dart';
import 'package:tlslite/src/errors.dart';

const pythonServerScript = 'scripts/python_tls_server.py';

/// Helper class to manage Python TLS server process
class PythonTlsServer {
  Process? _process;
  final int port;
  final String cipher;
  final StringBuffer _stdout = StringBuffer();
  final StringBuffer _stderr = StringBuffer();
  
  PythonTlsServer({this.port = 4433, this.cipher = 'chacha20'});
  
  Future<void> start() async {
    final pythonPath = 'C:/MyDartProjects/tlslite/tlslite-ng';
    
    _process = await Process.start(
      'python',
      [pythonServerScript, '--port', port.toString(), '--cipher', cipher],
      environment: {'PYTHONPATH': pythonPath},
      workingDirectory: 'C:/MyDartProjects/tlslite',
    );
    
    // Capture output
    _process!.stdout.transform(utf8.decoder).listen((data) {
      _stdout.write(data);
      print('[Python Server] $data');
    });
    
    _process!.stderr.transform(utf8.decoder).listen((data) {
      _stderr.write(data);
      print('[Python Server ERROR] $data');
    });
    
    // Wait for server to be ready
    await Future.delayed(const Duration(seconds: 2));
  }
  
  Future<void> stop() async {
    if (_process != null) {
      _process!.kill();
      await _process!.exitCode.timeout(
        const Duration(seconds: 5),
        onTimeout: () {
          _process!.kill(ProcessSignal.sigkill);
          return -1;
        },
      );
    }
  }
  
  String get stdout => _stdout.toString();
  String get stderr => _stderr.toString();
}

void main() {
  group('Python-Dart TLS Integration', () {
    late PythonTlsServer server;
    
    setUp(() async {
      // Server will be started per test
    });
    
    tearDown(() async {
      await server.stop();
    });
    
    test('TLS 1.2 handshake with ChaCha20-Poly1305 to Python server', () async {
      server = PythonTlsServer(port: 4433, cipher: 'chacha20');
      await server.start();
      
      Socket? socket;
      TlsConnection? tls;
      
      try {
        print('Connecting to Python TLS server...');
        socket = await Socket.connect('127.0.0.1', 4433);
        print('TCP connection established');
        
        tls = TlsConnection(socket);
        
        // Configure handshake settings
        final settings = HandshakeSettings(
          minVersion: (3, 3),
          maxVersion: (3, 3),
          cipherNames: ['chacha20-poly1305'],
        );
        
        print('Starting TLS handshake...');
        print('  Min version: ${settings.minVersion}');
        print('  Max version: ${settings.maxVersion}');
        print('  Cipher names: ${settings.cipherNames}');
        
        try {
          await tls.handshakeClient(settings: settings);
          
          print('Handshake completed successfully!');
          print('  Negotiated version: ${tls.version}');
          print('  Session ID: ${tls.session.sessionID}');
          
          // Send test data
          final testMessage = 'Hello from Dart!';
          print('Sending: $testMessage');
          await tls.write(Uint8List.fromList(utf8.encode(testMessage)));
          
          // Read echo response
          final response = await tls.read().timeout(
            const Duration(seconds: 5),
            onTimeout: () => Uint8List(0),
          );
          
          if (response.isNotEmpty) {
            print('Received echo: ${utf8.decode(response)}');
            expect(utf8.decode(response), equals(testMessage));
          }
          
        } on TLSError catch (e) {
          print('TLS Handshake failed: $e');
          print('Error: $e');
          
          // Print detailed server output
          await Future.delayed(const Duration(seconds: 1));
          print('\n=== Python Server Output ===');
          print(server.stdout);
          if (server.stderr.isNotEmpty) {
            print('\n=== Python Server Errors ===');
            print(server.stderr);
          }
          
          rethrow;
        }
        
      } finally {
        // TlsConnection doesn't have shutdown, so just destroy socket
        socket?.destroy();
      }
    }, timeout: Timeout(Duration(seconds: 30)));

    test('TLS 1.2 handshake with AES-128-GCM to Python server', () async {
      server = PythonTlsServer(port: 4434, cipher: 'aes128gcm');
      await server.start();
      
      Socket? socket;
      TlsConnection? tls;
      
      try {
        print('Connecting to Python TLS server...');
        socket = await Socket.connect('127.0.0.1', 4434);
        print('TCP connection established');
        
        tls = TlsConnection(socket);
        
        final settings = HandshakeSettings(
          minVersion: (3, 3),
          maxVersion: (3, 3),
          cipherNames: ['aes128gcm'],
        );
        
        print('Starting TLS handshake with AES-128-GCM...');
        
        try {
          await tls.handshakeClient(settings: settings);
          
          print('Handshake completed successfully!');
          
          final testMessage = 'Hello with AES-GCM!';
          print('Sending: $testMessage');
          await tls.write(Uint8List.fromList(utf8.encode(testMessage)));
          
          final response = await tls.read().timeout(
            const Duration(seconds: 5),
            onTimeout: () => Uint8List(0),
          );
          
          if (response.isNotEmpty) {
            print('Received echo: ${utf8.decode(response)}');
            expect(utf8.decode(response), equals(testMessage));
          }
          
        } on TLSError catch (e) {
          print('TLS Handshake failed: $e');
          await Future.delayed(const Duration(seconds: 1));
          print('\n=== Python Server Output ===');
          print(server.stdout);
          rethrow;
        }
        
      } finally {
        // TlsConnection doesn't have shutdown
        socket?.destroy();
      }
    }, timeout: Timeout(Duration(seconds: 30)));
  });

  group('Debug: Step-by-step handshake analysis', () {
    test('Analyze handshake message by message', () async {
      final server = PythonTlsServer(port: 4435, cipher: 'chacha20');
      await server.start();
      
      Socket? socket;
      
      try {
        socket = await Socket.connect('127.0.0.1', 4435);
        
        // Use a custom transport to log all bytes
        // Create TLS connection
        final tls = TlsConnection(socket);
        
        final settings = HandshakeSettings(
          minVersion: (3, 3),
          maxVersion: (3, 3),
          cipherNames: ['chacha20-poly1305'],
        );
        
        try {
          await tls.handshakeClient(settings: settings);
          print('SUCCESS: Handshake completed');
        } on TLSError catch (e) {
          print('FAILURE: $e');
        }
        
        await Future.delayed(const Duration(seconds: 1));
        print('\n=== Server Output ===');
        print(server.stdout);
        
      } finally {
        socket?.destroy();
        await server.stop();
      }
    }, timeout: Timeout(Duration(seconds: 30)));
  });
}

String _toHex(List<int> bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ');
}

void _analyzeTlsRecords(Uint8List data, String direction) {
  print('\n=== TLS Records ($direction) ===');
  
  var offset = 0;
  var recordNum = 0;
  
  while (offset + 5 <= data.length) {
    recordNum++;
    final contentType = data[offset];
    final versionMajor = data[offset + 1];
    final versionMinor = data[offset + 2];
    final length = (data[offset + 3] << 8) | data[offset + 4];
    
    String typeName;
    switch (contentType) {
      case 20: typeName = 'ChangeCipherSpec'; break;
      case 21: typeName = 'Alert'; break;
      case 22: typeName = 'Handshake'; break;
      case 23: typeName = 'ApplicationData'; break;
      default: typeName = 'Unknown($contentType)';
    }
    
    print('Record #$recordNum:');
    print('  Type: $typeName');
    print('  Version: $versionMajor.$versionMinor');
    print('  Length: $length');
    
    if (offset + 5 + length <= data.length) {
      final payload = data.sublist(offset + 5, offset + 5 + length);
      
      // Parse handshake messages
      if (contentType == 22 && payload.isNotEmpty) {
        final hsType = payload[0];
        String hsName;
        switch (hsType) {
          case 1: hsName = 'ClientHello'; break;
          case 2: hsName = 'ServerHello'; break;
          case 11: hsName = 'Certificate'; break;
          case 12: hsName = 'ServerKeyExchange'; break;
          case 13: hsName = 'CertificateRequest'; break;
          case 14: hsName = 'ServerHelloDone'; break;
          case 15: hsName = 'CertificateVerify'; break;
          case 16: hsName = 'ClientKeyExchange'; break;
          case 20: hsName = 'Finished'; break;
          default: hsName = 'Unknown($hsType)';
        }
        print('  Handshake: $hsName');
      }
      
      // Show first bytes
      print('  Data: ${_toHex(payload.take(20).toList())}${payload.length > 20 ? "..." : ""}');
    }
    
    offset += 5 + length;
  }
}
