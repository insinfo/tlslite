// ignore_for_file: avoid_print
/// Test TLS connection to local nginx server.
/// Run nginx first: nginx -c nginx.conf -p test/integration/nginx

import 'dart:io';
import 'dart:typed_data';
import 'dart:convert';

import 'package:tlslite/src/tlsconnection.dart';
import 'package:tlslite/src/handshake_settings.dart';
import 'package:tlslite/src/recordlayer.dart';
import 'package:tlslite/src/constants.dart';

Future<void> main() async {
  print('=' * 70);
  print('Testing TLS connection to local nginx server');
  print('=' * 70);
  
  try {
    // Connect to local nginx
    print('\n[1] Connecting to localhost:8443...');
    final socket = await Socket.connect('localhost', 8443);
    print('    TCP connected');
    
    // Wrap with TLS
    print('\n[2] Creating TlsConnection...');
    final tls = TlsConnection(socket);
    
    // Settings for TLS 1.2
    final settings = HandshakeSettings(
      minVersion: (3, 3),
      maxVersion: (3, 3),
    );
    
    print('\n[3] Starting TLS handshake...');
    await tls.handshakeClient(
      settings: settings,
      serverName: 'localhost',
    );
    
    print('\n[4] TLS handshake completed!');
    print('    Version: ${tls.version}');
    print('    Cipher: 0x${tls.session.cipherSuite.toRadixString(16)}');
    
    // Send HTTP request
    print('\n[5] Sending HTTP GET request...');
    final request = 'GET / HTTP/1.1\r\n'
        'Host: localhost\r\n'
        'User-Agent: TlsLite-Dart/1.0\r\n'
        'Connection: close\r\n'
        '\r\n';
    await tls.sendRecord(Message(ContentType.application_data, Uint8List.fromList(utf8.encode(request))));
    
    // Read response
    print('\n[6] Reading response...');
    final response = StringBuffer();
    while (true) {
      try {
        final data = await tls.read();
        if (data.isEmpty) break;
        response.write(utf8.decode(data, allowMalformed: true));
        if (response.toString().contains('</html>')) break;
      } catch (e) {
        print('    Read ended: $e');
        break;
      }
    }
    
    print('\n[7] Response received:');
    final lines = response.toString().split('\n');
    for (int i = 0; i < lines.length && i < 5; i++) {
      print('    ${lines[i]}');
    }
    
    socket.destroy();
    print('\n[8] Connection closed');
    
    print('\n' + '=' * 70);
    print('SUCCESS!');
    print('=' * 70);
    
  } catch (e, st) {
    print('\nERROR: $e');
    print(st);
  }
}
