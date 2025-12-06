// ignore_for_file: avoid_print
/// Simple TLS server for testing the TLS handshake.
/// This server uses Dart's built-in SecureServerSocket for comparison.

import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

Future<void> main() async {
  // Generate self-signed certificate for testing
  await generateTestCertificate();
  
  // Start the server
  final server = await startSecureServer();
  print('Secure server started on port ${server.port}');
  print('Test with: curl -k https://localhost:${server.port}/');
  print('Press Ctrl+C to stop');
  
  // Handle connections
  await for (final socket in server) {
    handleConnection(socket);
  }
}

Future<void> generateTestCertificate() async {
  final certDir = Directory('test/integration/certs');
  if (!await certDir.exists()) {
    await certDir.create(recursive: true);
  }
  
  final certFile = File('test/integration/certs/server.crt');
  final keyFile = File('test/integration/certs/server.key');
  
  if (await certFile.exists() && await keyFile.exists()) {
    print('Using existing certificates');
    return;
  }
  
  print('Generating self-signed certificate...');
  
  // Use OpenSSL to generate certificate
  final result = await Process.run('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048',
    '-keyout', keyFile.path,
    '-out', certFile.path,
    '-days', '365',
    '-nodes',
    '-subj', '/CN=localhost/O=Test/C=US',
  ]);
  
  if (result.exitCode != 0) {
    print('Error generating certificate: ${result.stderr}');
    print('Please ensure OpenSSL is installed and in PATH');
    exit(1);
  }
  
  print('Certificate generated successfully');
}

Future<SecureServerSocket> startSecureServer() async {
  final context = SecurityContext()
    ..useCertificateChain('test/integration/certs/server.crt')
    ..usePrivateKey('test/integration/certs/server.key');
  
  return await SecureServerSocket.bind(
    InternetAddress.anyIPv4,
    8443,
    context,
  );
}

void handleConnection(SecureSocket socket) async {
  print('\n--- New connection from ${socket.remoteAddress}:${socket.remotePort} ---');
  print('Protocol: ${socket.selectedProtocol ?? "not negotiated"}');
  
  try {
    final request = StringBuffer();
    
    await for (final data in socket) {
      request.write(utf8.decode(data));
      
      // Check if we have a complete HTTP request
      if (request.toString().contains('\r\n\r\n')) {
        break;
      }
    }
    
    print('Received request:');
    print(request.toString().split('\r\n').first);
    
    // Send HTTP response
    final body = '''
<!DOCTYPE html>
<html>
<head><title>TLS Test Server</title></head>
<body>
<h1>TLS Connection Successful!</h1>
<p>Your TLS handshake was successful.</p>
<p>Time: ${DateTime.now()}</p>
</body>
</html>
''';
    
    final response = '''HTTP/1.1 200 OK\r
Content-Type: text/html\r
Content-Length: ${body.length}\r
Connection: close\r
\r
$body''';
    
    socket.add(utf8.encode(response));
    await socket.flush();
    
  } catch (e) {
    print('Error handling connection: $e');
  } finally {
    await socket.close();
    print('Connection closed');
  }
}
