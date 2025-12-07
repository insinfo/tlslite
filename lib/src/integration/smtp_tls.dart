
/// TLS Lite + SMTP client with STARTTLS support.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../checker.dart';
import '../handshake_settings.dart';
import '../tls_connection.dart';
import '../x509certchain.dart';
import 'client_helper.dart';

/// Default SMTP port.
const int smtpPort = 25;

/// Default SMTP submission port.
const int smtpSubmissionPort = 587;

/// Default SMTPS (SMTP over TLS) port.
const int smtpsPort = 465;

/// SMTP client with TLS support via STARTTLS.
///
/// This class provides a simple SMTP client that supports STARTTLS for
/// upgrading a plain connection to TLS. It also supports direct TLS
/// connections on port 465.
///
/// Example usage with STARTTLS:
/// ```dart
/// final client = SmtpTls(host: 'smtp.example.com', port: 587);
/// await client.connect();
/// await client.ehlo('mydomain.com');
/// await client.starttls();
/// await client.login('user@example.com', 'password');
/// await client.sendMail(
///   from: 'user@example.com',
///   to: ['recipient@example.com'],
///   data: 'Subject: Test\r\n\r\nHello!',
/// );
/// await client.quit();
/// ```
class SmtpTls {
  final String host;
  final int port;
  
  Socket? _socket;
  TlsConnection? _tlsConnection;
  bool _tlsActive = false;
  
  /// Creates a new SMTP client.
  SmtpTls({
    required this.host,
    this.port = smtpSubmissionPort,
  });

  /// Whether TLS is active on the connection.
  bool get isTlsActive => _tlsActive;

  /// Whether the client is connected.
  bool get isConnected => _socket != null || _tlsConnection != null;

  /// Connects to the SMTP server.
  Future<SmtpResponse> connect() async {
    _socket = await Socket.connect(host, port);
    return await _readResponse();
  }

  /// Connects directly using TLS (for SMTPS on port 465).
  Future<SmtpResponse> connectTls({
    String? srpUsername,
    String? srpPassword,
    X509CertChain? certChain,
    Object? privateKey,
    Checker? checker,
    HandshakeSettings? settings,
  }) async {
    _socket = await Socket.connect(host, port);
    _tlsConnection = TlsConnection(_socket!);
    
    final helper = ClientHelper(
      username: srpUsername,
      password: srpPassword,
      certChain: certChain,
      privateKey: privateKey,
      checker: checker,
      settings: settings,
      host: host,
    );
    
    await helper.handshake(_tlsConnection!);
    _tlsActive = true;
    
    return await _readResponse();
  }

  /// Upgrades the connection to TLS using STARTTLS.
  ///
  /// Call this after receiving a 220 response to the STARTTLS command.
  Future<SmtpResponse> starttls({
    String? srpUsername,
    String? srpPassword,
    X509CertChain? certChain,
    Object? privateKey,
    Checker? checker,
    HandshakeSettings? settings,
  }) async {
    // Send STARTTLS command
    final response = await _sendCommand('STARTTLS');
    
    if (response.code != 220) {
      return response;
    }
    
    // Upgrade to TLS
    _tlsConnection = TlsConnection(_socket!);
    
    final helper = ClientHelper(
      username: srpUsername,
      password: srpPassword,
      certChain: certChain,
      privateKey: privateKey,
      checker: checker,
      settings: settings,
      host: host,
    );
    
    await helper.handshake(_tlsConnection!);
    _tlsActive = true;
    
    return response;
  }

  /// Sends a command and returns the response.
  Future<SmtpResponse> _sendCommand(String command) async {
    final data = Uint8List.fromList(utf8.encode('$command\r\n'));
    
    if (_tlsActive && _tlsConnection != null) {
      await _tlsConnection!.write(data);
    } else if (_socket != null) {
      _socket!.add(data);
      await _socket!.flush();
    }
    
    return await _readResponse();
  }

  Future<SmtpResponse> _readResponse() async {
    final lines = <String>[];
    
    while (true) {
      final line = await _readLine();
      lines.add(line);
      
      // Check if this is the last line (code followed by space, not hyphen)
      if (line.length >= 4 && line[3] == ' ') {
        break;
      }
    }
    
    final lastLine = lines.last;
    final code = int.tryParse(lastLine.substring(0, 3)) ?? 0;
    final message = lines.map((l) => l.length > 4 ? l.substring(4) : '').join('\n');
    
    return SmtpResponse(code, message, lines);
  }

  Future<String> _readLine() async {
    final buffer = <int>[];
    
    while (true) {
      int byte;
      
      if (_tlsActive && _tlsConnection != null) {
        final data = await _tlsConnection!.read(max: 1);
        if (data.isEmpty) break;
        byte = data[0];
      } else if (_socket != null) {
        final data = await _socket!.first;
        if (data.isEmpty) break;
        byte = data[0];
      } else {
        break;
      }
      
      buffer.add(byte);
      
      if (buffer.length >= 2 && 
          buffer[buffer.length - 2] == 0x0D && 
          buffer[buffer.length - 1] == 0x0A) {
        buffer.removeLast();
        buffer.removeLast();
        break;
      }
    }
    
    return utf8.decode(buffer);
  }

  /// Sends the EHLO command.
  Future<SmtpResponse> ehlo(String domain) async {
    return await _sendCommand('EHLO $domain');
  }

  /// Sends the HELO command.
  Future<SmtpResponse> helo(String domain) async {
    return await _sendCommand('HELO $domain');
  }

  /// Authenticates using AUTH LOGIN.
  Future<SmtpResponse> login(String username, String password) async {
    var response = await _sendCommand('AUTH LOGIN');
    if (response.code != 334) {
      return response;
    }
    
    response = await _sendCommand(base64Encode(utf8.encode(username)));
    if (response.code != 334) {
      return response;
    }
    
    return await _sendCommand(base64Encode(utf8.encode(password)));
  }

  /// Authenticates using AUTH PLAIN.
  Future<SmtpResponse> authPlain(String username, String password) async {
    final credentials = base64Encode(utf8.encode('\x00$username\x00$password'));
    return await _sendCommand('AUTH PLAIN $credentials');
  }

  /// Sends the MAIL FROM command.
  Future<SmtpResponse> mailFrom(String sender) async {
    return await _sendCommand('MAIL FROM:<$sender>');
  }

  /// Sends the RCPT TO command.
  Future<SmtpResponse> rcptTo(String recipient) async {
    return await _sendCommand('RCPT TO:<$recipient>');
  }

  /// Sends the DATA command and the message body.
  Future<SmtpResponse> data(String body) async {
    var response = await _sendCommand('DATA');
    if (response.code != 354) {
      return response;
    }
    
    // Send the message body, ensuring proper line endings and dot-stuffing
    final lines = body.split('\n');
    final buffer = StringBuffer();
    
    for (var line in lines) {
      line = line.trimRight();
      // Dot-stuffing: lines starting with a dot get an extra dot
      if (line.startsWith('.')) {
        buffer.write('.');
      }
      buffer.write(line);
      buffer.write('\r\n');
    }
    
    // End with <CRLF>.<CRLF>
    buffer.write('.\r\n');
    
    final data = Uint8List.fromList(utf8.encode(buffer.toString()));
    
    if (_tlsActive && _tlsConnection != null) {
      await _tlsConnection!.write(data);
    } else if (_socket != null) {
      _socket!.add(data);
      await _socket!.flush();
    }
    
    return await _readResponse();
  }

  /// Convenience method to send an email.
  Future<SmtpResponse> sendMail({
    required String from,
    required List<String> to,
    required String data,
  }) async {
    var response = await mailFrom(from);
    if (response.code != 250) {
      return response;
    }
    
    for (final recipient in to) {
      response = await rcptTo(recipient);
      if (response.code != 250 && response.code != 251) {
        return response;
      }
    }
    
    return await this.data(data);
  }

  /// Sends the RSET command.
  Future<SmtpResponse> rset() async {
    return await _sendCommand('RSET');
  }

  /// Sends the NOOP command.
  Future<SmtpResponse> noop() async {
    return await _sendCommand('NOOP');
  }

  /// Sends the VRFY command.
  Future<SmtpResponse> vrfy(String address) async {
    return await _sendCommand('VRFY $address');
  }

  /// Closes the connection.
  Future<SmtpResponse> quit() async {
    final response = await _sendCommand('QUIT');
    
    if (_tlsConnection != null) {
      _tlsConnection!.sock?.close();
      _tlsConnection = null;
    } else if (_socket != null) {
      await _socket!.close();
    }
    _socket = null;
    _tlsActive = false;
    
    return response;
  }
}

/// Represents an SMTP response.
class SmtpResponse {
  /// The 3-digit response code.
  final int code;
  
  /// The response message (without the code).
  final String message;
  
  /// The raw response lines.
  final List<String> lines;

  SmtpResponse(this.code, this.message, this.lines);

  /// Whether this is a positive response (2xx).
  bool get isPositive => code >= 200 && code < 300;
  
  /// Whether this is a positive intermediate response (3xx).
  bool get isIntermediate => code >= 300 && code < 400;
  
  /// Whether this is a negative response (4xx or 5xx).
  bool get isNegative => code >= 400;

  @override
  String toString() => '$code $message';
}
