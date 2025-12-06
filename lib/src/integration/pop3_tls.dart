// Author: Trevor Perrin
// Ported to Dart from tlslite-ng
// See the LICENSE file for legal information regarding use of this file.

/// TLS Lite + POP3 client with TLS support.
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import '../checker.dart';
import '../handshake_settings.dart';
import '../tlsconnection.dart';
import '../x509certchain.dart';
import 'client_helper.dart';

/// Default POP3 TLS port.
const int pop3TlsPort = 995;

/// POP3 client with TLS support.
///
/// This class provides a simple POP3 client that uses TLS for secure
/// communication. It supports certificate-based and SRP authentication.
///
/// Example usage:
/// ```dart
/// final client = Pop3Tls(
///   host: 'pop.example.com',
///   port: 995,
/// );
/// await client.connect();
/// await client.login('user', 'password');
/// final stat = await client.stat();
/// await client.quit();
/// ```
class Pop3Tls {
  final String host;
  final int port;
  final ClientHelper _helper;
  
  TlsConnection? _connection;
  String? _welcomeMessage;
  
  /// The server's welcome message received after connecting.
  String? get welcomeMessage => _welcomeMessage;

  /// Creates a new POP3 TLS client.
  ///
  /// For client authentication, use one of these argument combinations:
  /// - [srpUsername], [srpPassword] (SRP)
  /// - [certChain], [privateKey] (certificate)
  ///
  /// Parameters:
  /// - [host]: Server to connect to.
  /// - [port]: Port to connect to (default: 995).
  /// - [srpUsername]: SRP username for mutual authentication.
  /// - [srpPassword]: SRP password for mutual authentication.
  /// - [certChain]: Certificate chain for client authentication.
  /// - [privateKey]: Private key for client authentication.
  /// - [checker]: Callable object called after handshaking to evaluate the connection.
  /// - [settings]: Various settings to control ciphersuites, certificate types, and TLS versions.
  Pop3Tls({
    required this.host,
    this.port = pop3TlsPort,
    String? srpUsername,
    String? srpPassword,
    X509CertChain? certChain,
    Object? privateKey,
    Checker? checker,
    HandshakeSettings? settings,
  }) : _helper = ClientHelper(
          username: srpUsername,
          password: srpPassword,
          certChain: certChain,
          privateKey: privateKey,
          checker: checker,
          settings: settings,
          host: host,
        );

  /// Whether the client is connected.
  bool get isConnected => _connection != null;

  /// Connects to the POP3 server and performs the TLS handshake.
  Future<String> connect() async {
    final socket = await Socket.connect(host, port);
    _connection = TlsConnection(socket);
    await _helper.handshake(_connection!);
    
    // Read server greeting
    _welcomeMessage = await _readResponse();
    return _welcomeMessage!;
  }

  /// Sends a command and returns the response.
  Future<String> _sendCommand(String command) async {
    await _connection!.write(Uint8List.fromList(utf8.encode('$command\r\n')));
    return await _readResponse();
  }

  Future<String> _readResponse() async {
    final buffer = <int>[];
    while (true) {
      final data = await _connection!.read(max: 1);
      if (data.isEmpty) break;
      buffer.add(data[0]);
      if (buffer.length >= 2 && 
          buffer[buffer.length - 2] == 0x0D && 
          buffer[buffer.length - 1] == 0x0A) {
        // Remove CRLF
        buffer.removeLast();
        buffer.removeLast();
        break;
      }
    }
    return utf8.decode(buffer);
  }

  /// Reads a multi-line response (terminated by a line with just a dot).
  Future<String> _readMultiLineResponse() async {
    final response = StringBuffer();
    while (true) {
      final line = await _readResponse();
      if (line == '.') {
        break;
      }
      // Handle byte-stuffing (lines starting with . are prefixed with another .)
      if (line.startsWith('..')) {
        response.writeln(line.substring(1));
      } else {
        response.writeln(line);
      }
    }
    return response.toString();
  }

  /// Authenticates with USER/PASS commands.
  Future<String> login(String username, String password) async {
    final userResp = await _sendCommand('USER $username');
    if (!userResp.startsWith('+OK')) {
      return userResp;
    }
    return await _sendCommand('PASS $password');
  }

  /// Gets mailbox statistics (number of messages and total size).
  Future<String> stat() async {
    return await _sendCommand('STAT');
  }

  /// Lists messages. If [msgNum] is provided, lists only that message.
  Future<String> list([int? msgNum]) async {
    if (msgNum != null) {
      return await _sendCommand('LIST $msgNum');
    }
    final response = await _sendCommand('LIST');
    if (response.startsWith('+OK')) {
      final multiLine = await _readMultiLineResponse();
      return '$response\n$multiLine';
    }
    return response;
  }

  /// Retrieves a message by number.
  Future<String> retr(int msgNum) async {
    final response = await _sendCommand('RETR $msgNum');
    if (response.startsWith('+OK')) {
      final body = await _readMultiLineResponse();
      return '$response\n$body';
    }
    return response;
  }

  /// Deletes a message by number.
  Future<String> dele(int msgNum) async {
    return await _sendCommand('DELE $msgNum');
  }

  /// Resets the session (unmarks deleted messages).
  Future<String> rset() async {
    return await _sendCommand('RSET');
  }

  /// Sends a NOOP command.
  Future<String> noop() async {
    return await _sendCommand('NOOP');
  }

  /// Gets the unique ID for a message or all messages.
  Future<String> uidl([int? msgNum]) async {
    if (msgNum != null) {
      return await _sendCommand('UIDL $msgNum');
    }
    final response = await _sendCommand('UIDL');
    if (response.startsWith('+OK')) {
      final multiLine = await _readMultiLineResponse();
      return '$response\n$multiLine';
    }
    return response;
  }

  /// Gets the top [lines] lines of a message.
  Future<String> top(int msgNum, int lines) async {
    final response = await _sendCommand('TOP $msgNum $lines');
    if (response.startsWith('+OK')) {
      final body = await _readMultiLineResponse();
      return '$response\n$body';
    }
    return response;
  }

  /// Closes the connection.
  Future<String> quit() async {
    final response = await _sendCommand('QUIT');
    _connection?.sock?.close();
    _connection = null;
    return response;
  }
}
