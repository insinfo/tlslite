

/// TLS Lite + IMAP4 client with TLS support.
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

/// Default IMAP TLS port.
const int imap4TlsPort = 993;

/// IMAP4 client with TLS support.
///
/// This class provides a simple IMAP4 client that uses TLS for secure
/// communication. It supports certificate-based and SRP authentication.
///
/// Example usage:
/// ```dart
/// final client = Imap4Tls(
///   host: 'imap.example.com',
///   port: 993,
/// );
/// await client.connect();
/// final response = await client.login('user', 'password');
/// await client.close();
/// ```
class Imap4Tls {
  final String host;
  final int port;
  final ClientHelper _helper;
  
  TlsConnection? _connection;
  int _tagCounter = 0;
  
  /// Creates a new IMAP4 TLS client.
  ///
  /// For client authentication, use one of these argument combinations:
  /// - [srpUsername], [srpPassword] (SRP)
  /// - [certChain], [privateKey] (certificate)
  ///
  /// Parameters:
  /// - [host]: Server to connect to.
  /// - [port]: Port to connect to (default: 993).
  /// - [srpUsername]: SRP username for mutual authentication.
  /// - [srpPassword]: SRP password for mutual authentication.
  /// - [certChain]: Certificate chain for client authentication.
  /// - [privateKey]: Private key for client authentication.
  /// - [checker]: Callable object called after handshaking to evaluate the connection.
  /// - [settings]: Various settings to control ciphersuites, certificate types, and TLS versions.
  Imap4Tls({
    required this.host,
    this.port = imap4TlsPort,
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

  /// Connects to the IMAP server and performs the TLS handshake.
  Future<String> connect() async {
    final socket = await Socket.connect(host, port);
    _connection = TlsConnection(socket);
    await _helper.handshake(_connection!);
    
    // Read server greeting
    return await _readLine();
  }

  /// Sends a command and returns the response.
  Future<String> _sendCommand(String command) async {
    final tag = 'A${_tagCounter++}';
    final fullCommand = '$tag $command\r\n';
    
    await _connection!.write(Uint8List.fromList(utf8.encode(fullCommand)));
    
    // Read response lines until we get the tagged response
    final response = StringBuffer();
    while (true) {
      final line = await _readLine();
      response.writeln(line);
      if (line.startsWith(tag)) {
        break;
      }
    }
    return response.toString();
  }

  Future<String> _readLine() async {
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

  /// Logs in with the given username and password.
  Future<String> login(String username, String password) async {
    return await _sendCommand('LOGIN $username $password');
  }

  /// Logs out from the server.
  Future<String> logout() async {
    return await _sendCommand('LOGOUT');
  }

  /// Selects a mailbox.
  Future<String> select(String mailbox) async {
    return await _sendCommand('SELECT $mailbox');
  }

  /// Lists mailboxes matching the pattern.
  Future<String> list(String reference, String pattern) async {
    return await _sendCommand('LIST "$reference" "$pattern"');
  }

  /// Searches for messages matching the criteria.
  Future<String> search(String criteria) async {
    return await _sendCommand('SEARCH $criteria');
  }

  /// Fetches message data.
  Future<String> fetch(String sequence, String items) async {
    return await _sendCommand('FETCH $sequence $items');
  }

  /// Gets the server capability.
  Future<String> capability() async {
    return await _sendCommand('CAPABILITY');
  }

  /// Sends a NOOP command.
  Future<String> noop() async {
    return await _sendCommand('NOOP');
  }

  /// Closes the connection.
  Future<void> close() async {
    if (_connection != null) {
      try {
        await logout();
      } catch (_) {}
      _connection!.sock?.close();
      _connection = null;
    }
  }
}
