

/// TLS Lite + Socket Server Mixin for creating TLS servers.
library;

import 'dart:async' show unawaited;
import 'dart:io' show InternetAddress, ServerSocket, Socket;

import '../handshake_settings.dart' show HandshakeSettings;
import '../tls_connection.dart' show TlsConnection;
import '../x509certchain.dart' show X509CertChain;

/// Mixin that adds TLS support to any TCP server.
///
/// This mixin can be used to add TLS support to TCP servers. To use it,
/// create a class that uses this mixin and implement the [handleClient] method.
///
/// Example usage:
/// ```dart
/// class MyTlsServer with TlsSocketServerMixin {
///   final X509CertChain certChain;
///   final Object privateKey;
///   final SessionCache sessionCache = SessionCache();
///
///   MyTlsServer(this.certChain, this.privateKey);
///
///   @override
///   Future<bool> handshake(TlsConnection tlsConnection) async {
///     try {
///       await tlsConnection.handshakeServer(
///         certChain: certChain,
///         privateKey: privateKey,
///         sessionCache: sessionCache,
///       );
///       return true;
///     } catch (e) {
///       print('Handshake failure: $e');
///       return false;
///     }
///   }
///
///   @override
///   Future<void> handleClient(TlsConnection connection, dynamic address) async {
///     // Handle the TLS connection
///     final data = await connection.read();
///     await connection.write(data); // Echo
///   }
/// }
///
/// // Usage:
/// final server = MyTlsServer(certChain, privateKey);
/// await server.bind('localhost', 443);
/// await server.serve();
/// ```
mixin TlsSocketServerMixin {
  ServerSocket? _serverSocket;
  bool _running = false;

  /// Binds the server to the specified address and port.
  Future<void> bind(
    dynamic address,
    int port, {
    int backlog = 0,
    bool v6Only = false,
    bool shared = false,
  }) async {
    _serverSocket = await ServerSocket.bind(
      address,
      port,
      backlog: backlog,
      v6Only: v6Only,
      shared: shared,
    );
  }

  /// Returns the address the server is bound to.
  InternetAddress? get address => _serverSocket?.address;

  /// Returns the port the server is listening on.
  int? get port => _serverSocket?.port;

  /// Starts serving incoming connections.
  ///
  /// This method will listen for incoming connections and handle them
  /// asynchronously. For each connection, it will:
  /// 1. Create a TlsConnection wrapper
  /// 2. Call [handshake] to perform the TLS handshake
  /// 3. If handshake succeeds, call [handleClient] to process the request
  /// 4. Close the connection when done
  Future<void> serve() async {
    if (_serverSocket == null) {
      throw StateError('Server not bound. Call bind() first.');
    }

    _running = true;

    await for (final socket in _serverSocket!) {
      if (!_running) break;

      // Handle each connection asynchronously
      unawaited(_handleConnection(socket));
    }
  }

  Future<void> _handleConnection(Socket socket) async {
    final clientAddress = socket.remoteAddress;
    final tlsConnection = TlsConnection(socket);

    try {
      final success = await handshake(tlsConnection);
      if (success) {
        await handleClient(tlsConnection, clientAddress);
      }
    } catch (e) {
      // Log or handle error
      onError(e, clientAddress);
    } finally {
      try {
        tlsConnection.sock?.close();
      } catch (_) {
        // Ignore close errors
      }
    }
  }

  /// Performs the TLS handshake on the connection.
  ///
  /// Override this method to implement your server's handshake logic.
  /// Return true if the handshake succeeds and the request should be processed.
  /// Return false to reject the connection.
  ///
  /// Example:
  /// ```dart
  /// @override
  /// Future<bool> handshake(TlsConnection tlsConnection) async {
  ///   try {
  ///     await tlsConnection.handshakeServer(
  ///       certChain: certChain,
  ///       privateKey: privateKey,
  ///       sessionCache: sessionCache,
  ///     );
  ///     return true;
  ///   } catch (e) {
  ///     print('Handshake failure: $e');
  ///     return false;
  ///   }
  /// }
  /// ```
  Future<bool> handshake(TlsConnection tlsConnection);

  /// Handles a client connection after successful TLS handshake.
  ///
  /// Override this method to implement your server's request handling logic.
  Future<void> handleClient(TlsConnection connection, dynamic clientAddress);

  /// Called when an error occurs during connection handling.
  ///
  /// Override this method to implement custom error handling.
  void onError(Object error, dynamic clientAddress) {
    // Default: do nothing
  }

  /// Stops the server from accepting new connections.
  Future<void> close() async {
    _running = false;
    await _serverSocket?.close();
    _serverSocket = null;
  }
}

/// A simple TLS server implementation using the mixin.
class SimpleTlsServer with TlsSocketServerMixin {
  final X509CertChain certChain;
  final Object privateKey;
  final HandshakeSettings? settings;
  final Future<void> Function(TlsConnection connection, dynamic address)?
      requestHandler;
  final void Function(Object error, dynamic address)? errorHandler;

  SimpleTlsServer({
    required this.certChain,
    required this.privateKey,
    this.settings,
    this.requestHandler,
    this.errorHandler,
  });

  @override
  Future<bool> handshake(TlsConnection tlsConnection) async {
    try {
      await tlsConnection.handshakeServer(
        certChain: certChain,
        privateKey: privateKey,
        settings: settings,
      );
      return true;
    } catch (e) {
      return false;
    }
  }

  @override
  Future<void> handleClient(
      TlsConnection connection, dynamic clientAddress) async {
    if (requestHandler != null) {
      await requestHandler!(connection, clientAddress);
    }
  }

  @override
  void onError(Object error, dynamic clientAddress) {
    if (errorHandler != null) {
      errorHandler!(error, clientAddress);
    }
  }
}
