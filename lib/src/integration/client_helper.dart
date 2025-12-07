

import '../checker.dart';
import '../handshake_settings.dart';
import '../session.dart';
import '../tls_connection.dart';
import '../utils/dns_utils.dart';
import '../x509certchain.dart';

/// Helper class used to integrate TLS Lite with various TLS clients
/// (e.g. IMAP, POP3, SMTP, HTTP, etc.)
class ClientHelper {
  /// SRP username for mutual authentication
  String? username;

  /// SRP password for mutual authentication
  String? password;

  /// Certificate chain for client authentication
  X509CertChain? certChain;

  /// Private key for client authentication
  Object? privateKey;

  /// Callable object called after handshaking to evaluate the connection
  Checker? checker;

  /// Handshake settings for controlling ciphersuites, versions, etc.
  HandshakeSettings? settings;

  /// Whether to use anonymous TLS ciphersuites
  bool anon;

  /// Server name for SNI extension
  String? serverName;

  /// TLS session for resumption
  Session? tlsSession;

  /// Creates a new ClientHelper.
  ///
  /// For client authentication, use one of these argument combinations:
  /// - [username], [password] (SRP)
  /// - [certChain], [privateKey] (certificate)
  ///
  /// For server authentication, you can either rely on the implicit mutual
  /// authentication performed by SRP, or you can do certificate-based server
  /// authentication.
  ///
  /// The constructor does not perform the TLS handshake itself, but simply
  /// stores these arguments for later. The handshake is performed only when
  /// this class needs to connect with the server.
  ///
  /// Parameters:
  /// - [username]: SRP username. Requires the 'password' argument.
  /// - [password]: SRP password for mutual authentication.
  /// - [certChain]: Certificate chain for client authentication.
  /// - [privateKey]: Private key for client authentication.
  /// - [checker]: Callable object called after handshaking to evaluate the connection.
  /// - [settings]: Various settings to control ciphersuites, certificate types, and TLS versions.
  /// - [anon]: Set to true if negotiation should advertise only anonymous TLS ciphersuites.
  /// - [host]: The hostname that the connection is made to (for SNI).
  ClientHelper({
    this.username,
    this.password,
    this.certChain,
    this.privateKey,
    this.checker,
    this.settings,
    this.anon = false,
    String? host,
  }) {
    // Validate parameter combinations
    final hasSrp = username != null && password != null;
    final hasCert = certChain != null && privateKey != null;
    final hasPartialSrp = (username != null) != (password != null);
    final hasPartialCert = (certChain != null) != (privateKey != null);

    if (hasPartialSrp || hasPartialCert) {
      throw ArgumentError('Bad parameters: incomplete authentication credentials');
    }

    if (hasSrp && hasCert) {
      throw ArgumentError('Bad parameters: cannot use both SRP and certificate authentication');
    }

    if (anon && (hasSrp || hasCert)) {
      throw ArgumentError('Bad parameters: anonymous mode is mutually exclusive with authentication');
    }

    // Process host for SNI
    if (host != null && !_isIP(host)) {
      // Remove port if present
      final colon = host.indexOf(':');
      if (colon > 0) {
        host = host.substring(0, colon);
      }
      serverName = host;
      if (host.isNotEmpty && !isValidHostname(host)) {
        throw ArgumentError('Invalid hostname: $host');
      }
    } else {
      serverName = null;
    }
  }

  /// Returns true if the address is an IPv4 address.
  static bool _isIP(String? address) {
    if (address == null || address.isEmpty) {
      return false;
    }

    final vals = address.split('.');
    if (vals.length != 4) {
      return false;
    }

    for (final part in vals) {
      final i = int.tryParse(part);
      if (i == null || i < 0 || i > 255) {
        return false;
      }
    }
    return true;
  }

  /// Returns true if the address is an IPv6 address.
  static bool _isIPv6(String? address) {
    if (address == null || address.isEmpty) {
      return false;
    }
    // Simple check: contains colons and valid hex segments
    if (!address.contains(':')) {
      return false;
    }
    final parts = address.split(':');
    if (parts.length < 3 || parts.length > 8) {
      return false;
    }
    for (final part in parts) {
      if (part.isEmpty) continue; // Allow :: shorthand
      if (part.length > 4) return false;
      if (int.tryParse(part, radix: 16) == null) {
        return false;
      }
    }
    return true;
  }

  /// Returns true if the address is any type of IP address.
  static bool isIPAddress(String? address) {
    return _isIP(address) || _isIPv6(address);
  }

  /// Performs the TLS handshake on the given connection.
  ///
  /// This method selects the appropriate handshake method based on the
  /// authentication parameters provided to the constructor.
  Future<void> handshake(TlsConnection tlsConnection) async {
    if (username != null && password != null) {
      // SRP authentication
      await tlsConnection.handshakeClient(
        srpParams: SrpParams(username: username!, password: password!),
        settings: settings,
        session: tlsSession,
        serverName: serverName ?? '',
      );
    } else if (anon) {
      // Anonymous handshake
      await tlsConnection.handshakeClient(
        anonParams: true,
        settings: settings,
        session: tlsSession,
        serverName: serverName ?? '',
      );
    } else {
      // Certificate-based handshake
      await tlsConnection.handshakeClient(
        certParams: certChain != null && privateKey != null
            ? Keypair(key: privateKey, certificates: certChain!.x509List)
            : null,
        settings: settings,
        session: tlsSession,
        serverName: serverName ?? '',
      );
    }
    tlsSession = tlsConnection.session;
    if (checker != null) {
      checker!(tlsConnection);
    }
  }
}

/// Parameters for SRP authentication.
class SrpParams {
  final String username;
  final String password;

  const SrpParams({required this.username, required this.password});
}
