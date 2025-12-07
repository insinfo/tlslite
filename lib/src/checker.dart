import 'errors.dart';
import 'x509certchain.dart';
// import 'tlsconnection.dart'; // Avoid cycle if possible, or use it.

/// Class for post-handshake certificate checking.
class Checker {
  final String? x509Fingerprint;
  final bool checkResumedSession;

  /// Create a new Checker instance.
  ///
  /// [x509Fingerprint] A hex-encoded X.509 end-entity fingerprint which the
  /// other party's end-entity certificate must match.
  ///
  /// [checkResumedSession] If resumed sessions should be checked.
  /// Defaults to False.
  Checker({this.x509Fingerprint, this.checkResumedSession = false});

  /// Check a TLSConnection.
  ///
  /// When a Checker is passed to a handshake function, this will
  /// be called at the end of the function.
  ///
  /// [connection] The TLSConnection to examine.
  ///
  /// Throws [TLSAuthenticationError] if the other party's certificate chain
  /// is missing or bad.
  void call(dynamic connection) {
    if (!checkResumedSession && (connection.resumed == true)) {
      return;
    }

    if (x509Fingerprint != null) {
      X509CertChain? chain;
      if (connection.client == true) { // connection._client in 
        chain = connection.session.serverCertChain;
      } else {
        chain = connection.session.clientCertChain;
      }

      if (chain != null) {
        if (chain.getFingerprint() != x509Fingerprint) {
          throw TLSFingerprintError(
              "X.509 fingerprint mismatch: ${chain.getFingerprint()}, $x509Fingerprint");
        }
      } else {
        // chain is null
        // In : elif chain: raise TLSAuthenticationTypeError() else: raise TLSNoAuthenticationError()
        // If chain is null, it means no authentication.
        throw TLSNoAuthenticationError();
      }
    }
  }
}
