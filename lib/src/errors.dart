// Ported to Dart from tlslite-ng tlslite/errors.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'constants.dart';

/// Base class for all TLS Lite exceptions.
///
/// See [TLSError] for the exceptions that library users are expected
/// to catch.
class BaseTLSException implements Exception {
  final String? message;
  BaseTLSException([this.message]);

  @override
  String toString() {
    final className = runtimeType.toString();
    return message == null ? className : '$className: $message';
  }
}

/// Base class for exceptions thrown during encryption.
class EncryptionError extends BaseTLSException {
  EncryptionError([String? message]) : super(message);
}

// --- TLS Errors (Main Hierarchy) ---

/// Base class for all TLS errors raised by the library.
class TLSError extends BaseTLSException {
  TLSError([String? message]) : super(message);
  // The toString inherited from BaseTLSException already reproduces
  // the original behaviour reasonably well.
}

/// An attempt was made to use the connection after it was closed.
///
/// Note: in tlslite-ng this also inherits from socket.error. Dart does not
/// support multiple inheritance, so here it only extends [TLSError].
class TLSClosedConnectionError extends TLSError {
  TLSClosedConnectionError([String? message]) : super(message);
}

/// The socket was closed without a proper TLS shutdown.
///
/// The TLS specification requires that an alert of some sort
/// be sent before the underlying socket is closed. If the socket
/// is closed without this, it could mean that an attacker is trying
/// to truncate the connection. It could also mean a misbehaving
/// TLS implementation, or a random network failure.
class TLSAbruptCloseError extends TLSError {
  TLSAbruptCloseError([String? message]) : super(message);
}

// --- TLS Alerts ---

/// A TLS alert has been signalled.
abstract class TLSAlert extends TLSError {
  /// Set to one of the constants in [AlertDescription].
  final int description; // An int, matching the class definition

  /// Set to one of the constants in [AlertLevel].
  final int level; // An int, matching the class definition

  TLSAlert(this.description, this.level, [String? message]) : super(message);
}

/// A TLS alert has been signalled by the local implementation.
class TLSLocalAlert extends TLSAlert {
  /// Description of what went wrong.
  final String? detailedMessage;

  /// Creates a local alert.
  /// [description] must be one of the [AlertDescription] constants.
  /// [level] must be one of the [AlertLevel] constants.
  TLSLocalAlert(int description, int level, {this.detailedMessage})
      : super(description, level); // Takes an int

  @override
  String toString() {
    // Use the static method of the AlertDescription class defined in constants.dart
    final alertStr = AlertDescription.toStr(description);
    if (detailedMessage != null) {
      return '$alertStr: $detailedMessage';
    } else {
      return alertStr;
    }
  }
}

/// A TLS alert has been signalled by the remote implementation.
class TLSRemoteAlert extends TLSAlert {
  /// Creates a remote alert.
  /// [description] must be one of the [AlertDescription] constants.
  /// [level] must be one of the [AlertLevel] constants.
  TLSRemoteAlert(int description, int level)
      : super(description, level); // Takes an int

  @override
  String toString() {
    // Use the static method of the AlertDescription class defined in constants.dart
    return AlertDescription.toStr(description);
  }
}

// --- TLS Authentication Errors ---

/// The handshake succeeded, but the other party's authentication
/// was inadequate.
///
/// This exception will only be thrown when a `Checker` has been passed
/// to a handshake function. The Checker will be invoked once the handshake
/// completes, and if the Checker objects to how the other party
/// authenticated, a subclass of this exception will be thrown.
class TLSAuthenticationError extends TLSError {
  TLSAuthenticationError([String? message]) : super(message);
}

/// The Checker was expecting the other party to authenticate with a
/// certificate chain, but this did not occur.
class TLSNoAuthenticationError extends TLSAuthenticationError {
  TLSNoAuthenticationError([String? message]) : super(message);
}

/// The Checker was expecting the other party to authenticate with a
/// different type of certificate chain.
class TLSAuthenticationTypeError extends TLSAuthenticationError {
  TLSAuthenticationTypeError([String? message]) : super(message);
}

/// The Checker was expecting the other party to authenticate with a
/// certificate chain that matches a different fingerprint.
class TLSFingerprintError extends TLSAuthenticationError {
  TLSFingerprintError([String? message]) : super(message);
}

/// The Checker was expecting the other party to authenticate with a
/// certificate chain that has a different authorization.
class TLSAuthorizationError extends TLSAuthenticationError {
  TLSAuthorizationError([String? message]) : super(message);
}

/// The Checker has determined that the other party's certificate chain
/// is invalid.
class TLSValidationError extends TLSAuthenticationError {
  /// Contains information about this validation failure.
  final dynamic
      info; // Could be Map<String, dynamic>? if the structure were known

  TLSValidationError(String msg, {this.info}) : super(msg);

  @override
  String toString() {
    final baseStr = super.toString();
    return info == null ? baseStr : '$baseStr (Info: $info)';
  }
}

/// Why an X.509 certificate chain was rejected by `X509Validator`.
enum CertificateVerificationFailure {
  /// The peer did not present any certificate.
  noCertificate,

  /// A certificate on the path is past its notAfter date.
  expired,

  /// A certificate on the path is before its notBefore date.
  notYetValid,

  /// No path to a trust anchor could be built (issuer not found).
  unknownIssuer,

  /// The leaf is self-signed and is not one of the trust anchors.
  selfSigned,

  /// A certificate signature did not verify with its issuer's key.
  badSignature,

  /// An issuing certificate is not a CA (basicConstraints cA=false/absent).
  notCA,

  /// An issuer's basicConstraints pathLenConstraint was exceeded.
  pathLengthExceeded,

  /// An issuer's keyUsage does not allow keyCertSign.
  keyUsage,

  /// The leaf's extendedKeyUsage does not allow the required purpose
  /// (serverAuth by default).
  extendedKeyUsage,

  /// A name in the leaf violates an issuer's nameConstraints.
  nameConstraints,

  /// A certificate carries a critical extension the validator does not
  /// understand.
  unhandledCriticalExtension,

  /// The leaf does not match the expected host name / IP address.
  hostnameMismatch,

  /// The chain is longer than the validator's maximum depth.
  chainTooLong,

  /// The certificate (or its signature algorithm / key) is malformed or
  /// unsupported.
  malformed,
}

/// The peer's X.509 certificate chain failed validation (path building,
/// signature, validity period, constraints or host name check).
///
/// Thrown by `X509Validator.validate` and, when the validator is used as a
/// `Checker` during `TlsConnection.handshakeClient`, raised from the
/// handshake after a fatal alert (`bad_certificate`, `certificate_expired`
/// or `unknown_ca`) has been sent to the peer.
class TLSCertificateVerificationError extends TLSValidationError {
  /// Machine readable failure category.
  final CertificateVerificationFailure reason;

  /// The certificate that caused the failure, when known (an `X509`).
  final Object? certificate;

  TLSCertificateVerificationError(this.reason, String message,
      {this.certificate})
      : super(message);

  @override
  String toString() => 'TLSCertificateVerificationError(${reason.name}): '
      '$message';
}

// --- Other TLS Errors ---

/// The other party responded incorrectly to an induced fault.
///
/// This exception will only occur during fault testing, when a
/// connection's fault variable is set to induce some sort of faulty
/// behavior, and the other party does not respond appropriately.
class TLSFaultError extends TLSError {
  TLSFaultError([String? message]) : super(message);
}

/// The implementation does not support the requested (or required) capabilities.
class TLSUnsupportedError extends TLSError {
  TLSUnsupportedError([String? message]) : super(message);
}

/// The internal state of the object is unexpected or invalid.
///
/// Caused by incorrect use of the API.
class TLSInternalError extends TLSError {
  TLSInternalError([String? message]) : super(message);
}

// --- TLS Protocol Exceptions (Internal Handling) ---

/// Exceptions used internally for handling errors in received messages.
class TLSProtocolException extends BaseTLSException {
  TLSProtocolException([String? message]) : super(message);
}

/// The parameters specified in the message were incorrect or invalid.
class TLSIllegalParameterException extends TLSProtocolException {
  TLSIllegalParameterException([String? message]) : super(message);
}

/// The encoding of the received message does not match the specification.
class TLSDecodeError extends TLSProtocolException {
  TLSDecodeError([String? message]) : super(message);
}

/// The received message was unexpected or parsing of the Inner Plaintext
/// failed.
class TLSUnexpectedMessage extends TLSProtocolException {
  TLSUnexpectedMessage([String? message]) : super(message);
}

/// The size of the received record was too big.
class TLSRecordOverflow extends TLSProtocolException {
  TLSRecordOverflow([String? message]) : super(message);
}

/// Decryption of the data was unsuccessful.
class TLSDecryptionFailed extends TLSProtocolException {
  TLSDecryptionFailed([String? message]) : super(message);
}

/// Bad MAC (or padding in the case of mac-then-encrypt).
class TLSBadRecordMAC extends TLSProtocolException {
  TLSBadRecordMAC([String? message]) : super(message);
}

/// The parameters selected by the user are too weak.
class TLSInsufficientSecurity extends TLSProtocolException {
  TLSInsufficientSecurity([String? message]) : super(message);
}

/// The PSK or SRP identity is unknown.
class TLSUnknownPSKIdentity extends TLSProtocolException {
  TLSUnknownPSKIdentity([String? message]) : super(message);
}

/// Could not find an acceptable set of handshake parameters.
class TLSHandshakeFailure extends TLSProtocolException {
  TLSHandshakeFailure([String? message]) : super(message);
}

// --- Encryption Errors (Subtypes) ---

/// The maskLen passed to the function is too high.
class MaskTooLongError extends EncryptionError {
  MaskTooLongError([String? message]) : super(message);
}

/// The message passed to the function is too long.
class MessageTooLongError extends EncryptionError {
  MessageTooLongError([String? message]) : super(message);
}

/// An error occurred during encoding.
class EncodingError extends EncryptionError {
  EncodingError([String? message]) : super(message);
}

/// The verification function found an invalid signature.
class InvalidSignature extends EncryptionError {
  InvalidSignature([String? message]) : super(message);
}

/// An unknown RSA algorithm type was passed.
class UnknownRSAType extends EncryptionError {
  UnknownRSAType([String? message]) : super(message);
}
