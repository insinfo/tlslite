/// X.509 certificate path validation and host name verification.
///
/// This library does not use `dart:io`; see `x509_trust_store.dart` for
/// helpers that load trust anchors from disk.
library;

import 'dart:typed_data';

import 'checker.dart';
import 'errors.dart';
import 'utils/pem.dart';
import 'x509.dart';
import 'x509certchain.dart';

/// OID of the id-kp-serverAuth extended key usage (TLS server).
const String oidServerAuth = '1.3.6.1.5.5.7.3.1';

/// OID of the id-kp-clientAuth extended key usage (TLS client).
const String oidClientAuth = '1.3.6.1.5.5.7.3.2';

/// OID of anyExtendedKeyUsage.
const String oidAnyExtendedKeyUsage = '2.5.29.37.0';

/// Extensions the validator either enforces or may safely ignore for TLS
/// server authentication (policy extensions are not processed, as in most
/// TLS stacks: the relying party does not require a specific policy).
const Set<String> _handledCriticalExtensions = {
  '2.5.29.15', // keyUsage
  '2.5.29.17', // subjectAltName
  '2.5.29.19', // basicConstraints
  '2.5.29.30', // nameConstraints
  '2.5.29.37', // extendedKeyUsage
  '2.5.29.32', // certificatePolicies
  '2.5.29.33', // policyMappings
  '2.5.29.36', // policyConstraints
  '2.5.29.54', // inhibitAnyPolicy
};

/// Parses every `CERTIFICATE` block of a PEM bundle (e.g. a CA bundle such
/// as `/etc/ssl/cert.pem`).
///
/// Blocks of other types (keys, CRLs, `TRUSTED CERTIFICATE`, ...) and text
/// between blocks are ignored. Certificates that cannot be parsed (for
/// instance because they use a curve or algorithm tlslite does not support)
/// are skipped, unless [strict] is true, in which case the parse error is
/// rethrown.
List<X509> loadPemCertificates(String pem, {bool strict = false}) {
  final result = <X509>[];
  for (final der in dePemList(pem, 'CERTIFICATE')) {
    try {
      result.add(X509()..parseBinary(der));
    } catch (_) {
      if (strict) rethrow;
    }
  }
  return result;
}

/// Validates X.509 server (or client) certificate chains against a set of
/// trust anchors, similar to what `dart:io` `SecureSocket` does.
///
/// Checks performed:
///  * path building from the leaf to a trust anchor, looking up issuers by
///    raw DER subject/issuer name among the presented certificates and the
///    anchors (with backtracking, loop protection and a maximum depth);
///  * the signature of every certificate on the path (RSA PKCS#1 v1.5,
///    RSA-PSS, ECDSA, DSA, EdDSA);
///  * notBefore/notAfter of every certificate on the path (anchors included);
///  * basicConstraints cA=true and pathLenConstraint for every issuer,
///    keyUsage keyCertSign when keyUsage is present;
///  * extendedKeyUsage of the leaf ([requiredExtendedKeyUsage], serverAuth
///    by default) when the leaf has an EKU extension;
///  * DNS / IP nameConstraints of issuers against the leaf's names;
///  * rejection of unknown critical extensions;
///  * optionally the host name (RFC 6125: subjectAltName dNSName with a
///    single left-most wildcard label, iPAddress for IP literals, subject CN
///    only when the certificate has no DNS/IP subjectAltName at all).
///
/// A chain is trusted when the path reaches a certificate that is byte-equal
/// to an anchor, or that has the same subject and public key as an anchor.
/// A self-signed leaf is therefore trusted only when it is itself an anchor
/// (certificate pinning of a self-signed server certificate).
///
/// Revocation (CRL/OCSP) is not checked.
///
/// Usage after a handshake:
/// ```dart
/// final validator = X509Validator(loadSystemTrustAnchors() ?? const []);
/// await conn.handshakeClient(serverName: host);
/// validator.validate(conn.session.serverCertChain, hostname: host);
/// ```
///
/// Or during the handshake (preferred; a fatal alert is sent and the
/// handshake aborts before application data is exchanged):
/// ```dart
/// await conn.handshakeClient(
///   serverName: host,
///   checker: validator.checker(hostname: host),
/// );
/// ```
class X509Validator {
  /// Creates a validator trusting [trustAnchors].
  ///
  /// [maxDepth] bounds the number of certificates on a path (leaf and anchor
  /// included). [requiredExtendedKeyUsage] is the purpose the leaf must allow
  /// when it carries an EKU extension (use [oidClientAuth] to validate client
  /// certificates, or `null` to skip the EKU check). Set
  /// [allowUnknownCriticalExtensions] to accept certificates with critical
  /// extensions the validator does not understand (not recommended).
  X509Validator(
    Iterable<X509> trustAnchors, {
    this.maxDepth = 10,
    this.requiredExtendedKeyUsage = oidServerAuth,
    this.allowUnknownCriticalExtensions = false,
  }) : trustAnchors = List<X509>.unmodifiable(trustAnchors);

  /// The trusted root certificates.
  final List<X509> trustAnchors;

  /// Maximum number of certificates on a validated path.
  final int maxDepth;

  /// EKU OID the leaf must contain when it has an EKU extension.
  final String? requiredExtendedKeyUsage;

  /// Whether unknown critical extensions are tolerated.
  final bool allowUnknownCriticalExtensions;

  /// Returns a [Checker] that validates the peer's chain with this validator.
  ///
  /// Pass it to `TlsConnection.handshakeClient(checker: ...)`. When
  /// [hostname] is null the host name is not checked (only the chain).
  X509ValidatorChecker checker({String? hostname, DateTime Function()? clock}) =>
      X509ValidatorChecker(this, hostname: hostname, clock: clock);

  /// Validates [chain] (leaf first, as sent by the peer) and returns the
  /// verified path, from the leaf to the trust anchor (inclusive).
  ///
  /// [hostname] is a DNS name or an IP literal (IPv6 optionally in brackets);
  /// when null the host name check is skipped. [now] defaults to the current
  /// UTC time.
  ///
  /// Throws [TLSCertificateVerificationError] describing the first problem
  /// found.
  List<X509> validate(X509CertChain? chain, {String? hostname, DateTime? now}) {
    if (chain == null || chain.x509List.isEmpty) {
      throw TLSCertificateVerificationError(
          CertificateVerificationFailure.noCertificate,
          'peer did not present a certificate');
    }
    return validateCertificates(chain.x509List, hostname: hostname, now: now);
  }

  /// Same as [validate] but takes the certificates as a list (leaf first).
  List<X509> validateCertificates(List<X509> certificates,
      {String? hostname, DateTime? now}) {
    if (certificates.isEmpty) {
      throw TLSCertificateVerificationError(
          CertificateVerificationFailure.noCertificate,
          'peer did not present a certificate');
    }
    final time = (now ?? DateTime.now()).toUtc();
    final leaf = certificates.first;
    final intermediates = certificates.skip(1).toList();

    _checkValidity(leaf, time);
    _checkCriticalExtensions(leaf);
    _checkLeafUsage(leaf);

    final search = _PathSearch(this, intermediates, time);
    final path = search.build(leaf);
    if (path == null) {
      throw search.bestError ??
          TLSCertificateVerificationError(
              CertificateVerificationFailure.unknownIssuer,
              'unable to find the issuer of "${leaf.issuerString}"',
              certificate: leaf);
    }

    if (hostname != null) {
      verifyHostname(leaf, hostname);
    }
    return path;
  }

  /// Throws [TLSCertificateVerificationError] if [cert] does not match
  /// [hostname] (see [matchesHostname]).
  static void verifyHostname(X509 cert, String hostname) {
    if (!matchesHostname(cert, hostname)) {
      final names = <String>[
        ...?cert.dnsNames,
        for (final ip in cert.ipAddresses ?? const <Uint8List>[])
          _formatIp(ip),
      ];
      final presented = names.isNotEmpty
          ? 'subjectAltName ${names.join(', ')}'
          : 'CN ${cert.subjectCommonNames.join(', ')}';
      throw TLSCertificateVerificationError(
          CertificateVerificationFailure.hostnameMismatch,
          'certificate is not valid for "$hostname" (certificate has '
          '$presented)',
          certificate: cert);
    }
  }

  /// Whether [cert] is valid for [hostname] (DNS name or IP literal).
  ///
  /// DNS names are compared case-insensitively against subjectAltName
  /// dNSName entries; a `*` is only honoured as the complete left-most label
  /// and matches exactly one label (`*.example.com` matches
  /// `a.example.com`, not `example.com` nor `a.b.example.com`). IP literals
  /// only match iPAddress entries (never wildcards). The subject common name
  /// is consulted only when the certificate has no DNS or IP subjectAltName
  /// at all.
  static bool matchesHostname(X509 cert, String hostname) {
    var host = hostname.trim();
    if (host.startsWith('[') && host.endsWith(']')) {
      host = host.substring(1, host.length - 1);
    }
    final ip = parseIpAddress(host);
    final dnsNames = cert.dnsNames ?? const <String>[];
    final ipAddresses = cert.ipAddresses ?? const <Uint8List>[];
    final hasSan = dnsNames.isNotEmpty || ipAddresses.isNotEmpty;

    if (ip != null) {
      if (hasSan) {
        return ipAddresses.any((candidate) => _bytesEqual(candidate, ip));
      }
      return cert.subjectCommonNames.any((cn) {
        final cnIp = parseIpAddress(cn.trim());
        return cnIp != null && _bytesEqual(cnIp, ip);
      });
    }

    final normalizedHost = _normalizeDns(host);
    if (normalizedHost.isEmpty) return false;
    final patterns = hasSan ? dnsNames : cert.subjectCommonNames;
    return patterns.any((p) => _matchDnsPattern(_normalizeDns(p), normalizedHost));
  }

  /// Parses an IPv4 dotted-quad or IPv6 literal (optionally with a zone id,
  /// which is ignored) into network-order bytes; returns null if [text] is
  /// not an IP literal.
  static Uint8List? parseIpAddress(String text) {
    if (text.isEmpty) return null;
    if (RegExp(r'^\d{1,3}(\.\d{1,3}){3}$').hasMatch(text)) {
      final parts = text.split('.').map(int.parse).toList();
      if (parts.any((p) => p > 255)) return null;
      return Uint8List.fromList(parts);
    }
    if (text.contains(':')) {
      final zone = text.indexOf('%');
      final addr = zone >= 0 ? text.substring(0, zone) : text;
      try {
        return Uint8List.fromList(Uri.parseIPv6Address(addr));
      } on FormatException {
        return null;
      }
    }
    return null;
  }

  // ---------------------------------------------------------------------

  void _checkValidity(X509 cert, DateTime now) {
    final notBefore = cert.notBefore;
    final notAfter = cert.notAfter;
    if (notBefore != null && now.isBefore(notBefore)) {
      throw TLSCertificateVerificationError(
          CertificateVerificationFailure.notYetValid,
          'certificate "${cert.subjectString}" is not valid before '
          '${notBefore.toIso8601String()}',
          certificate: cert);
    }
    if (notAfter != null && now.isAfter(notAfter)) {
      throw TLSCertificateVerificationError(
          CertificateVerificationFailure.expired,
          'certificate "${cert.subjectString}" expired on '
          '${notAfter.toIso8601String()}',
          certificate: cert);
    }
  }

  void _checkCriticalExtensions(X509 cert) {
    if (allowUnknownCriticalExtensions) return;
    for (final oid in cert.criticalExtensions) {
      if (!_handledCriticalExtensions.contains(oid)) {
        throw TLSCertificateVerificationError(
            CertificateVerificationFailure.unhandledCriticalExtension,
            'certificate "${cert.subjectString}" has an unsupported critical '
            'extension $oid',
            certificate: cert);
      }
    }
  }

  void _checkLeafUsage(X509 leaf) {
    final required = requiredExtendedKeyUsage;
    final eku = leaf.extendedKeyUsage;
    if (required != null &&
        eku != null &&
        !eku.contains(required) &&
        !eku.contains(oidAnyExtendedKeyUsage)) {
      throw TLSCertificateVerificationError(
          CertificateVerificationFailure.extendedKeyUsage,
          'certificate "${leaf.subjectString}" extendedKeyUsage does not '
          'allow $required (has ${eku.join(', ')})',
          certificate: leaf);
    }
  }

  /// Checks [issuer] may issue certificates, given [caBelow] non-self-issued
  /// CA certificates between it and the leaf.
  void _checkIssuer(X509 issuer, int caBelow, X509 leaf, {required bool anchor}) {
    // Explicitly trusted anchors without a basicConstraints extension
    // (legacy X.509v1 roots) are accepted; a v3 cA=false is not.
    final isCA = issuer.isCA;
    if (isCA != true && !(anchor && isCA == null)) {
      throw TLSCertificateVerificationError(
          CertificateVerificationFailure.notCA,
          'issuer "${issuer.subjectString}" is not a CA certificate',
          certificate: issuer);
    }
    final pathLen = issuer.pathLenConstraint;
    if (pathLen != null && caBelow > pathLen) {
      throw TLSCertificateVerificationError(
          CertificateVerificationFailure.pathLengthExceeded,
          'issuer "${issuer.subjectString}" pathLenConstraint $pathLen '
          'exceeded',
          certificate: issuer);
    }
    final keyUsage = issuer.keyUsage;
    if (keyUsage != null && !keyUsage.contains('keyCertSign')) {
      throw TLSCertificateVerificationError(
          CertificateVerificationFailure.keyUsage,
          'issuer "${issuer.subjectString}" keyUsage does not allow '
          'keyCertSign',
          certificate: issuer);
    }
    _checkCriticalExtensions(issuer);
    _checkNameConstraints(issuer, leaf);
  }

  void _checkNameConstraints(X509 issuer, X509 leaf) {
    final permittedDns = issuer.permittedDnsNames;
    final excludedDns = issuer.excludedDnsNames;
    final permittedIp = issuer.permittedIpRanges;
    final excludedIp = issuer.excludedIpRanges;
    if (permittedDns == null &&
        excludedDns == null &&
        permittedIp == null &&
        excludedIp == null) {
      return;
    }
    final dnsNames = leaf.dnsNames ?? const <String>[];
    final ips = leaf.ipAddresses ?? const <Uint8List>[];
    final names = <String>[...dnsNames];
    if (dnsNames.isEmpty && ips.isEmpty) {
      // Names used by the CN fallback are subject to DNS constraints too.
      names.addAll(leaf.subjectCommonNames
          .where((cn) => parseIpAddress(cn) == null && cn.contains('.')));
    }
    void fail(String name) => throw TLSCertificateVerificationError(
        CertificateVerificationFailure.nameConstraints,
        'name "$name" violates the name constraints of '
        '"${issuer.subjectString}"',
        certificate: leaf);

    for (final name in names) {
      final n = _normalizeDns(name);
      if (excludedDns != null &&
          excludedDns.any((c) => _dnsWithinConstraint(n, c))) {
        fail(name);
      }
      if (permittedDns != null &&
          permittedDns.isNotEmpty &&
          !permittedDns.any((c) => _dnsWithinConstraint(n, c))) {
        fail(name);
      }
    }
    for (final ip in ips) {
      if (excludedIp != null && excludedIp.any((r) => _ipInRange(ip, r))) {
        fail(_formatIp(ip));
      }
      if (permittedIp != null) {
        final sameFamily =
            permittedIp.where((r) => r.length == ip.length * 2).toList();
        if (sameFamily.isNotEmpty && !sameFamily.any((r) => _ipInRange(ip, r))) {
          fail(_formatIp(ip));
        }
      }
    }
  }

  bool _isAnchor(X509 cert) {
    for (final anchor in trustAnchors) {
      if (_bytesEqual(anchor.bytes, cert.bytes)) return true;
      if (_sameSubjectAndKey(anchor, cert)) return true;
    }
    return false;
  }
}

/// A [Checker] that runs an [X509Validator] on the peer's certificate chain.
///
/// Pass it to `TlsConnection.handshakeClient(checker: ...)`: it is invoked as
/// soon as the server's Certificate message is processed (before the
/// handshake completes), and on failure the connection sends a fatal alert
/// and `handshakeClient` throws [TLSCertificateVerificationError].
///
/// When [Checker.x509Fingerprint] is also given, both checks must pass.
class X509ValidatorChecker extends Checker {
  X509ValidatorChecker(
    this.validator, {
    this.hostname,
    this.clock,
    super.x509Fingerprint,
    super.checkResumedSession,
  });

  /// The validator used to check the chain.
  final X509Validator validator;

  /// Expected host name (DNS name or IP literal); null skips the check.
  final String? hostname;

  /// Source of the current time; defaults to `DateTime.now()`.
  final DateTime Function()? clock;

  @override
  void call(dynamic connection) {
    if (!checkResumedSession && _isResumed(connection)) {
      return;
    }
    super.call(connection);
    final X509CertChain? chain = connection.client == true
        ? connection.session.serverCertChain
        : connection.session.clientCertChain;
    validator.validate(chain, hostname: hostname, now: clock?.call());
  }

  static bool _isResumed(dynamic connection) {
    try {
      return connection.resumed == true;
    } on NoSuchMethodError {
      return false;
    }
  }
}

/// Depth-first path builder with backtracking.
class _PathSearch {
  _PathSearch(this.validator, this.intermediates, this.now);

  final X509Validator validator;
  final List<X509> intermediates;
  final DateTime now;
  TLSCertificateVerificationError? bestError;

  void _record(TLSCertificateVerificationError error) {
    // Prefer specific errors over "unknown issuer".
    final current = bestError;
    if (current == null ||
        (current.reason == CertificateVerificationFailure.unknownIssuer &&
            error.reason != CertificateVerificationFailure.unknownIssuer)) {
      bestError = error;
    }
  }

  List<X509>? build(X509 leaf) {
    if (validator._isAnchor(leaf)) return [leaf];
    return _extend([leaf]);
  }

  List<X509>? _extend(List<X509> path) {
    final cert = path.last;
    final leaf = path.first;
    final issuerName = cert.issuer;
    if (issuerName == null) {
      _record(TLSCertificateVerificationError(
          CertificateVerificationFailure.malformed,
          'certificate has no issuer name',
          certificate: cert));
      return null;
    }
    final selfIssued = _bytesEqual(issuerName, cert.subject ?? Uint8List(0));

    final candidates = <(X509, bool)>[
      for (final a in validator.trustAnchors)
        if (_bytesEqual(a.subject ?? Uint8List(0), issuerName)) (a, true),
      for (final c in intermediates)
        if (_bytesEqual(c.subject ?? Uint8List(0), issuerName) &&
            !path.any((p) => _bytesEqual(p.bytes, c.bytes)) &&
            !path.any((p) => _sameSubjectAndKey(p, c)))
          (c, false),
    ];

    if (candidates.isEmpty) {
      if (selfIssued && path.length == 1) {
        _record(TLSCertificateVerificationError(
            CertificateVerificationFailure.selfSigned,
            'self-signed certificate "${cert.subjectString}" is not trusted',
            certificate: cert));
      } else {
        _record(TLSCertificateVerificationError(
            CertificateVerificationFailure.unknownIssuer,
            'unable to find the issuer "${cert.issuerString}" of '
            '"${cert.subjectString}" among the trust anchors',
            certificate: cert));
      }
      return null;
    }

    if (path.length + 1 > validator.maxDepth) {
      _record(TLSCertificateVerificationError(
          CertificateVerificationFailure.chainTooLong,
          'certificate chain exceeds the maximum depth of '
          '${validator.maxDepth}',
          certificate: cert));
      return null;
    }

    for (final (candidate, isAnchor) in candidates) {
      final key = candidate.publicKey;
      bool signatureOk;
      try {
        signatureOk = key != null && cert.verify(key);
      } catch (_) {
        signatureOk = false;
      }
      if (!signatureOk) {
        _record(TLSCertificateVerificationError(
            cert.signatureKind == null
                ? CertificateVerificationFailure.malformed
                : CertificateVerificationFailure.badSignature,
            cert.signatureKind == null
                ? 'unsupported signature algorithm on "${cert.subjectString}"'
                : 'signature of "${cert.subjectString}" does not verify with '
                    'the key of "${candidate.subjectString}"',
            certificate: cert));
        continue;
      }
      // Number of CA certificates between the candidate and the leaf
      // (self-issued intermediates do not count, RFC 5280 4.2.1.9).
      var caBelow = 0;
      for (var i = 1; i < path.length; i++) {
        final p = path[i];
        if (!_bytesEqual(p.issuer ?? Uint8List(0), p.subject ?? Uint8List(1))) {
          caBelow++;
        }
      }
      try {
        validator._checkValidity(candidate, now);
        validator._checkIssuer(candidate, caBelow, leaf, anchor: isAnchor);
      } on TLSCertificateVerificationError catch (e) {
        _record(e);
        continue;
      }
      final extended = [...path, candidate];
      if (isAnchor) return extended;
      if (validator._isAnchor(candidate)) return extended;
      final result = _extend(extended);
      if (result != null) return result;
    }
    return null;
  }
}

bool _sameSubjectAndKey(X509 a, X509 b) {
  final sa = a.subject, sb = b.subject;
  final ka = a.subjectPublicKey, kb = b.subjectPublicKey;
  if (sa == null || sb == null || ka == null || kb == null) return false;
  return a.certAlg == b.certAlg && _bytesEqual(sa, sb) && _bytesEqual(ka, kb);
}

bool _bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

String _normalizeDns(String name) {
  var n = name.trim().toLowerCase();
  while (n.endsWith('.')) {
    n = n.substring(0, n.length - 1);
  }
  return n;
}

bool _matchDnsPattern(String pattern, String host) {
  if (pattern.isEmpty) return false;
  if (!pattern.contains('*')) return pattern == host;
  // Only "*.<at least two labels>" is accepted.
  if (!pattern.startsWith('*.')) return false;
  final suffix = pattern.substring(2);
  if (suffix.contains('*') || !suffix.contains('.')) return false;
  if (X509Validator.parseIpAddress(host) != null) return false;
  final dot = host.indexOf('.');
  if (dot <= 0) return false;
  return host.substring(dot + 1) == suffix;
}

/// RFC 5280 4.2.1.10 DNS constraint: "example.com" covers the name itself and
/// its subdomains; ".example.com" covers subdomains only.
bool _dnsWithinConstraint(String name, String constraint) {
  final c = _normalizeDns(constraint);
  if (c.isEmpty) return true;
  final n = name.startsWith('*.') ? name.substring(2) : name;
  if (c.startsWith('.')) return n.endsWith(c);
  return n == c || n.endsWith('.$c');
}

bool _ipInRange(Uint8List ip, Uint8List range) {
  if (range.length != ip.length * 2) return false;
  for (var i = 0; i < ip.length; i++) {
    final mask = range[ip.length + i];
    if ((ip[i] & mask) != (range[i] & mask)) return false;
  }
  return true;
}

String _formatIp(Uint8List ip) {
  if (ip.length == 4) return ip.join('.');
  final parts = <String>[];
  for (var i = 0; i + 1 < ip.length; i += 2) {
    parts.add(((ip[i] << 8) | ip[i + 1]).toRadixString(16));
  }
  return parts.join(':');
}
