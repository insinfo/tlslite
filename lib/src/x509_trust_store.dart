/// Loading of trust anchors from the operating system (uses `dart:io`).
library;

import 'dart:io';

import 'x509.dart';
import 'x509_validator.dart';

/// Well-known locations of the system CA bundle, in lookup order.
const List<String> systemTrustBundlePaths = [
  '/etc/ssl/cert.pem', // macOS, Alpine, OpenBSD
  '/etc/ssl/certs/ca-certificates.crt', // Debian, Ubuntu, Arch, Gentoo
  '/etc/pki/tls/certs/ca-bundle.crt', // RHEL, Fedora, CentOS
  '/etc/ssl/ca-bundle.pem', // openSUSE
  '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem', // RHEL 7+
];

/// Loads the system trust anchors from a PEM CA bundle.
///
/// The file named by the `SSL_CERT_FILE` environment variable is used when it
/// exists; otherwise the first existing file of [systemTrustBundlePaths].
/// Returns null when no bundle is found (for example on Windows, where the
/// certificate store is not exposed as a PEM file) or when the bundle holds
/// no parseable certificate. Certificates tlslite cannot parse are skipped.
List<X509>? loadSystemTrustAnchors() {
  final candidates = <String>[
    if (Platform.environment['SSL_CERT_FILE'] case final env?
        when env.isNotEmpty)
      env,
    ...systemTrustBundlePaths,
  ];
  for (final path in candidates) {
    final file = File(path);
    String text;
    try {
      if (!file.existsSync()) continue;
      text = file.readAsStringSync();
    } on FileSystemException {
      continue;
    }
    final anchors = loadPemCertificates(text);
    if (anchors.isNotEmpty) return anchors;
  }
  return null;
}

/// Reads a PEM file holding one or more certificates (see
/// [loadPemCertificates]).
List<X509> loadPemCertificatesFromFile(String path, {bool strict = false}) =>
    loadPemCertificates(File(path).readAsStringSync(), strict: strict);
