// Ported to Dart from tlslite-ng tlslite/utils/dns_utils.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:convert'; // For ascii
import 'dart:typed_data'; // For Uint8List

/// Checks whether the argument is a valid DNS hostname.
///
/// Follows common validation rules, including RFC 1035/1123 for characters
/// and structure.
///
/// [hostnameInput]: the String or Uint8List (assumed to be ASCII) to check.
/// Returns `true` if it is a valid hostname, `false` otherwise.
bool isValidHostname(Object hostnameInput) {
  String hostname;

  // 1. Handle the input type and decode it if it is a Uint8List (ASCII)
  if (hostnameInput is String) {
    hostname = hostnameInput;
  } else if (hostnameInput is Uint8List) {
    try {
      // Try to decode as strict ASCII
      hostname = ascii.decode(hostnameInput, allowInvalid: false);
    } on FormatException {
      return false; // ASCII decoding failed
    }
  } else {
    // Invalid input type
    return false;
    // Alternatively, this could throw an ArgumentError:
    // throw ArgumentError("Input must be a String or Uint8List representing ASCII");
  }

  // The hostname cannot be empty after decoding
  if (hostname.isEmpty) {
    return false;
  }

  // 2. Strip a trailing dot, if present
  // FQDN hostnames may end with '.', representing the root.
  // For label validation, we remove that trailing dot.
  if (hostname.endsWith('.')) {
    hostname = hostname.substring(0, hostname.length - 1);
    // If the hostname was just '.', it is now empty, which is invalid
    if (hostname.isEmpty) {
      return false;
    }
  }

  // 3. Check the total length (RFC 1035)
  // The maximum total length of a hostname in its text representation
  // (with dots) is 253 characters (excluding the trailing root dot).
  if (hostname.length > 253) {
    return false;
  }

  // 4. Reject all-numeric names with dots (to avoid confusion with IP addresses)
  // This is not a strict RFC rule, but a common practice.
  final numericRegex = RegExp(r'^[\d.]+$');
  if (numericRegex.hasMatch(hostname)) {
    return false;
  }

  // 5. Validate each label individually
  final labels = hostname.split('.');

  // There must be no empty labels (e.g. "host..name")
  if (labels.any((label) => label.isEmpty)) {
    return false;
  }

  // Regex for the characters allowed in each label (RFC 1123 extends RFC 952/1035)
  // Allows letters (a-z, A-Z), digits (0-9) and hyphen (-)
  // Length from 1 to 63 characters.
  // Leading/trailing hyphens are not checked here; that is done separately.
  final labelRegex = RegExp(r'^[a-zA-Z0-9-]{1,63}$');

  // Check each label
  return labels.every((label) {
    // Check characters and length with the regex
    if (!labelRegex.hasMatch(label)) {
      return false;
    }
    // Check whether the label starts or ends with a hyphen (RFC 1123)
    if (label.startsWith('-') || label.endsWith('-')) {
      return false;
    }
    // The label passed all checks
    return true;
  });
}
