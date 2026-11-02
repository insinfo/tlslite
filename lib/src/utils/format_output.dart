// Ported to Dart from tlslite-ng tlslite/utils/format_output.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

/// Formatting helpers 

/// Returns [text] when it is neither null nor empty; otherwise produces
/// `'unknown(number)'` with the supplied [number].
String noneAsUnknown(String? text, int number) {
  if (text == null || text.isEmpty) {
    return 'unknown($number)';
  }
  return text;
}
