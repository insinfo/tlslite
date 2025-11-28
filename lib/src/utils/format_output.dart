/// Formatting helpers ported from tlslite's Python utilities.

/// Returns [text] when it is neither null nor empty; otherwise produces
/// `'unknown(number)'` with the supplied [number].
String noneAsUnknown(String? text, int number) {
  if (text == null || text.isEmpty) {
    return 'unknown($number)';
  }
  return text;
}
