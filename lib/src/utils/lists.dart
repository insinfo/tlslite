/// Helper utilities for working with lists and iterable collections.
/// Ported from tlslite-ng/tlslite/utils/lists.py.

/// Returns the first element from [values] that is also present in [matches].
/// If no element matches (or [values] is null/empty) this returns null.
T? getFirstMatching<T>(Iterable<T>? values, Iterable<T>? matches) {
  if (values == null) {
    return null;
  }
  if (matches == null) {
    throw AssertionError('matches cannot be null');
  }
  if (matches.isEmpty) {
    return null;
  }
  final matchSet = matches is Set<T> ? matches : matches.toSet();
  for (final value in values) {
    if (matchSet.contains(value)) {
      return value;
    }
  }
  return null;
}

/// Formats [values] as a human-readable list separated by [delim] and [lastDelim].
/// Mimics the behavior of tlslite's to_str_delimiter helper.
String toStrDelimiter(
  Iterable<dynamic> values, {
  String delim = ', ',
  String lastDelim = ' or ',
}) {
  final items = values.map((value) => value.toString()).toList(growable: false);
  if (items.isEmpty) {
    return '';
  }
  if (items.length == 1) {
    return items.first;
  }
  if (items.length == 2) {
    return '${items[0]}$lastDelim${items[1]}';
  }

  final head = items.sublist(0, items.length - 2);
  final tail = '${items[items.length - 2]}$lastDelim${items.last}';
  return [...head, tail].join(delim);
}
