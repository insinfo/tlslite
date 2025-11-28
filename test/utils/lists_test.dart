import 'package:test/test.dart';
import 'package:tlslite/src/utils/lists.dart';

void main() {
  group('getFirstMatching', () {
    test('returns null when values is null', () {
      expect(getFirstMatching(null, [1, 2, 3]), isNull);
    });

    test('returns first matching element', () {
      final values = [3, 2, 1];
      final matches = {2, 4};
      expect(getFirstMatching(values, matches), 2);
    });

    test('returns last matching element when earlier ones missing', () {
      final values = [7, 8, 9, 1];
      expect(getFirstMatching(values, const [1, 2, 3]), 1);
    });

    test('returns null when nothing matches', () {
      expect(getFirstMatching([1, 2], const [3, 4]), isNull);
    });

    test('returns null when matches is empty', () {
      expect(getFirstMatching([1, 2, 3], const []), isNull);
    });

    test('throws AssertionError when matches is null', () {
      expect(() => getFirstMatching([1, 2, 3], null), throwsA(isA<AssertionError>()));
    });
  });

  group('toStrDelimiter', () {
    test('handles empty iterables', () {
      expect(toStrDelimiter(const []), '');
    });

    test('handles single value', () {
      expect(toStrDelimiter(const ['apple']), 'apple');
    });

    test('handles two values', () {
      expect(toStrDelimiter(const ['apple', 'banana']), 'apple or banana');
    });

    test('handles three or more values', () {
      expect(
        toStrDelimiter(const ['apple', 'banana', 'cherry']),
        'apple, banana or cherry',
      );
    });

    test('supports custom delimiters', () {
      expect(
        toStrDelimiter(const [1, 2, 3], delim: ' / ', lastDelim: ' & '),
        '1 / 2 & 3',
      );
    });
  });
}
