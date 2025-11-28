import 'package:test/test.dart';
import 'package:tlslite/src/utils/format_output.dart';

void main() {
  group('noneAsUnknown', () {
    test('returns provided text when not empty', () {
      expect(noneAsUnknown('cipher', 42), 'cipher');
    });

    test('returns unknown text when null', () {
      expect(noneAsUnknown(null, 7), 'unknown(7)');
    });

    test('returns unknown text when empty', () {
      expect(noneAsUnknown('', 99), 'unknown(99)');
    });
  });
}
