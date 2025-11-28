import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/constanttime.dart';

void main() {
  group('ctLtU32/ctGtU32/ctLeU32', () {
    test('basic ordering works on small values', () {
      expect(ctLtU32(1, 2), 1);
      expect(ctLtU32(2, 1), 0);
      expect(ctGtU32(2, 1), 1);
      expect(ctLeU32(2, 2), 1);
      expect(ctLeU32(3, 2), 0);
    });

    test('properly masks to 32 bits', () {
      const high = 0xffffffff;
      expect(ctLtU32(high, 0), 0);
      expect(ctGtU32(high, 0), 1);
      expect(ctLeU32(high, high), 1);
    });
  });

  group('ctLsb propagation', () {
    test('ctLsbPropU8 expands bit', () {
      expect(ctLsbPropU8(1), 0xff);
      expect(ctLsbPropU8(0), 0x00);
    });

    test('ctLsbPropU16 expands bit', () {
      expect(ctLsbPropU16(1), 0xffff);
      expect(ctLsbPropU16(0), 0x0000);
    });
  });

  group('ctIsNonZero/ctEq/ctNeq', () {
    test('detects zero and non-zero', () {
      expect(ctIsNonZeroU32(0), 0);
      expect(ctIsNonZeroU32(7), 1);
    });

    test('equality helpers', () {
      expect(ctEqU32(5, 5), 1);
      expect(ctEqU32(5, 6), 0);
      expect(ctNeqU32(5, 6), 1);
      expect(ctNeqU32(5, 5), 0);
    });
  });

  group('ctCompareDigest', () {
    test('returns true for equal buffers', () {
      final left = Uint8List.fromList([1, 2, 3, 4]);
      final right = Uint8List.fromList([1, 2, 3, 4]);
      expect(ctCompareDigest(left, right), isTrue);
    });

    test('returns false for different lengths', () {
      final left = Uint8List.fromList([1, 2, 3]);
      final right = Uint8List.fromList([1, 2, 3, 4]);
      expect(ctCompareDigest(left, right), isFalse);
    });

    test('returns false for mismatched contents', () {
      final left = Uint8List.fromList([1, 2, 3, 4]);
      final right = Uint8List.fromList([1, 2, 3, 5]);
      expect(ctCompareDigest(left, right), isFalse);
    });
  });
}
