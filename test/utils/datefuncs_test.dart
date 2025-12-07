import 'package:test/test.dart';
import 'package:tlslite/src/utils/date_funcs.dart';

void main() {
  group('datefuncs', () {
    test('parseDateClass handles fractional seconds and UTC suffix', () {
      final dateTime = parseDateClass('2025-11-28T12:34:56.789Z');
      expect(dateTime.year, 2025);
      expect(dateTime.month, 11);
      expect(dateTime.day, 28);
      expect(dateTime.hour, 12);
      expect(dateTime.minute, 34);
      expect(dateTime.second, 56);
      expect(dateTime.isUtc, isTrue);
    });

    test('printDateClass emits canonical UTC representation', () {
      final dt = createDateClass(2024, 1, 2, 3, 4, 5);
      expect(printDateClass(dt), '2024-01-02T03:04:05Z');
    });

    test('getHoursFromNow advances at least requested hours', () {
      final now = getNow();
      final future = getHoursFromNow(2);
      expect(future.isAfter(now), isTrue);
      final diff = future.difference(now);
      expect(diff.inHours, greaterThanOrEqualTo(2));
      expect(diff.inHours, lessThanOrEqualTo(3));
    });

    test('getMinutesFromNow advances at least requested minutes', () {
      final now = getNow();
      final future = getMinutesFromNow(45);
      expect(future.isAfter(now), isTrue);
      final diff = future.difference(now);
      expect(diff.inMinutes, greaterThanOrEqualTo(45));
      expect(diff.inMinutes, lessThanOrEqualTo(46));
    });

    test('isDateClassExpired detects past timestamps', () {
      final past = getNow().subtract(const Duration(minutes: 1));
      final future = getNow().add(const Duration(minutes: 1));
      expect(isDateClassExpired(past), isTrue);
      expect(isDateClassExpired(future), isFalse);
    });

    test('isDateClassBefore compares chronological order', () {
      final earlier = createDateClass(2023, 6, 1, 0, 0, 0);
      final later = createDateClass(2024, 6, 1, 0, 0, 0);
      expect(isDateClassBefore(earlier, later), isTrue);
      expect(isDateClassBefore(later, earlier), isFalse);
    });
  });
}
