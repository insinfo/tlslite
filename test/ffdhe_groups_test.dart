import 'package:test/test.dart';
import 'package:tlslite/src/ffdhe_groups.dart';

void main() {
  group('FFDHE Groups', () {
    test('RFC 2409 groups are defined', () {
      expect(rfc2409Group1.generator, equals(BigInt.from(2)));
      expect(rfc2409Group1.prime.bitLength, greaterThanOrEqualTo(768));
      expect(rfc2409Group1.prime.bitLength, lessThan(800));

      expect(rfc2409Group2.generator, equals(BigInt.from(2)));
      expect(rfc2409Group2.prime.bitLength, greaterThanOrEqualTo(1024));
      expect(rfc2409Group2.prime.bitLength, lessThan(1100));
    });

    test('RFC 3526 groups are defined', () {
      expect(rfc3526Group5.prime.bitLength, greaterThanOrEqualTo(1536));
      expect(rfc3526Group14.prime.bitLength, greaterThanOrEqualTo(2048));
      expect(rfc3526Group15.prime.bitLength, greaterThanOrEqualTo(3072));
      expect(rfc3526Group16.prime.bitLength, greaterThanOrEqualTo(4096));
      expect(rfc3526Group17.prime.bitLength, greaterThanOrEqualTo(6144));
      expect(rfc3526Group18.prime.bitLength, greaterThanOrEqualTo(8192));
    });

    test('RFC 7919 groups are defined', () {
      expect(ffdhe2048.generator, equals(BigInt.from(2)));
      expect(ffdhe2048.prime.bitLength, greaterThanOrEqualTo(2048));
      expect(ffdhe2048.prime.bitLength, lessThan(2100));

      expect(ffdhe3072.generator, equals(BigInt.from(2)));
      expect(ffdhe3072.prime.bitLength, greaterThanOrEqualTo(3072));
      expect(ffdhe3072.prime.bitLength, lessThan(3100));

      expect(ffdhe4096.generator, equals(BigInt.from(2)));
      expect(ffdhe4096.prime.bitLength, greaterThanOrEqualTo(4096));
      expect(ffdhe4096.prime.bitLength, lessThan(4300));

      expect(ffdhe6144.generator, equals(BigInt.from(2)));
      expect(ffdhe6144.prime.bitLength, greaterThanOrEqualTo(6144));
      expect(ffdhe6144.prime.bitLength, lessThan(6200));

      expect(ffdhe8192.generator, equals(BigInt.from(2)));
      expect(ffdhe8192.prime.bitLength, greaterThanOrEqualTo(8192));
      expect(ffdhe8192.prime.bitLength, lessThan(8300));
    });

    test('ffdheParameters map contains all groups', () {
      expect(ffdheParameters.keys, contains('RFC2409 group 1'));
      expect(ffdheParameters.keys, contains('RFC2409 group 2'));
      expect(ffdheParameters.keys, contains('RFC3526 group 5'));
      expect(ffdheParameters.keys, contains('RFC3526 group 14'));
      expect(ffdheParameters.keys, contains('RFC3526 group 15'));
      expect(ffdheParameters.keys, contains('RFC3526 group 16'));
      expect(ffdheParameters.keys, contains('RFC3526 group 17'));
      expect(ffdheParameters.keys, contains('RFC3526 group 18'));
      expect(ffdheParameters.keys, contains('RFC7919 ffdhe2048'));
      expect(ffdheParameters.keys, contains('RFC7919 ffdhe3072'));
      expect(ffdheParameters.keys, contains('RFC7919 ffdhe4096'));
      expect(ffdheParameters.keys, contains('RFC7919 ffdhe6144'));
      expect(ffdheParameters.keys, contains('RFC7919 ffdhe8192'));
      
      expect(ffdheParameters.length, equals(13));
    });

    test('rfc7919Groups list has 5 entries', () {
      expect(rfc7919Groups.length, equals(5));
      expect(rfc7919Groups[0], equals(ffdhe2048));
      expect(rfc7919Groups[1], equals(ffdhe3072));
      expect(rfc7919Groups[2], equals(ffdhe4096));
      expect(rfc7919Groups[3], equals(ffdhe6144));
      expect(rfc7919Groups[4], equals(ffdhe8192));
    });

    test('all groups have odd primes', () {
      for (final group in ffdheParameters.values) {
        expect(group.prime.isOdd, isTrue, reason: '${group.name} prime should be odd');
      }
    });

    test('all primes are greater than generators', () {
      for (final group in ffdheParameters.values) {
        expect(group.prime, greaterThan(group.generator), 
            reason: '${group.name} prime should be > generator');
      }
    });

    test('generator^2 mod prime != 1 (basic DH safety)', () {
      // Basic sanity check: g^2 mod p should not equal 1
      for (final group in rfc7919Groups) {
        final g2 = (group.generator * group.generator) % group.prime;
        expect(g2, isNot(equals(BigInt.one)),
            reason: '${group.name} fails basic DH safety check');
      }
    });

    test('RFC 7919 groups are recommended for TLS', () {
      // RFC 7919 groups should all be 2048 bits or larger
      for (final group in rfc7919Groups) {
        expect(group.prime.bitLength, greaterThanOrEqualTo(2048),
            reason: '${group.name} should be at least 2048 bits');
      }
    });
  });
}
