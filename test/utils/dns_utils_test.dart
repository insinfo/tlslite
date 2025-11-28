import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/dns_utils.dart';

void main() {
  Uint8List ascii(String value) => Uint8List.fromList(value.codeUnits);

  group('isValidHostname', () {
    test('accepts typical hostname', () {
      expect(isValidHostname(ascii('example.com')), isTrue);
    });

    test('rejects dotted decimal IPs', () {
      expect(isValidHostname(ascii('192.168.0.1')), isFalse);
    });

    test('rejects dotted decimal with trailing dot', () {
      expect(isValidHostname(ascii('192.168.0.1.')), isFalse);
    });

    test('accepts ip-like hostname with label suffix', () {
      expect(isValidHostname(ascii('192.168.example.com')), isTrue);
    });

    test('accepts trailing dot root notation', () {
      expect(isValidHostname(ascii('example.com.')), isTrue);
    });

    test('accepts localhost label', () {
      expect(isValidHostname(ascii('localhost')), isTrue);
    });

    test('rejects overly long fqdn', () {
      final longHost = 'a' * 250 + '.example.com';
      expect(isValidHostname(ascii(longHost)), isFalse);
    });

    test('rejects overly long label', () {
      final longLabel = 'a' * 70 + '.example.com';
      expect(isValidHostname(ascii(longLabel)), isFalse);
    });

    test('accepts long but valid labels', () {
      final valid = 'a' * 60 + '.example.com';
      expect(isValidHostname(ascii(valid)), isTrue);
    });
  });
}
