import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/poly1305.dart';

void main() {
  group('Poly1305', () {
    test('constructor accepts 32-byte key', () {
      expect(() => Poly1305(Uint8List(32)), returnsNormally);
    });

    test('constructor rejects invalid key size', () {
      expect(() => Poly1305(Uint8List(16)), throwsArgumentError);
    });

    test('leBytesToNum matches Python helper', () {
      expect(Poly1305.leBytesToNum(hex('04030201')),
          equals(BigInt.from(0x01020304)));
      expect(Poly1305.leBytesToNum(hex('0807060504030201')),
          equals(BigInt.parse('0x0102030405060708')));
    });

    test('numTo16LeBytes matches Python helper', () {
      expect(
        Poly1305.numTo16LeBytes(BigInt.from(0x01020304)),
        equals(hex('04030201000000000000000000000000')),
      );
    });

    test('RFC7539 sample tag generation', () {
      final key = hex(
        '85d6be7857556d337f4452fe42d506a8'
        '0103808afb0db2fd4abff6af4149f51b',
      );
      final poly = Poly1305(key);
      final msg = asciiBytes('Cryptographic Forum Research Group');
      expect(
          poly.createTag(msg), equals(hex('a8061dc1305136c6c22b8baf0c0127a9')));
    });

    test('RFC7539 vector #1', () {
      final poly = Poly1305(Uint8List(32));
      expect(poly.createTag(Uint8List(64)), equals(Uint8List(16)));
    });

    final ietfText = asciiBytes(
        'Any submission to the IETF intended by the Contributor for publication '
        'as all or part of an IETF Internet-Draft or RFC and any statement made '
        'within the context of an IETF activity is considered an "IETF Contribution". '
        'Such statements include oral statements in IETF sessions, as well as written '
        'and electronic communications made at any time or place, which are addressed to');

    test('RFC7539 vector #2', () {
      final key =
          concat([Uint8List(16), hex('36e5f6b5c5e06070f0efca96227a863e')]);
      expect(Poly1305(key).createTag(ietfText),
          equals(hex('36e5f6b5c5e06070f0efca96227a863e')));
    });

    test('RFC7539 vector #3', () {
      final key = concat([
        hex('36e5f6b5c5e06070f0efca96227a863e'),
        Uint8List(16),
      ]);
      expect(Poly1305(key).createTag(ietfText),
          equals(hex('f3477e7cd95417af89a6b8794c310cf0')));
    });

    test('RFC7539 vector #4', () {
      final key = hex(
        '1c9240a5eb55d38af333888604f6b5f0'
        '473917c1402b80099dca5cbc207075c0',
      );
      const poem = "'Twas brillig, and the slithy toves\n"
          'Did gyre and gimble in the wabe:\n'
          'All mimsy were the borogoves,\n'
          'And the mome raths outgrabe.';
      final message = asciiBytes(poem);
      expect(Poly1305(key).createTag(message),
          equals(hex('4541669a7eaaee61e708dc7cbcc5eb62')));
    });

    test('RFC7539 vector #5', () {
      final key = concat([
        Uint8List.fromList([0x02]),
        Uint8List(31),
      ]);
      final message = Uint8List.fromList(List<int>.filled(16, 0xff));
      expect(
          Poly1305(key).createTag(message),
          equals(concat([
            Uint8List.fromList([0x03]),
            Uint8List(15)
          ])));
    });

    test('RFC7539 vector #6', () {
      final key = concat([
        Uint8List.fromList([0x02]),
        Uint8List(15),
        Uint8List.fromList(List<int>.filled(16, 0xff)),
      ]);
      final message = concat([
        Uint8List.fromList([0x02]),
        Uint8List(15),
      ]);
      expect(
          Poly1305(key).createTag(message),
          equals(concat([
            Uint8List.fromList([0x03]),
            Uint8List(15)
          ])));
    });

    test('RFC7539 vector #7', () {
      final key = concat([
        Uint8List.fromList([0x01]),
        Uint8List(31),
      ]);
      final message = concat([
        Uint8List.fromList(List<int>.filled(16, 0xff)),
        Uint8List.fromList([0xf0]),
        Uint8List.fromList(List<int>.filled(15, 0xff)),
        Uint8List.fromList([0x11]),
        Uint8List(15),
      ]);
      expect(
          Poly1305(key).createTag(message),
          equals(concat([
            Uint8List.fromList([0x05]),
            Uint8List(15)
          ])));
    });

    test('RFC7539 vector #8', () {
      final key = concat([
        Uint8List.fromList([0x01]),
        Uint8List(31),
      ]);
      final message = concat([
        Uint8List.fromList(List<int>.filled(16, 0xff)),
        Uint8List.fromList([0xfb]),
        Uint8List.fromList(List<int>.filled(15, 0xfe)),
        Uint8List.fromList(List<int>.filled(16, 0x01)),
      ]);
      expect(Poly1305(key).createTag(message), equals(Uint8List(16)));
    });

    test('RFC7539 vector #9', () {
      final key = concat([
        Uint8List.fromList([0x02]),
        Uint8List(31),
      ]);
      final message = concat([
        Uint8List.fromList([0xfd]),
        Uint8List.fromList(List<int>.filled(15, 0xff)),
      ]);
      expect(
        Poly1305(key).createTag(message),
        equals(concat([
          Uint8List.fromList([0xfa]),
          Uint8List.fromList(List<int>.filled(15, 0xff)),
        ])),
      );
    });

    test('RFC7539 vector #10', () {
      final key = concat([
        Uint8List.fromList([0x01]),
        Uint8List(7),
        Uint8List.fromList([0x04]),
        Uint8List(23),
      ]);
      final message = hex(
        'e33594d7505e43b90000000000000000'
        '3394d7505e4379cd0100000000000000'
        '00000000000000000000000000000000'
        '01000000000000000000000000000000',
      );
      expect(
        Poly1305(key).createTag(message),
        equals(hex('14000000000000005500000000000000')),
      );
    });

    test('RFC7539 vector #11', () {
      final key = concat([
        Uint8List.fromList([0x01]),
        Uint8List(7),
        Uint8List.fromList([0x04]),
        Uint8List(23),
      ]);
      final message = hex(
        'e33594d7505e43b90000000000000000'
        '3394d7505e4379cd0100000000000000'
        '00000000000000000000000000000000',
      );
      expect(
        Poly1305(key).createTag(message),
        equals(hex('13000000000000000000000000000000')),
      );
    });
  });
}

Uint8List asciiBytes(String value) => Uint8List.fromList(ascii.encode(value));

Uint8List concat(List<Uint8List> parts) {
  final total = parts.fold<int>(0, (sum, part) => sum + part.length);
  final out = Uint8List(total);
  var offset = 0;
  for (final part in parts) {
    out.setRange(offset, offset + part.length, part);
    offset += part.length;
  }
  return out;
}

Uint8List hex(String hexStr) {
  final cleaned = hexStr.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
  if (cleaned.length.isOdd) {
    throw ArgumentError('Hex string must contain pairs of characters');
  }
  final out = Uint8List(cleaned.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    final byte = cleaned.substring(i * 2, i * 2 + 2);
    out[i] = int.parse(byte, radix: 16);
  }
  return out;
}
