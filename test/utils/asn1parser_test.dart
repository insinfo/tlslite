import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/asn1parser.dart';

void main() {
  group('ASN1Parser', () {
    test('parses sequence and exposes children', () {
      final data = Uint8List.fromList([
        0x30,
        0x06,
        0x02,
        0x01,
        0x01,
        0x02,
        0x01,
        0x02,
      ]);
      final parser = ASN1Parser(data);
      expect(parser.type.tagId, 0x10); // SEQUENCE tag
      expect(parser.getChildCount(), 2);

      final firstChild = parser.getChild(0);
      expect(firstChild.type.tagId, 0x02); // INTEGER
      expect(firstChild.value, [0x01]);

      final secondChild = parser.getChild(1);
      expect(secondChild.value, [0x02]);
    });

    test('handles long-form lengths', () {
      final payload = Uint8List.fromList(List<int>.filled(130, 0xAA));
      final data = Uint8List(payload.length + 3);
      data[0] = 0x04; // OCTET STRING
      data[1] = 0x81; // long-form, 1 length byte follows
      data[2] = 130; // actual length
      data.setRange(3, data.length, payload);

      final parser = ASN1Parser(data);
      expect(parser.type.tagId, 0x04);
      expect(parser.length, 130);
      expect(parser.value.length, 130);
    });
  });
}
