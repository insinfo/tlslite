import 'dart:typed_data';

import 'cryptomath.dart';
import 'asn1parser.dart';

Uint8List derEncodeInteger(BigInt value) {
  var bytes = numberToByteArray(value, endian: 'big');
  if (bytes.isEmpty) {
    bytes = Uint8List.fromList([0]);
  } else if (bytes[0] & 0x80 != 0) {
    final extended = Uint8List(bytes.length + 1);
    extended[0] = 0;
    extended.setRange(1, extended.length, bytes);
    bytes = extended;
  }
  final length = _encodeLength(bytes.length);
  final out = Uint8List(1 + length.length + bytes.length);
  out[0] = 0x02;
  out.setRange(1, 1 + length.length, length);
  out.setRange(1 + length.length, out.length, bytes);
  return out;
}

Uint8List derEncodeSequence(List<Uint8List> children) {
  final totalLength = children.fold<int>(0, (acc, item) => acc + item.length);
  final length = _encodeLength(totalLength);
  final out = Uint8List(1 + length.length + totalLength);
  out[0] = 0x30;
  out.setRange(1, 1 + length.length, length);
  var offset = 1 + length.length;
  for (final child in children) {
    out.setRange(offset, offset + child.length, child);
    offset += child.length;
  }
  return out;
}

Uint8List derEncodeBitString(Uint8List data, {int unusedBits = 0}) {
  if (unusedBits < 0 || unusedBits > 7) {
    throw ArgumentError('unusedBits must be between 0 and 7');
  }
  final payloadLength = data.length + 1;
  final length = _encodeLength(payloadLength);
  final out = Uint8List(1 + length.length + payloadLength);
  out[0] = 0x03;
  out.setRange(1, 1 + length.length, length);
  out[1 + length.length] = unusedBits;
  out.setRange(2 + length.length, out.length, data);
  return out;
}

Uint8List derEncodeNull() => Uint8List.fromList([0x05, 0x00]);

Uint8List derEncodeOctetString(Uint8List data) {
  final length = _encodeLength(data.length);
  final out = Uint8List(1 + length.length + data.length);
  out[0] = 0x04;
  out.setRange(1, 1 + length.length, length);
  out.setRange(1 + length.length, out.length, data);
  return out;
}

Uint8List derEncodeContextSpecific(int tagNumber, Uint8List value,
    {bool constructed = true}) {
  if (tagNumber < 0 || tagNumber > 30) {
    throw ArgumentError('tagNumber must be between 0 and 30');
  }
  final tag = (constructed ? 0xa0 : 0x80) | tagNumber;
  final length = _encodeLength(value.length);
  final out = Uint8List(1 + length.length + value.length);
  out[0] = tag;
  out.setRange(1, 1 + length.length, length);
  out.setRange(1 + length.length, out.length, value);
  return out;
}

Uint8List derEncodeObjectIdentifier(List<int> oid) {
  if (oid.length < 2) {
    throw ArgumentError('OID must have at least two components');
  }
  final encoded = <int>[];
  encoded.add(oid[0] * 40 + oid[1]);
  for (var i = 2; i < oid.length; i++) {
    var value = oid[i];
    if (value < 0) {
      throw ArgumentError('OID components must be non-negative');
    }
    final stack = <int>[];
    do {
      stack.insert(0, value & 0x7f);
      value >>= 7;
    } while (value > 0);
    for (var j = 0; j < stack.length - 1; j++) {
      encoded.add(stack[j] | 0x80);
    }
    encoded.add(stack.last);
  }
  final length = _encodeLength(encoded.length);
  final out = Uint8List(1 + length.length + encoded.length);
  out[0] = 0x06;
  out.setRange(1, 1 + length.length, length);
  out.setRange(1 + length.length, out.length, encoded);
  return out;
}

({BigInt r, BigInt s}) derDecodeSignature(Uint8List signature) {
  final parser = ASN1Parser(signature);
  if (parser.type.tagId != 0x10) {
    throw const FormatException('Signature is not a DER sequence');
  }
  final rNode = parser.getChild(0);
  final sNode = parser.getChild(1);
  final r = bytesToNumber(rNode.value);
  final s = bytesToNumber(sNode.value);
  return (r: r, s: s);
}

Uint8List _encodeLength(int length) {
  if (length < 0x80) {
    return Uint8List.fromList([length]);
  }
  final bytes = <int>[];
  var remaining = length;
  while (remaining > 0) {
    bytes.insert(0, remaining & 0xff);
    remaining >>= 8;
  }
  return Uint8List.fromList([0x80 | bytes.length, ...bytes]);
}
