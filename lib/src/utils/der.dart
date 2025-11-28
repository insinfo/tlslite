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
