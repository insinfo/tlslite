import 'dart:typed_data';

import 'package:tlslite/src/ed448/ed448.dart' as ed448;
import 'package:tlslite/src/ed448/src/ed448_impl.dart' as impl;

Uint8List _hexToBytes(String hex) {
  final cleaned = hex.replaceAll(RegExp(r'\s'), '');
  final result = Uint8List(cleaned.length ~/ 2);
  for (var i = 0; i < cleaned.length; i += 2) {
    result[i >> 1] = int.parse(cleaned.substring(i, i + 2), radix: 16);
  }
  return result;
}

void main() {
  const baseHex =
      '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e9677'
      '8edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180';
  final pk = ed448.Ed448PublicKeyImpl(_hexToBytes(baseHex));
  print('decoded ok? ${pk.bytes.length}');
  final point = impl.Ed448Point.decode(pk.bytes);
  if (point != null) {
    final normalized = point.normalize();
    print('x: \\n${normalized.x.toRadixString(16)}');
    print('y: \\n${normalized.y.toRadixString(16)}');
  }
}
