import 'package:tlslite/src/utils/brotlidecpy/prefix.dart';

const insertLengthNBits = [
  0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24,
];

void main() {
  final offsets = List<int>.filled(insertLengthNBits.length, 0);
  for (var i = 0; i < insertLengthNBits.length - 1; i++) {
    offsets[i + 1] = offsets[i] + (1 << insertLengthNBits[i]);
  }
  for (var i = 0; i < insertLengthNBits.length; i++) {
    final prefix = kInsertLengthPrefixCode[i];
    print('$i: prefix=${prefix.offset} offset=${offsets[i]}');
  }
}
