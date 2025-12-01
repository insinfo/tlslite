import 'package:tlslite/src/utils/brotlidecpy/prefix.dart';

void main() {
  const length = 8192;
  final code = _findInsertLengthCode(length);
  final prefix = kInsertLengthPrefixCode[code];
  final insertExtraValue = length - prefix.offset;
  print('length=$length code=$code offset=${prefix.offset} nbits=${prefix.nbits} extra=$insertExtraValue');
}

int _findInsertLengthCode(int length) {
  for (var i = 0; i < kInsertLengthPrefixCode.length; i++) {
    final prefix = kInsertLengthPrefixCode[i];
    final maxValue = prefix.offset + ((prefix.nbits == 0) ? 0 : ((1 << prefix.nbits) - 1));
    if (length >= prefix.offset && length <= maxValue) {
      return i;
    }
  }
  throw ArgumentError('Insert length $length outside supported ranges');
}
