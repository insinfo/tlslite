import 'package:tlslite/src/utils/brotlidecpy/prefix.dart';

void main(List<String> args) {
  final length = args.isEmpty ? 8192 : int.parse(args.first);
  for (var i = 0; i < kInsertLengthPrefixCode.length; i++) {
    final prefix = kInsertLengthPrefixCode[i];
    final max = prefix.offset + ((prefix.nbits == 0) ? 0 : ((1 << prefix.nbits) - 1));
    if (length >= prefix.offset && length <= max) {
      print('length=$length code=$i offset=${prefix.offset} bits=${prefix.nbits} range=[${prefix.offset}, $max]');
      return;
    }
  }
  print('length=$length not representable');
}
