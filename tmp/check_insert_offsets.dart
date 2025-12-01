import 'package:tlslite/src/utils/brotlidecpy/prefix.dart' as prefix;
import 'package:tlslite/src/utils/brotlidecpy/dec/Decode.dart';

void main() {
  final insertOffsets = List<int>.filled(Decode.INSERT_LENGTH_N_BITS.length, 0);
  final copyOffsets = List<int>.filled(Decode.COPY_LENGTH_N_BITS.length, 0);
  for (var i = 0; i < insertOffsets.length - 1; i++) {
    final nbits = Decode.INSERT_LENGTH_N_BITS[i];
    insertOffsets[i + 1] = insertOffsets[i] + (1 << nbits);
  }
  copyOffsets[0] = 2;
  for (var i = 0; i < copyOffsets.length - 1; i++) {
    final nbits = Decode.COPY_LENGTH_N_BITS[i];
    copyOffsets[i + 1] = copyOffsets[i] + (1 << nbits);
  }
  for (var i = 0; i < insertOffsets.length; i++) {
    final pref = prefix.kInsertLengthPrefixCode[i].offset;
    final off = insertOffsets[i];
    if (pref != off) {
      print('insert mismatch at $i: prefix=$pref decode=$off');
    }
  }
  for (var i = 0; i < copyOffsets.length; i++) {
    final pref = prefix.kCopyLengthPrefixCode[i].offset;
    final off = copyOffsets[i];
    if (pref != off) {
      print('copy mismatch at $i: prefix=$pref decode=$off');
    }
  }
  print('done');
}
