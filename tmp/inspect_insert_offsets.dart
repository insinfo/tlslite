import 'package:tlslite/src/utils/brotlidecpy/dec/Decode.dart' as dec;

void main() {
  _dump('Insert', dec.Decode.INSERT_LENGTH_N_BITS);
  _dump('Copy  ', dec.Decode.COPY_LENGTH_N_BITS, initialOffset: 2);
}

void _dump(String label, List<int> nbitsTable, {int initialOffset = 0}) {
  final offsets = List<int>.filled(nbitsTable.length, 0);
  offsets[0] = initialOffset;
  for (var i = 0; i < nbitsTable.length - 1; i++) {
    offsets[i + 1] = offsets[i] + (1 << nbitsTable[i]);
  }
  for (var i = 0; i < offsets.length; i++) {
    final nbits = nbitsTable[i];
    final start = offsets[i];
    final end = offsets[i] + (1 << nbits) - 1;
    print('$label code $i: offset=$start bits=$nbits range=[$start,$end]');
  }
}
