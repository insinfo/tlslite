import 'package:tlslite/src/utils/bit_stream_writer.dart';
import 'package:tlslite/src/utils/brotlidecpy/dec/BitReader.dart';
import 'package:tlslite/src/utils/brotlidecpy/dec/State.dart';

void main() {
  final writer = BitStreamWriter();
  writer.writeBits(1982, 14);
  writer.alignToByte();
  final bytes = writer.takeBytes();
  final state = State();
  state.input = ByteArrayInputStream(bytes);
  BitReader.initBitReader(state);
  BitReader.fillBitWindow(state);
  final value = BitReader.readBits(state, 14);
  print('roundtrip=$value bytes=$bytes');
}
