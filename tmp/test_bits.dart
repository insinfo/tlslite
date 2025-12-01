import 'package:tlslite/src/utils/bit_stream_writer.dart';

int readBits(List<int> bytes, int bitCount) {
  var result = 0;
  var byteIndex = 0;
  var currentByte = bytes.isEmpty ? 0 : bytes[0];
  var bitsUsed = 0;
  for (var i = 0; i < bitCount; i++) {
    if (bitsUsed == 8) {
      byteIndex++;
      currentByte = bytes[byteIndex];
      bitsUsed = 0;
    }
    final bit = (currentByte >> bitsUsed) & 1;
    result |= bit << i;
    bitsUsed++;
  }
  return result;
}

void main() {
  final writer = BitStreamWriter();
  writer.writeBits(1982, 14);
  final bytes = writer.takeBytes();
  final decoded = readBits(bytes, 14);
  print('bytes: $bytes decoded=$decoded');
}
