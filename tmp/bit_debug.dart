import 'dart:typed_data';

import 'package:tlslite/src/utils/zstd/bit_stream.dart';

void main() {
  final data = Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0x80]);
  final init = BitStreamInitializer(data, 0, data.length);
  init.initialize();
  print('bitsConsumed=${init.bitsConsumed} bits=${init.bits} current=${init.current}');
}
