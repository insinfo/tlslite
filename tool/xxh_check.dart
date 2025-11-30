import 'dart:typed_data';

import 'package:tlslite/src/utils/zstd/xxhash64.dart';

void main(List<String> args) {
  final data = args.isEmpty ? Uint8List(0) : Uint8List.fromList(args.first.codeUnits);
  final hash = xxHash64(data);
  final low32 = hash.toUnsigned(32).toInt();
  print('len=${data.length} hash=0x${hash.toRadixString(16)} low32=0x${low32.toRadixString(16)}');
}
