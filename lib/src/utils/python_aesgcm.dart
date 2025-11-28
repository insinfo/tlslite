import 'dart:typed_data';

import 'aesgcm.dart';
import 'rijndael.dart';

AESGCM newAESGCM(Uint8List key) {
  final rijndael = Rijndael(Uint8List.fromList(key), blockSize: 16);
  return AESGCM(Uint8List.fromList(key), 'python', rijndael.encrypt);
}
