import 'dart:typed_data';
import 'aesgcm.dart';
import 'rijndael_slow.dart';

AESGCM newAESGCM(Uint8List key) {
  final rijndael = Rijndael(Uint8List.fromList(key), blockSize: 16);
  return AESGCM(Uint8List.fromList(key), 'dart', rijndael.encrypt);
}
