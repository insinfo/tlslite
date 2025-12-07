import 'dart:typed_data';
import 'aesccm.dart';
import 'rijndael.dart';

AESCCM newAESCCM(Uint8List key, {int tagLength = 16}) {
  final internalKey = Uint8List.fromList(key);
  final rijndael = Rijndael(internalKey, blockSize: 16);
  return AESCCM(internalKey, 'dart', rijndael.encrypt, tagLength: tagLength);
}
