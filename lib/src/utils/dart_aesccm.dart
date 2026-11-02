// Ported to Dart from tlslite-ng tlslite/utils/python_aesccm.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:typed_data';
import 'aesccm.dart';
import 'rijndael_slow.dart';

AESCCM newAESCCM(Uint8List key, {int tagLength = 16}) {
  final internalKey = Uint8List.fromList(key);
  final rijndael = Rijndael(internalKey, blockSize: 16);
  return AESCCM(internalKey, 'dart', rijndael.encrypt, tagLength: tagLength);
}
