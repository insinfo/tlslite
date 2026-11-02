// Ported to Dart from tlslite-ng tlslite/utils/python_aesgcm.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:typed_data';
import 'aesgcm.dart';
import 'rijndael_slow.dart';

AESGCM newAESGCM(Uint8List key) {
  final rijndael = Rijndael(Uint8List.fromList(key), blockSize: 16);
  return AESGCM(Uint8List.fromList(key), 'dart', rijndael.encrypt);
}
