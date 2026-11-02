// Ported to Dart from tlslite-ng tlslite/utils/python_chacha20_poly1305.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:typed_data';
import 'chacha20_poly1305.dart';

Chacha20Poly1305 newChaCha20Poly1305(Uint8List key) {
  return Chacha20Poly1305(Uint8List.fromList(key), 'dart');
}
