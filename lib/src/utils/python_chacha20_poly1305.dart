import 'dart:typed_data';

import 'chacha20_poly1305.dart';

Chacha20Poly1305 newChaCha20Poly1305(Uint8List key) {
  return Chacha20Poly1305(Uint8List.fromList(key), 'python');
}
