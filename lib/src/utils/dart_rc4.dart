import 'dart:typed_data';

import 'rc4.dart';

RC4 newRC4(Uint8List key) {
  return DartRC4(key);
}

class DartRC4 extends RC4 {
  DartRC4(Uint8List keyBytes)
      : _state = Uint8List.fromList(List<int>.generate(256, (i) => i)),
        super(keyBytes, 'dart') {
    var j = 0;
    for (var i = 0; i < 256; i++) {
      j = (j + _state[i] + keyBytes[i % keyBytes.length]) & 0xff;
      final tmp = _state[i];
      _state[i] = _state[j];
      _state[j] = tmp;
    }
    _i = 0;
    _j = 0;
  }

  final Uint8List _state;
  late int _i;
  late int _j;

  @override
  Uint8List encrypt(Uint8List plaintext) {
    final output = Uint8List.fromList(plaintext);
    final s = _state;
    var i = _i;
    var j = _j;
    for (var idx = 0; idx < output.length; idx++) {
      i = (i + 1) & 0xff;
      j = (j + s[i]) & 0xff;
      final tmp = s[i];
      s[i] = s[j];
      s[j] = tmp;
      final t = (s[i] + s[j]) & 0xff;
      output[idx] ^= s[t];
    }
    _i = i;
    _j = j;
    return output;
  }

  @override
  Uint8List decrypt(Uint8List ciphertext) {
    return encrypt(ciphertext);
  }
}
