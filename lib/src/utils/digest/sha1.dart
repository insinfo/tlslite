import 'dart:typed_data';

import 'message_digest.dart';

const int _mask32 = 0xFFFFFFFF;

final Uint32List _w = Uint32List(80);

/// SHA-1 (FIPS 180-4). Only for legacy protocols (TLS 1.0/1.1 PRF, MACs).
class Sha1 extends MdDigest {
  Sha1() : super(64, 8) {
    resetState();
  }

  final Uint32List _h = Uint32List(5);

  @override
  String get algorithm => 'sha1';

  @override
  int get digestSize => 20;

  @override
  void resetState() {
    final h = _h;
    h[0] = 0x67452301;
    h[1] = 0xefcdab89;
    h[2] = 0x98badcfe;
    h[3] = 0x10325476;
    h[4] = 0xc3d2e1f0;
  }

  @override
  Sha1 clone() {
    final c = Sha1();
    c._h.setAll(0, _h);
    copyBufferTo(c);
    return c;
  }

  @override
  void writeLength(Uint8List buffer, int offset, int byteCount) {
    final hi = byteCount >>> 29;
    final lo = (byteCount << 3) & _mask32;
    buffer[offset] = hi >>> 24;
    buffer[offset + 1] = hi >>> 16;
    buffer[offset + 2] = hi >>> 8;
    buffer[offset + 3] = hi;
    buffer[offset + 4] = lo >>> 24;
    buffer[offset + 5] = lo >>> 16;
    buffer[offset + 6] = lo >>> 8;
    buffer[offset + 7] = lo;
  }

  @override
  void writeOutput(Uint8List out) {
    final h = _h;
    for (var i = 0; i < 5; i++) {
      final v = h[i];
      out[4 * i] = v >>> 24;
      out[4 * i + 1] = v >>> 16;
      out[4 * i + 2] = v >>> 8;
      out[4 * i + 3] = v;
    }
  }

  @override
  void processBlock(Uint8List m, int offset) {
    final w = _w;
    for (var i = 0; i < 16; i++) {
      final j = offset + (i << 2);
      w[i] = (m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3];
    }
    for (var i = 16; i < 80; i++) {
      final x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
      w[i] = (x << 1) | (x >>> 31);
    }

    final h = _h;
    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];
    var e = h[4];

    for (var i = 0; i < 80; i++) {
      int f;
      int k;
      if (i < 20) {
        f = (b & c) | (~b & d);
        k = 0x5a827999;
      } else if (i < 40) {
        f = b ^ c ^ d;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = (b & c) | (b & d) | (c & d);
        k = 0x8f1bbcdc;
      } else {
        f = b ^ c ^ d;
        k = 0xca62c1d6;
      }
      final t =
          ((((a << 5) | (a >>> 27)) & _mask32) + f + e + k + w[i]) & _mask32;
      e = d;
      d = c;
      c = ((b << 30) | (b >>> 2)) & _mask32;
      b = a;
      a = t;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  }
}
