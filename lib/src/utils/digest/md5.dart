import 'dart:typed_data';

import 'message_digest.dart';

const int _mask32 = 0xFFFFFFFF;

final Uint32List _k = Uint32List.fromList(const [
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, //
  0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
  0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
  0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
  0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
  0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]);

final Uint8List _s = Uint8List.fromList(const [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, //
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]);

final Uint32List _x = Uint32List(16);

/// MD5 (RFC 1321). Only for legacy protocols (SSLv3/TLS 1.0/1.1).
class Md5 extends MdDigest {
  Md5() : super(64, 8) {
    resetState();
  }

  final Uint32List _h = Uint32List(4);

  @override
  String get algorithm => 'md5';

  @override
  int get digestSize => 16;

  @override
  void resetState() {
    final h = _h;
    h[0] = 0x67452301;
    h[1] = 0xefcdab89;
    h[2] = 0x98badcfe;
    h[3] = 0x10325476;
  }

  @override
  Md5 clone() {
    final c = Md5();
    c._h.setAll(0, _h);
    copyBufferTo(c);
    return c;
  }

  @override
  void writeLength(Uint8List buffer, int offset, int byteCount) {
    // 64-bit little-endian bit count.
    final bits = byteCount << 3;
    for (var i = 0; i < 8; i++) {
      buffer[offset + i] = bits >>> (8 * i);
    }
  }

  @override
  void writeOutput(Uint8List out) {
    final h = _h;
    for (var i = 0; i < 4; i++) {
      final v = h[i];
      out[4 * i] = v;
      out[4 * i + 1] = v >>> 8;
      out[4 * i + 2] = v >>> 16;
      out[4 * i + 3] = v >>> 24;
    }
  }

  @override
  void processBlock(Uint8List m, int offset) {
    final x = _x;
    for (var i = 0; i < 16; i++) {
      final j = offset + (i << 2);
      x[i] = m[j] | (m[j + 1] << 8) | (m[j + 2] << 16) | (m[j + 3] << 24);
    }
    final k = _k;
    final s = _s;
    final h = _h;
    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];

    for (var i = 0; i < 64; i++) {
      int f;
      int g;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) & 15;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) & 15;
      } else {
        f = (c ^ (b | (~d & _mask32))) & _mask32;
        g = (7 * i) & 15;
      }
      final t = (a + f + k[i] + x[g]) & _mask32;
      final r = s[i];
      a = d;
      d = c;
      c = b;
      b = (b + (((t << r) | (t >>> (32 - r))) & _mask32)) & _mask32;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
  }
}
