import 'dart:typed_data';

import 'message_digest.dart';

const int _mask32 = 0xFFFFFFFF;

final Uint32List _k256 = Uint32List.fromList(const [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, //
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const List<int> _iv256 = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, //
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const List<int> _iv224 = [
  0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, //
  0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

/// Message schedule scratch space shared by all SHA-224/256 instances
/// (Dart isolates are single-threaded and [Sha256._compress] is not
/// re-entrant).
final Uint32List _w = Uint32List(64);

/// SHA-256 (FIPS 180-4).
class Sha256 extends MdDigest {
  Sha256() : this._(_iv256, 32, 'sha256');

  Sha256._(this._iv, this._outSize, this._name) : super(64, 8) {
    resetState();
  }

  final List<int> _iv;
  final int _outSize;
  final String _name;
  final Uint32List _h = Uint32List(8);

  @override
  String get algorithm => _name;

  @override
  int get digestSize => _outSize;

  @override
  void resetState() {
    final h = _h;
    for (var i = 0; i < 8; i++) {
      h[i] = _iv[i];
    }
  }

  @override
  Sha256 clone() {
    final c = Sha256._(_iv, _outSize, _name);
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
    for (var i = 0, j = 0; j < _outSize; i++, j += 4) {
      final v = h[i];
      out[j] = v >>> 24;
      out[j + 1] = v >>> 16;
      out[j + 2] = v >>> 8;
      out[j + 3] = v;
    }
  }

  @override
  void processBlock(Uint8List m, int offset) {
    final w = _w;
    final k = _k256;
    for (var i = 0; i < 16; i++) {
      final j = offset + (i << 2);
      w[i] = (m[j] << 24) | (m[j + 1] << 16) | (m[j + 2] << 8) | m[j + 3];
    }
    for (var i = 16; i < 64; i++) {
      final x = w[i - 15];
      final y = w[i - 2];
      final s0 =
          (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) &
              _mask32;
      final s1 =
          (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) &
              _mask32;
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    final h = _h;
    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];
    var e = h[4];
    var f = h[5];
    var g = h[6];
    var hh = h[7];

    for (var i = 0; i < 64; i++) {
      final s1 = (((e >>> 6) | (e << 26)) ^
              ((e >>> 11) | (e << 21)) ^
              ((e >>> 25) | (e << 7))) &
          _mask32;
      final ch = (e & f) ^ (~e & g);
      final t1 = hh + s1 + ch + k[i] + w[i];
      final s0 = (((a >>> 2) | (a << 30)) ^
              ((a >>> 13) | (a << 19)) ^
              ((a >>> 22) | (a << 10))) &
          _mask32;
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final t2 = s0 + maj;
      hh = g;
      g = f;
      f = e;
      e = (d + t1) & _mask32;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) & _mask32;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
  }
}

/// SHA-224 (FIPS 180-4): SHA-256 with a different IV, truncated to 28 bytes.
class Sha224 extends Sha256 {
  Sha224() : super._(_iv224, 28, 'sha224');

  @override
  Sha224 clone() {
    final c = Sha224();
    c._h.setAll(0, _h);
    copyBufferTo(c);
    return c;
  }
}
