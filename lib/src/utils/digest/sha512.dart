import 'dart:typed_data';

import 'message_digest.dart';

// Native 64-bit integer arithmetic: additions wrap modulo 2^64 on the Dart VM,
// so no masking is needed. Not web-compatible (the package is VM-only).

final Int64List _k512 = Int64List.fromList(const [
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, //
  0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019,
  0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242,
  0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
  0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
  0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275,
  0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f,
  0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
  0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc,
  0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6,
  0x92722c851482353b, 0xa2bfe8a14cf10364, 0xa81a664bbc423001,
  0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
  0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99,
  0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
  0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc,
  0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915,
  0xc67178f2e372532b, 0xca273eceea26619c, 0xd186b8c721c0c207,
  0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba,
  0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
  0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
  0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
]);

const List<int> _iv512 = [
  0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, //
  0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
  0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

const List<int> _iv384 = [
  0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, //
  0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511,
  0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
];

/// Message schedule scratch space shared by all SHA-384/512 instances.
final Int64List _w = Int64List(80);

/// SHA-512 (FIPS 180-4).
class Sha512 extends MdDigest {
  Sha512() : this._(_iv512, 64, 'sha512');

  Sha512._(this._iv, this._outSize, this._name) : super(128, 16) {
    resetState();
  }

  final List<int> _iv;
  final int _outSize;
  final String _name;
  final Int64List _h = Int64List(8);

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
  Sha512 clone() {
    final c = Sha512._(_iv, _outSize, _name);
    c._h.setAll(0, _h);
    copyBufferTo(c);
    return c;
  }

  @override
  void writeLength(Uint8List buffer, int offset, int byteCount) {
    // 128-bit big-endian bit count.
    final hi = byteCount >>> 61;
    final lo = byteCount << 3;
    for (var i = 0; i < 8; i++) {
      buffer[offset + i] = hi >>> (56 - 8 * i);
      buffer[offset + 8 + i] = lo >>> (56 - 8 * i);
    }
  }

  @override
  void writeOutput(Uint8List out) {
    final h = _h;
    for (var i = 0, j = 0; j < _outSize; i++, j += 8) {
      final v = h[i];
      // SHA-384 output (48 bytes) is a whole number of 64-bit words.
      out[j] = v >>> 56;
      out[j + 1] = v >>> 48;
      out[j + 2] = v >>> 40;
      out[j + 3] = v >>> 32;
      out[j + 4] = v >>> 24;
      out[j + 5] = v >>> 16;
      out[j + 6] = v >>> 8;
      out[j + 7] = v;
    }
  }

  @override
  void processBlock(Uint8List m, int offset) {
    final w = _w;
    final k = _k512;
    for (var i = 0; i < 16; i++) {
      final j = offset + (i << 3);
      w[i] = (m[j] << 56) |
          (m[j + 1] << 48) |
          (m[j + 2] << 40) |
          (m[j + 3] << 32) |
          (m[j + 4] << 24) |
          (m[j + 5] << 16) |
          (m[j + 6] << 8) |
          m[j + 7];
    }
    for (var i = 16; i < 80; i++) {
      final x = w[i - 15];
      final y = w[i - 2];
      final s0 = ((x >>> 1) | (x << 63)) ^ ((x >>> 8) | (x << 56)) ^ (x >>> 7);
      final s1 = ((y >>> 19) | (y << 45)) ^ ((y >>> 61) | (y << 3)) ^ (y >>> 6);
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

    for (var i = 0; i < 80; i++) {
      final s1 = ((e >>> 14) | (e << 50)) ^
          ((e >>> 18) | (e << 46)) ^
          ((e >>> 41) | (e << 23));
      final ch = (e & f) ^ (~e & g);
      final t1 = hh + s1 + ch + k[i] + w[i];
      final s0 = ((a >>> 28) | (a << 36)) ^
          ((a >>> 34) | (a << 30)) ^
          ((a >>> 39) | (a << 25));
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final t2 = s0 + maj;
      hh = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
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

/// SHA-384 (FIPS 180-4): SHA-512 with a different IV, truncated to 48 bytes.
class Sha384 extends Sha512 {
  Sha384() : super._(_iv384, 48, 'sha384');

  @override
  Sha384 clone() {
    final c = Sha384();
    c._h.setAll(0, _h);
    copyBufferTo(c);
    return c;
  }
}
