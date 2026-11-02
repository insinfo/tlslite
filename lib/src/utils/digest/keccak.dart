import 'dart:typed_data';

import 'message_digest.dart';

// Keccak-f[1600] and the FIPS 202 sponge functions (SHA3-*, SHAKE*).
// Lanes are native 64-bit integers (VM-only).

final Int64List _rc = Int64List.fromList(const [
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a, //
  0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
  0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
  0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
  0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
  0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]);

/// Applies the Keccak-f[1600] permutation (24 rounds) to the 25-lane state.
void keccakF1600(Int64List s) {
  var a0 = s[0];
  var a1 = s[1];
  var a2 = s[2];
  var a3 = s[3];
  var a4 = s[4];
  var a5 = s[5];
  var a6 = s[6];
  var a7 = s[7];
  var a8 = s[8];
  var a9 = s[9];
  var a10 = s[10];
  var a11 = s[11];
  var a12 = s[12];
  var a13 = s[13];
  var a14 = s[14];
  var a15 = s[15];
  var a16 = s[16];
  var a17 = s[17];
  var a18 = s[18];
  var a19 = s[19];
  var a20 = s[20];
  var a21 = s[21];
  var a22 = s[22];
  var a23 = s[23];
  var a24 = s[24];
  for (var round = 0; round < 24; round++) {
    final c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20;
    final c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21;
    final c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22;
    final c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23;
    final c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24;
    final d0 = c4 ^ ((c1 << 1) | (c1 >>> 63));
    final d1 = c0 ^ ((c2 << 1) | (c2 >>> 63));
    final d2 = c1 ^ ((c3 << 1) | (c3 >>> 63));
    final d3 = c2 ^ ((c4 << 1) | (c4 >>> 63));
    final d4 = c3 ^ ((c0 << 1) | (c0 >>> 63));
    final b0 = a0 ^ d0;
    final t1 = a6 ^ d1;
    final b1 = ((t1 << 44) | (t1 >>> 20));
    final t2 = a12 ^ d2;
    final b2 = ((t2 << 43) | (t2 >>> 21));
    final t3 = a18 ^ d3;
    final b3 = ((t3 << 21) | (t3 >>> 43));
    final t4 = a24 ^ d4;
    final b4 = ((t4 << 14) | (t4 >>> 50));
    final t5 = a3 ^ d3;
    final b5 = ((t5 << 28) | (t5 >>> 36));
    final t6 = a9 ^ d4;
    final b6 = ((t6 << 20) | (t6 >>> 44));
    final t7 = a10 ^ d0;
    final b7 = ((t7 << 3) | (t7 >>> 61));
    final t8 = a16 ^ d1;
    final b8 = ((t8 << 45) | (t8 >>> 19));
    final t9 = a22 ^ d2;
    final b9 = ((t9 << 61) | (t9 >>> 3));
    final t10 = a1 ^ d1;
    final b10 = ((t10 << 1) | (t10 >>> 63));
    final t11 = a7 ^ d2;
    final b11 = ((t11 << 6) | (t11 >>> 58));
    final t12 = a13 ^ d3;
    final b12 = ((t12 << 25) | (t12 >>> 39));
    final t13 = a19 ^ d4;
    final b13 = ((t13 << 8) | (t13 >>> 56));
    final t14 = a20 ^ d0;
    final b14 = ((t14 << 18) | (t14 >>> 46));
    final t15 = a4 ^ d4;
    final b15 = ((t15 << 27) | (t15 >>> 37));
    final t16 = a5 ^ d0;
    final b16 = ((t16 << 36) | (t16 >>> 28));
    final t17 = a11 ^ d1;
    final b17 = ((t17 << 10) | (t17 >>> 54));
    final t18 = a17 ^ d2;
    final b18 = ((t18 << 15) | (t18 >>> 49));
    final t19 = a23 ^ d3;
    final b19 = ((t19 << 56) | (t19 >>> 8));
    final t20 = a2 ^ d2;
    final b20 = ((t20 << 62) | (t20 >>> 2));
    final t21 = a8 ^ d3;
    final b21 = ((t21 << 55) | (t21 >>> 9));
    final t22 = a14 ^ d4;
    final b22 = ((t22 << 39) | (t22 >>> 25));
    final t23 = a15 ^ d0;
    final b23 = ((t23 << 41) | (t23 >>> 23));
    final t24 = a21 ^ d1;
    final b24 = ((t24 << 2) | (t24 >>> 62));
    a0 = b0 ^ (~b1 & b2);
    a1 = b1 ^ (~b2 & b3);
    a2 = b2 ^ (~b3 & b4);
    a3 = b3 ^ (~b4 & b0);
    a4 = b4 ^ (~b0 & b1);
    a5 = b5 ^ (~b6 & b7);
    a6 = b6 ^ (~b7 & b8);
    a7 = b7 ^ (~b8 & b9);
    a8 = b8 ^ (~b9 & b5);
    a9 = b9 ^ (~b5 & b6);
    a10 = b10 ^ (~b11 & b12);
    a11 = b11 ^ (~b12 & b13);
    a12 = b12 ^ (~b13 & b14);
    a13 = b13 ^ (~b14 & b10);
    a14 = b14 ^ (~b10 & b11);
    a15 = b15 ^ (~b16 & b17);
    a16 = b16 ^ (~b17 & b18);
    a17 = b17 ^ (~b18 & b19);
    a18 = b18 ^ (~b19 & b15);
    a19 = b19 ^ (~b15 & b16);
    a20 = b20 ^ (~b21 & b22);
    a21 = b21 ^ (~b22 & b23);
    a22 = b22 ^ (~b23 & b24);
    a23 = b23 ^ (~b24 & b20);
    a24 = b24 ^ (~b20 & b21);
    a0 ^= _rc[round];
  }
  s[0] = a0;
  s[1] = a1;
  s[2] = a2;
  s[3] = a3;
  s[4] = a4;
  s[5] = a5;
  s[6] = a6;
  s[7] = a7;
  s[8] = a8;
  s[9] = a9;
  s[10] = a10;
  s[11] = a11;
  s[12] = a12;
  s[13] = a13;
  s[14] = a14;
  s[15] = a15;
  s[16] = a16;
  s[17] = a17;
  s[18] = a18;
  s[19] = a19;
  s[20] = a20;
  s[21] = a21;
  s[22] = a22;
  s[23] = a23;
  s[24] = a24;
}

/// Keccak sponge with byte-oriented absorb and incremental squeeze.
class KeccakSponge {
  /// [rate] in bytes (multiple of 8, < 200); [domain] is the domain
  /// separation/padding start byte (0x06 for SHA-3, 0x1F for SHAKE).
  KeccakSponge(this.rate, this.domain)
      : assert(rate > 0 && rate < 200 && rate % 8 == 0),
        _buffer = Uint8List(rate);

  final int rate;
  final int domain;
  final Int64List _state = Int64List(25);
  final Uint8List _buffer;
  int _bufferLength = 0;
  bool _squeezing = false;
  int _squeezeOffset = 0;

  /// Whether the sponge has switched to the squeezing phase.
  bool get isSqueezing => _squeezing;

  void reset() {
    _state.fillRange(0, 25, 0);
    _bufferLength = 0;
    _squeezing = false;
    _squeezeOffset = 0;
  }

  KeccakSponge clone() {
    final c = KeccakSponge(rate, domain);
    c._state.setAll(0, _state);
    c._buffer.setRange(0, _bufferLength, _buffer);
    c._bufferLength = _bufferLength;
    c._squeezing = _squeezing;
    c._squeezeOffset = _squeezeOffset;
    return c;
  }

  void _absorbBlock(Uint8List m, int offset) {
    final s = _state;
    final lanes = rate >> 3;
    for (var i = 0; i < lanes; i++) {
      final j = offset + (i << 3);
      s[i] ^= m[j] |
          (m[j + 1] << 8) |
          (m[j + 2] << 16) |
          (m[j + 3] << 24) |
          (m[j + 4] << 32) |
          (m[j + 5] << 40) |
          (m[j + 6] << 48) |
          (m[j + 7] << 56);
    }
    keccakF1600(s);
  }

  void absorb(List<int> data, [int start = 0, int? end]) {
    if (_squeezing) {
      throw StateError('Cannot absorb after squeezing has started');
    }
    end = RangeError.checkValidRange(start, end, data.length);
    var length = end - start;
    if (length == 0) return;
    final Uint8List bytes;
    if (data is Uint8List) {
      bytes = data;
    } else {
      bytes = Uint8List.fromList(data.sublist(start, end));
      start = 0;
    }
    final buffer = _buffer;
    if (_bufferLength > 0) {
      final room = rate - _bufferLength;
      final take = room < length ? room : length;
      buffer.setRange(_bufferLength, _bufferLength + take, bytes, start);
      _bufferLength += take;
      start += take;
      length -= take;
      if (_bufferLength < rate) return;
      _absorbBlock(buffer, 0);
      _bufferLength = 0;
    }
    while (length >= rate) {
      _absorbBlock(bytes, start);
      start += rate;
      length -= rate;
    }
    if (length > 0) {
      buffer.setRange(0, length, bytes, start);
      _bufferLength = length;
    }
  }

  void _pad() {
    final buffer = _buffer;
    buffer.fillRange(_bufferLength, rate, 0);
    buffer[_bufferLength] ^= domain;
    buffer[rate - 1] ^= 0x80;
    _absorbBlock(buffer, 0);
    _bufferLength = 0;
    _squeezing = true;
    _squeezeOffset = 0;
  }

  /// Writes the next `end - start` output bytes into `out[start..end)`.
  /// Can be called repeatedly; output is the continuation of the stream.
  void squeeze(Uint8List out, [int start = 0, int? end]) {
    end = RangeError.checkValidRange(start, end, out.length);
    if (!_squeezing) _pad();
    final s = _state;
    var pos = _squeezeOffset;
    for (var i = start; i < end; i++) {
      if (pos == rate) {
        keccakF1600(s);
        pos = 0;
      }
      out[i] = s[pos >> 3] >>> ((pos & 7) << 3);
      pos++;
    }
    _squeezeOffset = pos;
  }
}

/// SHA3-224/256/384/512 (FIPS 202).
class Sha3 extends MessageDigest {
  /// [bits] is 224, 256, 384 or 512.
  Sha3(int bits)
      : _bits = bits,
        _sponge = KeccakSponge(200 - 2 * (bits >> 3), 0x06) {
    if (bits != 224 && bits != 256 && bits != 384 && bits != 512) {
      throw ArgumentError.value(bits, 'bits', 'Unsupported SHA-3 size');
    }
  }

  Sha3._clone(this._bits, this._sponge);

  final int _bits;
  final KeccakSponge _sponge;

  @override
  String get algorithm => 'sha3_$_bits';

  @override
  int get digestSize => _bits >> 3;

  @override
  int get blockSize => _sponge.rate;

  @override
  void update(List<int> data, [int start = 0, int? end]) =>
      _sponge.absorb(data, start, end);

  @override
  Uint8List finish() {
    final out = Uint8List(digestSize);
    _sponge.squeeze(out);
    _sponge.reset();
    return out;
  }

  @override
  void reset() => _sponge.reset();

  @override
  Sha3 clone() => Sha3._clone(_bits, _sponge.clone());
}

/// SHAKE128 / SHAKE256 extendable-output functions (FIPS 202).
///
/// Absorb with [update]; then call [read]/[readInto] any number of times to
/// squeeze consecutive output. [update] after the first read throws.
class Shake {
  /// [securityBits] is 128 or 256.
  Shake(int securityBits)
      : _bits = securityBits,
        _sponge = KeccakSponge(200 - 2 * (securityBits >> 3), 0x1F) {
    if (securityBits != 128 && securityBits != 256) {
      throw ArgumentError.value(
          securityBits, 'securityBits', 'Unsupported SHAKE strength');
    }
  }

  Shake._clone(this._bits, this._sponge);

  final int _bits;
  final KeccakSponge _sponge;

  String get algorithm => 'shake$_bits';

  /// Sponge rate in bytes (168 for SHAKE128, 136 for SHAKE256).
  int get blockSize => _sponge.rate;

  void update(List<int> data, [int start = 0, int? end]) =>
      _sponge.absorb(data, start, end);

  /// Squeezes the next [length] bytes.
  Uint8List read(int length) {
    final out = Uint8List(length);
    _sponge.squeeze(out);
    return out;
  }

  /// Squeezes the next `end - start` bytes into `out[start..end)`.
  void readInto(Uint8List out, [int start = 0, int? end]) =>
      _sponge.squeeze(out, start, end);

  void reset() => _sponge.reset();

  Shake clone() => Shake._clone(_bits, _sponge.clone());
}

/// One-shot SHA3-224.
Uint8List sha3_224(List<int> data) => (Sha3(224)..update(data)).finish();

/// One-shot SHA3-256.
Uint8List sha3_256(List<int> data) => (Sha3(256)..update(data)).finish();

/// One-shot SHA3-384.
Uint8List sha3_384(List<int> data) => (Sha3(384)..update(data)).finish();

/// One-shot SHA3-512.
Uint8List sha3_512(List<int> data) => (Sha3(512)..update(data)).finish();

/// One-shot SHAKE128 producing [outputLength] bytes.
Uint8List shake128(List<int> data, int outputLength) =>
    (Shake(128)..update(data)).read(outputLength);

/// One-shot SHAKE256 producing [outputLength] bytes.
Uint8List shake256(List<int> data, int outputLength) =>
    (Shake(256)..update(data)).read(outputLength);
