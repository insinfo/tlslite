// dart format width=5000
//
// Optimized Poly1305 implementation based on OpenSSL poly1305.c
//
// This implementation avoids BigInt entirely by using limb arithmetic
// with native 64-bit integers for multiplication.
//
// The original Poly1305 uses BigInt, which is slow in Dart.
// This version uses a 5 x 32-bit limb representation (130 bits in total).
//
// Reference: openssl-master/crypto/poly1305/poly1305.c (u32/u64 version)
//
// Expected speedup: 3-10x over BigInt

import 'dart:typed_data';

/// Optimized Poly1305 using 32-bit limbs (no BigInt).
///
/// Numbers are represented with 5 limbs of 32 bits:
/// h = h0 + h1*2^32 + h2*2^64 + h3*2^96 + h4*2^128
///
/// A 32x32=64-bit multiplication fits in an int64.
class Poly1305Asm {
  // State: accumulator in 5 limbs of 32 bits each
  int _h0 = 0;
  int _h1 = 0;
  int _h2 = 0;
  int _h3 = 0;
  int _h4 = 0;

  // Key r in 4 limbs of 32 bits (clamped)
  late final int _r0;
  late final int _r1;
  late final int _r2;
  late final int _r3;

  // Precomputed for reduction: s = r + (r >> 2) = r * 5/4
  late final int _s1;
  late final int _s2;
  late final int _s3;

  // Nonce for the final addition - 4 limbs of 32 bits
  late final int _pad0;
  late final int _pad1;
  late final int _pad2;
  late final int _pad3;

  // Buffer for a partial block
  final Uint8List _buffer = Uint8List(16);
  int _bufferLen = 0;

  /// Creates a Poly1305 instance with a 32-byte key.
  Poly1305Asm(Uint8List key) {
    if (key.length != 32) {
      throw ArgumentError('Poly1305 key must be 32 bytes');
    }

    // r = key[0..15] with clamping
    // r &= 0xffffffc0ffffffc0ffffffc0fffffff
    _r0 = _loadLe32(key, 0) & 0x0fffffff;
    _r1 = _loadLe32(key, 4) & 0x0ffffffc;
    _r2 = _loadLe32(key, 8) & 0x0ffffffc;
    _r3 = _loadLe32(key, 12) & 0x0ffffffc;

    // Precompute s = r + (r >> 2) for reduction mod 2^130-5
    // This is equivalent to the r * 5/4 used in the reduction
    _s1 = _r1 + (_r1 >> 2);
    _s2 = _r2 + (_r2 >> 2);
    _s3 = _r3 + (_r3 >> 2);

    // nonce = key[16..31]
    _pad0 = _loadLe32(key, 16);
    _pad1 = _loadLe32(key, 20);
    _pad2 = _loadLe32(key, 24);
    _pad3 = _loadLe32(key, 28);
  }

  /// Loads a 32-bit little-endian value.
  static int _loadLe32(Uint8List data, int offset) {
    return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8) | ((data[offset + 2] & 0xFF) << 16) | ((data[offset + 3] & 0xFF) << 24);
  }

  /// Feeds [data] into the MAC.
  void update(Uint8List data) {
    int offset = 0;

    // Fill the partial buffer first
    if (_bufferLen > 0) {
      final need = 16 - _bufferLen;
      final take = data.length < need ? data.length : need;
      _buffer.setRange(_bufferLen, _bufferLen + take, data);
      _bufferLen += take;
      offset = take;

      if (_bufferLen == 16) {
        _processBlock(_buffer, 0, 1);
        _bufferLen = 0;
      }
    }

    // Process full blocks
    while (offset + 16 <= data.length) {
      _processBlock(data, offset, 1);
      offset += 16;
    }

    // Keep the remainder in the buffer
    if (offset < data.length) {
      _buffer.setRange(0, data.length - offset, data.sublist(offset));
      _bufferLen = data.length - offset;
    }
  }

  /// Processes a 16-byte block.
  void _processBlock(Uint8List data, int offset, int padbit) {
    // h += m[i] with carry propagation
    int d0 = _h0 + _loadLe32(data, offset);
    _h0 = d0 & 0xFFFFFFFF;
    int d1 = _h1 + (d0 >> 32) + _loadLe32(data, offset + 4);
    _h1 = d1 & 0xFFFFFFFF;
    int d2 = _h2 + (d1 >> 32) + _loadLe32(data, offset + 8);
    _h2 = d2 & 0xFFFFFFFF;
    int d3 = _h3 + (d2 >> 32) + _loadLe32(data, offset + 12);
    _h3 = d3 & 0xFFFFFFFF;
    _h4 += (d3 >> 32) + padbit;

    // h *= r "%" p (partial remainder)
    _multiply();
  }

  /// Multiplies h * r and reduces mod 2^130-5.
  void _multiply() {
    // d = h * r
    // Using 32x32->64-bit multiplication
    int d0 = _h0 * _r0 + _h1 * _s3 + _h2 * _s2 + _h3 * _s1;
    int d1 = _h0 * _r1 + _h1 * _r0 + _h2 * _s3 + _h3 * _s2 + _h4 * _s1;
    int d2 = _h0 * _r2 + _h1 * _r1 + _h2 * _r0 + _h3 * _s3 + _h4 * _s2;
    int d3 = _h0 * _r3 + _h1 * _r2 + _h2 * _r1 + _h3 * _r0 + _h4 * _s3;
    int h4 = _h4 * _r0;

    // a) h4:h0 = h4<<128 + d3<<96 + d2<<64 + d1<<32 + d0
    _h0 = d0 & 0xFFFFFFFF;
    d1 += d0 >> 32;
    _h1 = d1 & 0xFFFFFFFF;
    d2 += d1 >> 32;
    _h2 = d2 & 0xFFFFFFFF;
    d3 += d2 >> 32;
    _h3 = d3 & 0xFFFFFFFF;
    h4 += d3 >> 32;

    // b) (h4:h0 += (h4:h0>>130) * 5) %= 2^130
    // c = (h4 >> 2) + (h4 & ~3)
    int c = (h4 >> 2) + (h4 & ~3);
    _h4 = h4 & 3;

    // Add c with carry propagation
    _h0 += c;
    c = _constantTimeCarry(_h0, c);
    _h0 &= 0xFFFFFFFF;
    _h1 += c;
    c = _constantTimeCarry(_h1, c);
    _h1 &= 0xFFFFFFFF;
    _h2 += c;
    c = _constantTimeCarry(_h2, c);
    _h2 &= 0xFFFFFFFF;
    _h3 += c;
    c = _constantTimeCarry(_h3, c);
    _h3 &= 0xFFFFFFFF;
    _h4 += c;
  }

  /// Constant-time carry detection (from OpenSSL)
  static int _constantTimeCarry(int a, int b) {
    // CONSTANT_TIME_CARRY(a,b) = (a ^ ((a ^ b) | ((a - b) ^ b))) >> 31
    return ((a ^ ((a ^ b) | ((a - b) ^ b))) >> 31) & 1;
  }

  /// Finalizes and returns the 16-byte tag.
  Uint8List finalize() {
    // Process the partial block (if any)
    if (_bufferLen > 0) {
      // Build a padded block: data + 0x01 + zeros
      final block = Uint8List(16);
      block.setRange(0, _bufferLen, _buffer.sublist(0, _bufferLen));
      block[_bufferLen] = 0x01;
      _processBlock(block, 0, 0); // padbit = 0 for a partial block
    }

    // Compare with the modulus by computing h + -p
    // g = h + 5
    int t = _h0 + 5;
    int g0 = t & 0xFFFFFFFF;
    t = _h1 + (t >> 32);
    int g1 = t & 0xFFFFFFFF;
    t = _h2 + (t >> 32);
    int g2 = t & 0xFFFFFFFF;
    t = _h3 + (t >> 32);
    int g3 = t & 0xFFFFFFFF;
    int g4 = _h4 + (t >> 32);

    // If there was a carry into bit 131, use g
    // mask = 0 - (g4 >> 2)
    int mask = 0 - (g4 >> 2);
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    int invMask = ~mask;
    int h0 = (_h0 & invMask) | g0;
    int h1 = (_h1 & invMask) | g1;
    int h2 = (_h2 & invMask) | g2;
    int h3 = (_h3 & invMask) | g3;

    // mac = (h + nonce) % (2^128)
    t = h0 + _pad0;
    h0 = t & 0xFFFFFFFF;
    t = h1 + (t >> 32) + _pad1;
    h1 = t & 0xFFFFFFFF;
    t = h2 + (t >> 32) + _pad2;
    h2 = t & 0xFFFFFFFF;
    t = h3 + (t >> 32) + _pad3;
    h3 = t & 0xFFFFFFFF;

    // Convert to little-endian bytes
    final result = Uint8List(16);
    result[0] = h0 & 0xFF;
    result[1] = (h0 >> 8) & 0xFF;
    result[2] = (h0 >> 16) & 0xFF;
    result[3] = (h0 >> 24) & 0xFF;
    result[4] = h1 & 0xFF;
    result[5] = (h1 >> 8) & 0xFF;
    result[6] = (h1 >> 16) & 0xFF;
    result[7] = (h1 >> 24) & 0xFF;
    result[8] = h2 & 0xFF;
    result[9] = (h2 >> 8) & 0xFF;
    result[10] = (h2 >> 16) & 0xFF;
    result[11] = (h2 >> 24) & 0xFF;
    result[12] = h3 & 0xFF;
    result[13] = (h3 >> 8) & 0xFF;
    result[14] = (h3 >> 16) & 0xFF;
    result[15] = (h3 >> 24) & 0xFF;

    return result;
  }

  /// Computes the tag for [data] in one shot.
  Uint8List createTag(Uint8List data) {
    reset();
    update(data);
    return finalize();
  }

  /// Resets the state for reuse (keeps the key).
  void reset() {
    _h0 = 0;
    _h1 = 0;
    _h2 = 0;
    _h3 = 0;
    _h4 = 0;
    _bufferLen = 0;
  }
}
