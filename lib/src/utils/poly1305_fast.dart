// dart format width=5000
//
// Versão otimizada do Poly1305 baseada em OpenSSL poly1305.c
//
// Esta implementação evita BigInt completamente usando aritmética de limbs
// com inteiros nativos de 64 bits para multiplicação.
//
// O Poly1305 original usa BigInt que é lento em Dart.
// Esta versão usa representação em 5 limbs de 32 bits (130 bits total).
//
// Referência: openssl-master/crypto/poly1305/poly1305.c (versão u32/u64)
//
// Speedup esperado: 3-10x sobre BigInt

import 'dart:typed_data';

/// Poly1305 otimizado usando limbs de 32 bits (sem BigInt)
///
/// Representa números com 5 limbs de 32 bits:
/// h = h0 + h1*2^32 + h2*2^64 + h3*2^96 + h4*2^128
///
/// Multiplicação 32x32=64 bits cabe em int64
class Poly1305Asm {
  // Estado: acumulador em 5 limbs de 32 bits cada
  int _h0 = 0;
  int _h1 = 0;
  int _h2 = 0;
  int _h3 = 0;
  int _h4 = 0;

  // Chave r em 4 limbs de 32 bits (clamped)
  late final int _r0;
  late final int _r1;
  late final int _r2;
  late final int _r3;

  // Pré-computados para redução: s = r + (r >> 2) = r * 5/4
  late final int _s1;
  late final int _s2;
  late final int _s3;

  // Nonce para adição final - 4 limbs de 32 bits
  late final int _pad0;
  late final int _pad1;
  late final int _pad2;
  late final int _pad3;

  // Buffer para bloco parcial
  final Uint8List _buffer = Uint8List(16);
  int _bufferLen = 0;

  /// Cria instância Poly1305 com chave de 32 bytes
  Poly1305Asm(Uint8List key) {
    if (key.length != 32) {
      throw ArgumentError('Poly1305 key must be 32 bytes');
    }

    // r = key[0..15] com clamping
    // r &= 0xffffffc0ffffffc0ffffffc0fffffff
    _r0 = _loadLe32(key, 0) & 0x0fffffff;
    _r1 = _loadLe32(key, 4) & 0x0ffffffc;
    _r2 = _loadLe32(key, 8) & 0x0ffffffc;
    _r3 = _loadLe32(key, 12) & 0x0ffffffc;

    // Pré-computa s = r + (r >> 2) para redução mod 2^130-5
    // Isso é equivalente a r * 5/4 usado na redução
    _s1 = _r1 + (_r1 >> 2);
    _s2 = _r2 + (_r2 >> 2);
    _s3 = _r3 + (_r3 >> 2);

    // nonce = key[16..31]
    _pad0 = _loadLe32(key, 16);
    _pad1 = _loadLe32(key, 20);
    _pad2 = _loadLe32(key, 24);
    _pad3 = _loadLe32(key, 28);
  }

  /// Carrega 32 bits little-endian
  static int _loadLe32(Uint8List data, int offset) {
    return (data[offset] & 0xFF) | ((data[offset + 1] & 0xFF) << 8) | ((data[offset + 2] & 0xFF) << 16) | ((data[offset + 3] & 0xFF) << 24);
  }

  /// Atualiza com dados
  void update(Uint8List data) {
    int offset = 0;

    // Completa buffer parcial primeiro
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

    // Processa blocos completos
    while (offset + 16 <= data.length) {
      _processBlock(data, offset, 1);
      offset += 16;
    }

    // Guarda sobra no buffer
    if (offset < data.length) {
      _buffer.setRange(0, data.length - offset, data.sublist(offset));
      _bufferLen = data.length - offset;
    }
  }

  /// Processa um bloco de 16 bytes
  void _processBlock(Uint8List data, int offset, int padbit) {
    // h += m[i] com carry propagation
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

  /// Multiplica h * r e reduz mod 2^130-5
  void _multiply() {
    // d = h * r
    // Usando multiplicação 32x32->64 bits
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

    // Adiciona c com carry propagation
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

  /// Finaliza e retorna a tag de 16 bytes
  Uint8List finalize() {
    // Processa bloco parcial (se houver)
    if (_bufferLen > 0) {
      // Cria bloco com padding: dados + 0x01 + zeros
      final block = Uint8List(16);
      block.setRange(0, _bufferLen, _buffer.sublist(0, _bufferLen));
      block[_bufferLen] = 0x01;
      _processBlock(block, 0, 0); // padbit = 0 para bloco parcial
    }

    // Compara com módulo computando h + -p
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

    // Se houve carry para o bit 131, usa g
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

    // Converte para bytes little-endian
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

  /// Calcula tag de uma vez
  Uint8List createTag(Uint8List data) {
    reset();
    update(data);
    return finalize();
  }

  /// Reset para reutilização (mantém chave)
  void reset() {
    _h0 = 0;
    _h1 = 0;
    _h2 = 0;
    _h3 = 0;
    _h4 = 0;
    _bufferLen = 0;
  }
}
