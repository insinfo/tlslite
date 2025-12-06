/// Polynomial ring R_q = Z_q[X]/(X^256 + 1) for ML-KEM.
library;

import 'dart:typed_data';
import 'field.dart';
import 'ntt.dart';

/// A polynomial in R_q = Z_q[X]/(X^256 + 1)
class Polynomial {
  /// Coefficients in [0, mlKemModulus-1]
  final Int16List coeffs;
  
  /// Whether polynomial is in NTT domain
  final bool isNtt;

  Polynomial(this.coeffs, {this.isNtt = false}) {
    assert(coeffs.length == mlKemDegree);
  }

  /// Create zero polynomial
  factory Polynomial.zero({bool isNtt = false}) {
    return Polynomial(Int16List(mlKemDegree), isNtt: isNtt);
  }

  /// Create polynomial from coefficient list
  factory Polynomial.fromList(List<int> coefficients, {bool isNtt = false}) {
    final c = Int16List(mlKemDegree);
    for (var i = 0; i < coefficients.length && i < mlKemDegree; i++) {
      c[i] = _canonical(coefficients[i]);
    }
    return Polynomial(c, isNtt: isNtt);
  }

  /// Parse bytes using rejection sampling (Algorithm 6: SampleNTT)
  factory Polynomial.sampleNtt(Uint8List bytes) {
    final coeffs = Int16List(mlKemDegree);
    var i = 0;
    var j = 0;
    while (j < mlKemDegree) {
      final d1 = bytes[i] + 256 * (bytes[i + 1] % 16);
      final d2 = (bytes[i + 1] ~/ 16) + 16 * bytes[i + 2];
      
      if (d1 < mlKemModulus) {
        coeffs[j] = d1;
        j++;
      }
      if (d2 < mlKemModulus && j < mlKemDegree) {
        coeffs[j] = d2;
        j++;
      }
      i += 3;
    }
    return Polynomial(coeffs, isNtt: true);
  }

  /// Sample from centered binomial distribution (Algorithm 7: SamplePolyCBD)
  factory Polynomial.sampleCbd(Uint8List bytes, int eta, {bool isNtt = false}) {
    switch (eta) {
      case 2:
        assert(bytes.length == 64 * eta);
        return Polynomial(_cbd2(bytes), isNtt: isNtt);
      case 3:
        assert(bytes.length == 64 * eta);
        return Polynomial(_cbd3(bytes), isNtt: isNtt);
      default:
        throw ArgumentError('Unsupported eta value: $eta');
    }
  }

  static Int16List _cbd2(Uint8List bytes) {
    final coeffs = Int16List(mlKemDegree);
    final data = ByteData.sublistView(bytes);
    for (var i = 0; i < mlKemDegree ~/ 8; i++) {
      final t = data.getUint32(i * 4, Endian.little);
      var d = t & 0x55555555;
      d += (t >> 1) & 0x55555555;
      for (var j = 0; j < 8; j++) {
        final a = (d >> (4 * j)) & 0x3;
        final b = (d >> (4 * j + 2)) & 0x3;
        coeffs[8 * i + j] = _canonical(a - b);
      }
    }
    return coeffs;
  }

  static Int16List _cbd3(Uint8List bytes) {
    final coeffs = Int16List(mlKemDegree);
    for (var i = 0; i < mlKemDegree ~/ 4; i++) {
      final t = _load24(bytes, 3 * i);
      var d = t & 0x00249249;
      d += (t >> 1) & 0x00249249;
      d += (t >> 2) & 0x00249249;
      for (var j = 0; j < 4; j++) {
        final a = (d >> (6 * j)) & 0x7;
        final b = (d >> (6 * j + 3)) & 0x7;
        coeffs[4 * i + j] = _canonical(a - b);
      }
    }
    return coeffs;
  }

  static int _load24(Uint8List bytes, int offset) {
    return bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16);
  }

  /// Decode bytes to polynomial (Algorithm 4: ByteDecode)
  factory Polynomial.decode(Uint8List bytes, int d, {bool isNtt = false}) {
    assert(bytes.length == 32 * d);
    final coeffs = Int16List(mlKemDegree);
    final m = d == 12 ? mlKemModulus : (1 << d);
    
    // Decode d-bit integers from bytes
    var bitBuffer = BigInt.zero;
    for (var i = bytes.length - 1; i >= 0; i--) {
      bitBuffer = (bitBuffer << 8) | BigInt.from(bytes[i]);
    }
    
    final mask = (BigInt.one << d) - BigInt.one;
    for (var i = 0; i < mlKemDegree; i++) {
      final value = ((bitBuffer & mask).toInt()) % m;
      coeffs[i] = d == 12 ? _canonical(value) : value;
      bitBuffer >>= d;
    }
    
    return Polynomial(coeffs, isNtt: isNtt);
  }

  /// Encode polynomial to bytes (Algorithm 5: ByteEncode)
  Uint8List encode(int d) {
    final result = Uint8List(32 * d);
    
    // Encode coefficients as d-bit integers
    var bitBuffer = BigInt.zero;
    for (var i = mlKemDegree - 1; i >= 0; i--) {
      final value = _canonical(coeffs[i]) & ((1 << d) - 1);
      bitBuffer = (bitBuffer << d) | BigInt.from(value);
    }
    
    for (var i = 0; i < result.length; i++) {
      result[i] = (bitBuffer & BigInt.from(0xFF)).toInt();
      bitBuffer >>= 8;
    }
    
    return result;
  }

  /// Construct polynomial from a 32-byte message (Algorithm 9)
  factory Polynomial.fromMessage(Uint8List message) {
    final expected = mlKemDegree >> 3;
    if (message.length != expected) {
      throw ArgumentError('Message must be $expected bytes');
    }
    final coeffs = Int16List(mlKemDegree);
    for (var i = 0; i < expected; i++) {
      for (var j = 0; j < 8; j++) {
        final bit = (message[i] >> j) & 1;
        coeffs[8 * i + j] = bit == 1 ? messageRepresentative : 0;
      }
    }
    return Polynomial(coeffs);
  }

  /// Convert polynomial back to a 32-byte message
  Uint8List toMessage() {
    final result = Uint8List(mlKemDegree >> 3);
    for (var i = 0; i < result.length; i++) {
      var byte = 0;
      for (var j = 0; j < 8; j++) {
        var t = coeffs[8 * i + j];
        t = barrettReduce(t);
        t <<= 1;
        t += 1665;
        t *= 80635;
        t >>= 28;
        t &= 1;
        byte |= t << j;
      }
      result[i] = byte;
    }
    return result;
  }

  /// Compress polynomial coefficients
  Polynomial compress(int d) {
    final result = Int16List(mlKemDegree);
    final t = 1 << d;
    final rounding = mlKemModulus >> 1;
    for (var i = 0; i < mlKemDegree; i++) {
      final x = _canonical(coeffs[i]);
      result[i] = ((t * x + rounding) ~/ mlKemModulus) & (t - 1);
    }
    return Polynomial(result, isNtt: isNtt);
  }

  /// Decompress polynomial coefficients
  Polynomial decompress(int d) {
    final result = Int16List(mlKemDegree);
    final t = 1 << (d - 1);
    for (var i = 0; i < mlKemDegree; i++) {
      // round((mlKemModulus / 2^d) * x)
      result[i] = _canonical((mlKemModulus * coeffs[i] + t) >> d);
    }
    return Polynomial(result, isNtt: isNtt);
  }

  /// Convert to NTT domain
  Polynomial toNtt() {
    if (isNtt) {
      throw StateError('Polynomial is already in NTT domain');
    }
    return Polynomial(nttForward(coeffs), isNtt: true);
  }

  /// Convert from NTT domain
  Polynomial fromNtt() {
    if (!isNtt) {
      throw StateError('Polynomial is not in NTT domain');
    }
    return Polynomial(nttInverse(coeffs), isNtt: false);
  }

  /// Convert coefficients into Montgomery domain
  Polynomial toMontgomery() {
    final result = Int16List(mlKemDegree);
    for (var i = 0; i < mlKemDegree; i++) {
      result[i] = fqMul(coeffs[i], montgomeryFactor);
    }
    return Polynomial(result, isNtt: isNtt);
  }

  /// Add two polynomials
  Polynomial operator +(Polynomial other) {
    assert(isNtt == other.isNtt);
    final result = Int16List(mlKemDegree);
    for (var i = 0; i < mlKemDegree; i++) {
      result[i] = _canonical(coeffs[i] + other.coeffs[i]);
    }
    return Polynomial(result, isNtt: isNtt);
  }

  /// Subtract two polynomials
  Polynomial operator -(Polynomial other) {
    assert(isNtt == other.isNtt);
    final result = Int16List(mlKemDegree);
    for (var i = 0; i < mlKemDegree; i++) {
      result[i] = _canonical(coeffs[i] - other.coeffs[i]);
    }
    return Polynomial(result, isNtt: isNtt);
  }

  /// Multiply two polynomials (must be in NTT domain)
  Polynomial operator *(Polynomial other) {
    if (!isNtt || !other.isNtt) {
      throw StateError('Multiplication requires NTT domain');
    }
    return Polynomial(nttMultiply(coeffs, other.coeffs), isNtt: true);
  }

  /// Scale by integer
  Polynomial scale(int scalar) {
    final result = Int16List(mlKemDegree);
    for (var i = 0; i < mlKemDegree; i++) {
      result[i] = _canonical(coeffs[i] * scalar);
    }
    return Polynomial(result, isNtt: isNtt);
  }
}

int _canonical(int value) => freeze(value);
