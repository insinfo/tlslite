/// Polynomial ring R_q = Z_q[X]/(X^256 + 1) for ML-KEM.
library;

import 'dart:typed_data';
import 'ntt.dart';

/// The modulus q = 3329 for ML-KEM
const int q = 3329;

/// Polynomial degree n = 256
const int n = 256;

/// A polynomial in R_q = Z_q[X]/(X^256 + 1)
class Polynomial {
  /// Coefficients in [0, q-1]
  final Int16List coeffs;
  
  /// Whether polynomial is in NTT domain
  final bool isNtt;

  Polynomial(this.coeffs, {this.isNtt = false}) {
    assert(coeffs.length == n);
  }

  /// Create zero polynomial
  factory Polynomial.zero({bool isNtt = false}) {
    return Polynomial(Int16List(n), isNtt: isNtt);
  }

  /// Create polynomial from coefficient list
  factory Polynomial.fromList(List<int> coefficients, {bool isNtt = false}) {
    final c = Int16List(n);
    for (var i = 0; i < coefficients.length && i < n; i++) {
      c[i] = coefficients[i] % q;
    }
    return Polynomial(c, isNtt: isNtt);
  }

  /// Parse bytes using rejection sampling (Algorithm 6: SampleNTT)
  factory Polynomial.sampleNtt(Uint8List bytes) {
    final coeffs = Int16List(n);
    var i = 0;
    var j = 0;
    while (j < n) {
      final d1 = bytes[i] + 256 * (bytes[i + 1] % 16);
      final d2 = (bytes[i + 1] ~/ 16) + 16 * bytes[i + 2];
      
      if (d1 < q) {
        coeffs[j] = d1;
        j++;
      }
      if (d2 < q && j < n) {
        coeffs[j] = d2;
        j++;
      }
      i += 3;
    }
    return Polynomial(coeffs, isNtt: true);
  }

  /// Sample from centered binomial distribution (Algorithm 7: SamplePolyCBD)
  factory Polynomial.sampleCbd(Uint8List bytes, int eta, {bool isNtt = false}) {
    assert(bytes.length == 64 * eta);
    final coeffs = Int16List(n);
    
    // Convert bytes to bits and process
    var bitIndex = 0;
    int getBit() {
      final byteIdx = bitIndex ~/ 8;
      final bitIdx = bitIndex % 8;
      bitIndex++;
      return (bytes[byteIdx] >> bitIdx) & 1;
    }
    
    for (var i = 0; i < n; i++) {
      var a = 0;
      var b = 0;
      for (var j = 0; j < eta; j++) {
        a += getBit();
        b += getBit();
      }
      coeffs[i] = (a - b + q) % q;
    }
    
    return Polynomial(coeffs, isNtt: isNtt);
  }

  /// Decode bytes to polynomial (Algorithm 4: ByteDecode)
  factory Polynomial.decode(Uint8List bytes, int d, {bool isNtt = false}) {
    assert(bytes.length == 32 * d);
    final coeffs = Int16List(n);
    final m = d == 12 ? q : (1 << d);
    
    // Decode d-bit integers from bytes
    var bitBuffer = BigInt.zero;
    for (var i = bytes.length - 1; i >= 0; i--) {
      bitBuffer = (bitBuffer << 8) | BigInt.from(bytes[i]);
    }
    
    final mask = (BigInt.one << d) - BigInt.one;
    for (var i = 0; i < n; i++) {
      coeffs[i] = ((bitBuffer & mask).toInt()) % m;
      bitBuffer >>= d;
    }
    
    return Polynomial(coeffs, isNtt: isNtt);
  }

  /// Encode polynomial to bytes (Algorithm 5: ByteEncode)
  Uint8List encode(int d) {
    final result = Uint8List(32 * d);
    
    // Encode coefficients as d-bit integers
    var bitBuffer = BigInt.zero;
    for (var i = n - 1; i >= 0; i--) {
      bitBuffer = (bitBuffer << d) | BigInt.from(coeffs[i]);
    }
    
    for (var i = 0; i < result.length; i++) {
      result[i] = (bitBuffer & BigInt.from(0xFF)).toInt();
      bitBuffer >>= 8;
    }
    
    return result;
  }

  /// Compress polynomial coefficients
  Polynomial compress(int d) {
    final result = Int16List(n);
    final t = 1 << d;
    for (var i = 0; i < n; i++) {
      // round((2^d / q) * x) mod 2^d
      final x = coeffs[i];
      result[i] = ((t * x + 1664) ~/ q) % t;  // 1664 = q // 2
    }
    return Polynomial(result, isNtt: isNtt);
  }

  /// Decompress polynomial coefficients
  Polynomial decompress(int d) {
    final result = Int16List(n);
    final t = 1 << (d - 1);
    for (var i = 0; i < n; i++) {
      // round((q / 2^d) * x)
      result[i] = (q * coeffs[i] + t) >> d;
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

  /// Add two polynomials
  Polynomial operator +(Polynomial other) {
    assert(isNtt == other.isNtt);
    final result = Int16List(n);
    for (var i = 0; i < n; i++) {
      result[i] = (coeffs[i] + other.coeffs[i]) % q;
    }
    return Polynomial(result, isNtt: isNtt);
  }

  /// Subtract two polynomials
  Polynomial operator -(Polynomial other) {
    assert(isNtt == other.isNtt);
    final result = Int16List(n);
    for (var i = 0; i < n; i++) {
      result[i] = (coeffs[i] - other.coeffs[i] + q) % q;
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
    final result = Int16List(n);
    for (var i = 0; i < n; i++) {
      result[i] = (coeffs[i] * scalar) % q;
    }
    return Polynomial(result, isNtt: isNtt);
  }
}
