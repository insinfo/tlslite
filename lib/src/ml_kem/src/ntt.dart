/// Number-Theoretic Transform (NTT) for ML-KEM.
library;

import 'dart:typed_data';
import 'polynomial.dart';

/// Precomputed zetas for NTT (powers of root of unity 17)
final List<int> _nttZetas = _computeZetas();

/// Montgomery factor R = 2^16 mod q
const int _montR = 1 << 16;

/// Montgomery factor for reduction
const int _qinv = 62209;  // -q^(-1) mod 2^16

/// Compute zetas in bit-reversed order
List<int> _computeZetas() {
  const root = 17;  // primitive 512th root of unity mod q
  final zetas = List<int>.filled(128, 0);
  
  for (var i = 0; i < 128; i++) {
    final br = _bitReverse7(i);
    zetas[i] = _modPow(root, br, q);
  }
  return zetas;
}

/// Bit reverse a 7-bit integer
int _bitReverse7(int i) {
  var r = 0;
  for (var j = 0; j < 7; j++) {
    r = (r << 1) | ((i >> j) & 1);
  }
  return r;
}

/// Modular exponentiation
int _modPow(int base, int exp, int mod) {
  var result = 1;
  base = base % mod;
  while (exp > 0) {
    if (exp & 1 == 1) {
      result = (result * base) % mod;
    }
    exp >>= 1;
    base = (base * base) % mod;
  }
  return result;
}

/// Montgomery reduction: compute a * R^(-1) mod q
int _montgomeryReduce(int a) {
  final t = ((a & 0xFFFF) * _qinv) & 0xFFFF;
  var r = (a - t * q) >> 16;
  if (r < 0) r += q;
  return r;
}

/// Barrett reduction: compute a mod q
int _barrettReduce(int a) {
  // For ML-KEM, simple modulo is sufficient
  var r = a % q;
  if (r < 0) r += q;
  return r;
}

/// Forward NTT: convert from standard to NTT domain
Int16List nttForward(Int16List coeffs) {
  final result = Int16List.fromList(coeffs);
  var k = 1;
  var len = 128;
  
  while (len >= 2) {
    for (var start = 0; start < n; start += 2 * len) {
      final zeta = _nttZetas[k++];
      for (var j = start; j < start + len; j++) {
        final t = (zeta * result[j + len]) % q;
        result[j + len] = _barrettReduce(result[j] - t);
        result[j] = _barrettReduce(result[j] + t);
      }
    }
    len >>= 1;
  }
  
  return result;
}

/// Inverse NTT: convert from NTT to standard domain
Int16List nttInverse(Int16List coeffs) {
  final result = Int16List.fromList(coeffs);
  var k = 127;
  var len = 2;
  
  while (len <= 128) {
    for (var start = 0; start < n; start += 2 * len) {
      final zeta = _nttZetas[k--];
      for (var j = start; j < start + len; j++) {
        final t = result[j];
        result[j] = _barrettReduce(t + result[j + len]);
        result[j + len] = _barrettReduce(zeta * (result[j + len] - t));
      }
    }
    len <<= 1;
  }
  
  // Multiply by n^(-1) mod q = 3303
  const nInv = 3303;  // 256^(-1) mod 3329
  for (var i = 0; i < n; i++) {
    result[i] = (result[i] * nInv) % q;
  }
  
  return result;
}

/// Base case multiplication for NTT domain
(int, int) _baseMul(int a0, int a1, int b0, int b1, int zeta) {
  final r0 = (a0 * b0 + zeta * a1 * b1) % q;
  final r1 = (a1 * b0 + a0 * b1) % q;
  return (_barrettReduce(r0), _barrettReduce(r1));
}

/// Multiply two polynomials in NTT domain
Int16List nttMultiply(Int16List a, Int16List b) {
  final result = Int16List(n);
  
  for (var i = 0; i < 64; i++) {
    final zeta = _nttZetas[64 + i];
    final (r0, r1) = _baseMul(
      a[4 * i], a[4 * i + 1],
      b[4 * i], b[4 * i + 1],
      zeta,
    );
    final (r2, r3) = _baseMul(
      a[4 * i + 2], a[4 * i + 3],
      b[4 * i + 2], b[4 * i + 3],
      (q - zeta) % q,  // -zeta mod q
    );
    result[4 * i] = r0;
    result[4 * i + 1] = r1;
    result[4 * i + 2] = r2;
    result[4 * i + 3] = r3;
  }
  
  return result;
}
