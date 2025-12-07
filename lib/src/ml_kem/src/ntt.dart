/// Number-Theoretic Transform (NTT) for ML-KEM.
/// 
/// This implementation uses non-Montgomery arithmetic to be compatible
/// with the reference (kyber-py) and FIPS 203 test vectors.
library;

import 'dart:typed_data';

import 'field.dart';

/// Pre-computed zetas (twiddle factors) for NTT.
/// zetas[i] = 17^(bitrev(i, 7)) mod q
/// where bitrev reverses the 7 least significant bits.
/// 
/// Unlike the C reference implementation, these are NOT in Montgomery form.
const List<int> _zetas = [
  1, 1729, 2580, 3289, 2642, 630, 1897, 848,
  1062, 1919, 193, 797, 2786, 3260, 569, 1746,
  296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
  1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
  289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
  650, 1977, 2513, 632, 2865, 33, 1320, 1915,
  2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
  2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
  17, 2761, 583, 2649, 1637, 723, 2288, 1100,
  1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
  1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
  939, 2308, 2437, 2388, 733, 2337, 268, 641,
  1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
  1063, 319, 2773, 757, 2099, 561, 2466, 2594,
  2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
  1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

/// f = 128^-1 mod q = 3303
/// Used to scale inverse NTT output.
const int _f = 3303;

/// Perform forward NTT in-place.
/// Transforms coefficients from time domain to NTT domain.
Int16List nttForward(Int16List coeffs) {
  final r = Int16List.fromList(coeffs);
  var k = 1;
  var len = 128;
  
  while (len >= 2) {
    for (var start = 0; start < mlKemDegree; start += 2 * len) {
      final zeta = _zetas[k++];
      for (var j = start; j < start + len; j++) {
        final t = (zeta * r[j + len]) % mlKemModulus;
        r[j + len] = _reduce(r[j] - t);
        r[j] = _reduce(r[j] + t);
      }
    }
    len >>= 1;
  }
  
  return r;
}

/// Perform inverse NTT in-place.
/// Transforms coefficients from NTT domain back to time domain.
Int16List nttInverse(Int16List coeffs) {
  final r = Int16List.fromList(coeffs);
  var k = 127;
  var len = 2;
  
  while (len <= 128) {
    for (var start = 0; start < mlKemDegree; start += 2 * len) {
      final zeta = _zetas[k--];
      for (var j = start; j < start + len; j++) {
        final t = r[j];
        r[j] = _reduce(t + r[j + len]);
        r[j + len] = _reduce((zeta * (r[j + len] - t)) % mlKemModulus);
      }
    }
    len <<= 1;
  }
  
  // Multiply by f = 128^-1 mod q
  for (var i = 0; i < mlKemDegree; i++) {
    r[i] = _reduce(r[i] * _f);
  }
  
  return r;
}

/// Multiply two polynomials in NTT domain.
/// Uses schoolbook multiplication on pairs of coefficients.
Int16List nttMultiply(Int16List a, Int16List b) {
  final result = Int16List(mlKemDegree);
  
  for (var i = 0; i < mlKemDegree ~/ 2; i++) {
    // zeta^(2*br(i)+1) for the i-th pair
    final zeta = _zetas[64 + (i >> 1)];
    final zetaSign = (i & 1) == 0 ? 1 : -1;
    final zetaVal = zetaSign == 1 ? zeta : (mlKemModulus - zeta);
    
    _baseMul(result, a, b, 2 * i, zetaVal);
  }
  
  return result;
}

/// Base case multiplication for NTT multiply.
void _baseMul(
  Int16List out,
  Int16List a,
  Int16List b,
  int offset,
  int zeta,
) {
  final a0 = a[offset];
  final a1 = a[offset + 1];
  final b0 = b[offset];
  final b1 = b[offset + 1];

  // r0 = a0*b0 + a1*b1*zeta
  // r1 = a0*b1 + a1*b0
  final a1b1z = (a1 * b1 % mlKemModulus) * zeta % mlKemModulus;
  final a0b0 = a0 * b0 % mlKemModulus;
  final a0b1 = a0 * b1 % mlKemModulus;
  final a1b0 = a1 * b0 % mlKemModulus;

  out[offset] = _reduce(a0b0 + a1b1z);
  out[offset + 1] = _reduce(a0b1 + a1b0);
}

/// Reduce value to [0, q-1] range
int _reduce(int x) {
  x = x % mlKemModulus;
  if (x < 0) x += mlKemModulus;
  return x;
}
