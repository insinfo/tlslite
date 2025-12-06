/// Field arithmetic for ML-KEM.
///
/// This module defines the finite field Z_q where q = 3329,
/// along with helper functions for modular arithmetic.
library;

/// The prime modulus q = 3329 for ML-KEM.
const int mlKemModulus = 3329;

/// The degree n = 256 of the polynomial ring.
const int mlKemDegree = 256;

/// Barrett reduction constant for q = 3329.
/// v = floor(2^26 / q) = floor(67108864 / 3329) = 20159
const int _barrettV = 20159;

/// Message representative: round(q/2) = 1665
const int messageRepresentative = 1665;

/// Montgomery factor R^2 mod q (not used in non-Montgomery implementation)
const int montgomeryFactor = 1353; // (2^16)^2 mod 3329

/// Barrett reduction: reduce x to [0, q) using precomputed constant.
/// 
/// For x in [0, q^2), this computes x mod q without division.
/// Uses the formula: x - floor(x * v / 2^26) * q
int barrettReduce(int x) {
  // t = floor(x * v / 2^26)
  final t = (x * _barrettV) >> 26;
  // x - t*q
  var r = x - t * mlKemModulus;
  // Final correction if still >= q
  if (r >= mlKemModulus) {
    r -= mlKemModulus;
  }
  return r;
}

/// Reduce x to canonical form in [0, q-1].
/// 
/// Handles negative values properly.
int modQ(int x) {
  var r = x % mlKemModulus;
  if (r < 0) r += mlKemModulus;
  return r;
}

/// Freeze: reduce to canonical form [0, q-1].
/// 
/// This is the same as modQ but named to match reference implementations.
int freeze(int x) {
  var r = x % mlKemModulus;
  if (r < 0) r += mlKemModulus;
  return r;
}

/// Field multiplication (non-Montgomery).
/// 
/// Computes (a * b) mod q.
int fqMul(int a, int b) {
  return freeze(a * b);
}
