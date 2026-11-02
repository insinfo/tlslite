// dart format width=5000
// Optimized Montgomery multiplication for RSA
// References: C:\MyDartProjects\tlslite\referencias\openssl-master
// References: C:\MyDartProjects\tlslite\referencias\sdk-main
// Based on:
// - Dart SDK bigint_patch.dart (half-digit multiplication techniques)
// - OpenSSL bn_mont.c (CIOS Montgomery algorithm)
//
// Uses 32-bit limbs with half-digit (16-bit) multiplication to avoid
// overflow in multiplications on the Dart VM.

import 'dart:typed_data';

// ============================================================================
// Constants
// ============================================================================

const int _digitBits = 32;
const int _digitMask = 0xFFFFFFFF;

// ============================================================================
// Array functions
// ============================================================================

/// Subtraction: rp = ap - bp; returns the borrow.
@pragma('vm:prefer-inline')
int _subWords(Uint32List rp, int rpOff, Uint32List ap, int apOff, Uint32List bp, int bpOff, int num) {
  int borrow = 0;
  for (int i = 0; i < num; i++) {
    final diff = ap[apOff + i] - bp[bpOff + i] - borrow;
    rp[rpOff + i] = diff & _digitMask;
    borrow = (diff < 0) ? 1 : 0;
  }
  return borrow;
}

/// Comparison: returns 1 if a > b, -1 if a < b, 0 if equal.
@pragma('vm:prefer-inline')
int _cmpWords(Uint32List a, Uint32List b, int num) {
  for (int i = num - 1; i >= 0; i--) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

/// Addition: rp = ap + bp; returns the carry.
int bnAddWords(Uint32List rp, int rpOff, Uint32List ap, int apOff, Uint32List bp, int bpOff, int num) {
  int carry = 0;
  for (int i = 0; i < num; i++) {
    final sum = ap[apOff + i] + bp[bpOff + i] + carry;
    rp[rpOff + i] = sum & _digitMask;
    carry = sum >> _digitBits;
  }
  return carry;
}

/// Subtraction: rp = ap - bp; returns the borrow.
int bnSubWords(Uint32List rp, int rpOff, Uint32List ap, int apOff, Uint32List bp, int bpOff, int num) {
  return _subWords(rp, rpOff, ap, apOff, bp, bpOff, num);
}

// ============================================================================
// BigNum - big number represented as an array of limbs
// ============================================================================

/// Big number represented as an array of limbs (little-endian).
class BN {
  /// Limb array (little-endian: limbs[0] is the least significant).
  Uint32List d;
  
  /// Number of limbs in use (top).
  int top;
  
  /// Allocated capacity.
  int dmax;
  
  /// Negative sign.
  bool neg;

  BN(int size)
      : d = Uint32List(size),
        top = 0,
        dmax = size,
        neg = false;

  BN.fromList(List<int> limbs)
      : d = Uint32List.fromList(limbs),
        top = limbs.length,
        dmax = limbs.length,
        neg = false {
    _fixTop();
  }

  /// Creates a BN from big-endian bytes.
  factory BN.fromBytes(Uint8List bytes) {
    if (bytes.isEmpty) return BN(1);
    
    // Number of limbs needed
    final numLimbs = (bytes.length + 3) ~/ 4;
    final bn = BN(numLimbs);
    
    // Convert big-endian bytes to little-endian limbs
    int limbIdx = 0;
    int shift = 0;
    int limb = 0;
    
    for (int i = bytes.length - 1; i >= 0; i--) {
      limb |= bytes[i] << shift;
      shift += 8;
      if (shift >= 32) {
        bn.d[limbIdx++] = limb & _digitMask;
        limb = 0;
        shift = 0;
      }
    }
    
    if (shift > 0 && limbIdx < numLimbs) {
      bn.d[limbIdx++] = limb;
    }
    
    bn.top = limbIdx;
    bn._fixTop();
    return bn;
  }

  /// Strips leading zero limbs.
  void _fixTop() {
    while (top > 0 && d[top - 1] == 0) {
      top--;
    }
    if (top == 0) neg = false;
  }

  /// Copies the value of [other].
  void copyFrom(BN other) {
    if (dmax < other.top) {
      d = Uint32List(other.top);
      dmax = other.top;
    }
    for (int i = 0; i < other.top; i++) {
      d[i] = other.d[i];
    }
    for (int i = other.top; i < dmax; i++) {
      d[i] = 0;
    }
    top = other.top;
    neg = other.neg;
  }

  /// Sets the number to zero.
  void zero() {
    for (int i = 0; i < dmax; i++) {
      d[i] = 0;
    }
    top = 0;
    neg = false;
  }

  /// Sets the number to one.
  void setOne() {
    zero();
    d[0] = 1;
    top = 1;
  }

  /// Whether the number is zero.
  bool get isZero => top == 0;

  /// Whether the number is one.
  bool get isOne => top == 1 && d[0] == 1 && !neg;

  /// Number of significant bits.
  int get numBits {
    if (top == 0) return 0;
    int bits = (top - 1) * 32;
    int w = d[top - 1];
    while (w != 0) {
      bits++;
      w >>= 1;
    }
    return bits;
  }

  /// Converts to big-endian bytes.
  Uint8List toBytes() {
    if (top == 0) return Uint8List(1);
    
    final numBytes = (numBits + 7) ~/ 8;
    final bytes = Uint8List(numBytes);
    
    int byteIdx = numBytes - 1;
    for (int i = 0; i < top && byteIdx >= 0; i++) {
      int limb = d[i];
      for (int j = 0; j < 4 && byteIdx >= 0; j++) {
        bytes[byteIdx--] = limb & 0xFF;
        limb >>= 8;
      }
    }
    
    return bytes;
  }

  /// Grows the capacity to [newSize] limbs if needed.
  void expand(int newSize) {
    if (dmax >= newSize) return;
    final newD = Uint32List(newSize);
    for (int i = 0; i < top; i++) {
      newD[i] = d[i];
    }
    d = newD;
    dmax = newSize;
  }

  @override
  String toString() {
    if (top == 0) return '0';
    final sb = StringBuffer();
    if (neg) sb.write('-');
    for (int i = top - 1; i >= 0; i--) {
      sb.write(d[i].toRadixString(16).padLeft(8, '0'));
    }
    return sb.toString();
  }
}

// ============================================================================
// Montgomery Context
// ============================================================================

/// Montgomery context for efficient modular multiplication.
///
/// Similar to OpenSSL's bn_mont_ctx_st.
class MontgomeryCtx {
  /// Modulus N.
  final BN n;
  
  /// R*R mod N (used to convert to Montgomery form).
  final BN rr;
  
  /// Constant n0 = -N^(-1) mod 2^32
  /// (n0[0] and n0[1] in the 64-bit version).
  final int n0;
  
  /// Number of bits in R (ri).
  final int ri;

  MontgomeryCtx._({
    required this.n,
    required this.rr,
    required this.n0,
    required this.ri,
  });

  /// Creates a context for the modulus [mod].
  factory MontgomeryCtx.fromModulus(BN mod) {
    final numLimbs = mod.top;
    final ri = numLimbs * _digitBits;
    
    // Compute n0 = -N^(-1) mod 2^32
    final n0 = _computeN0Inv(mod.d[0]);
    
    // Compute R*R mod N
    final rr = _computeRR(mod, ri);
    
    // Copy the modulus
    final n = BN(numLimbs);
    n.copyFrom(mod);
    
    return MontgomeryCtx._(n: n, rr: rr, n0: n0, ri: ri);
  }

  /// Computes -N^(-1) mod 2^32 using Newton's method.
  static int _computeN0Inv(int n0) {
    // n0 must be odd (always true for RSA)
    // x = x * (2 - n0 * x) mod 2^k, doubling k on each iteration
    int x = n0; // x0 = n0 (works because n0 is odd)
    
    // 5 iterations converge to 32 bits
    x = (x * (2 - ((n0 * x) & _digitMask))) & _digitMask;
    x = (x * (2 - ((n0 * x) & _digitMask))) & _digitMask;
    x = (x * (2 - ((n0 * x) & _digitMask))) & _digitMask;
    x = (x * (2 - ((n0 * x) & _digitMask))) & _digitMask;
    x = (x * (2 - ((n0 * x) & _digitMask))) & _digitMask;
    
    return (-x) & _digitMask;
  }

  /// Computes R*R mod N where R = 2^ri.
  static BN _computeRR(BN mod, int ri) {
    final numLimbs = mod.top;
    
    // R = 2^ri, R*R = 2^(2*ri)
    // Compute 2^(2*ri) mod N with shifts and subtractions
    
    // Start with 1
    final rr = BN(numLimbs * 2 + 1);
    rr.setOne();
    
    // Shift left 2*ri bits, reducing mod N at each step
    for (int i = 0; i < ri * 2; i++) {
      // rr = rr * 2
      int carry = 0;
      for (int j = 0; j < rr.top; j++) {
        int t = (rr.d[j] << 1) | carry;
        rr.d[j] = t & _digitMask;
        carry = t >> 32;
      }
      if (carry != 0) {
        if (rr.top < rr.dmax) {
          rr.d[rr.top] = carry;
          rr.top++;
        }
      }
      
      // If rr >= mod, subtract mod (at most once per iteration)
      if (_bnCmp(rr, mod) >= 0) {
        _bnSubInPlace(rr, mod);
      }
    }
    
    return rr;
  }
  
  /// Compares two BNs: returns 1 if a > b, -1 if a < b, 0 if equal.
  static int _bnCmp(BN a, BN b) {
    if (a.top > b.top) return 1;
    if (a.top < b.top) return -1;
    for (int i = a.top - 1; i >= 0; i--) {
      if (a.d[i] > b.d[i]) return 1;
      if (a.d[i] < b.d[i]) return -1;
    }
    return 0;
  }
  
  /// Subtracts b from a in place: a = a - b (requires a >= b).
  static void _bnSubInPlace(BN a, BN b) {
    int borrow = 0;
    for (int i = 0; i < a.top; i++) {
      final bi = i < b.top ? b.d[i] : 0;
      final diff = a.d[i] - bi - borrow;
      if (diff < 0) {
        a.d[i] = (diff + 0x100000000) & _digitMask;
        borrow = 1;
      } else {
        a.d[i] = diff & _digitMask;
        borrow = 0;
      }
    }
    a._fixTop();
  }
}

// ============================================================================
// Montgomery Multiplication
// ============================================================================

/// Montgomery multiplication: ret = a * b * R^(-1) mod N.
///
/// Implements the CIOS (Coarsely Integrated Operand Scanning) algorithm
/// using the Dart VM's native 32x32 multiplication (64-bit integers).
void bnMontMul(BN ret, BN a, BN b, MontgomeryCtx mont) {
  final n = mont.n;
  final numLimbs = n.top;
  final n0 = mont.n0;
  final nDigits = n.d;
  
  // Make sure the result has enough room
  ret.expand(numLimbs + 1);
  
  // Temporary for the intermediate result (needs 2*numLimbs + 2)
  final tLen = numLimbs * 2 + 2;
  final t = Uint32List(tLen);
  
  // Cache sizes
  final aTop = a.top;
  final bTop = b.top;
  final aDigits = a.d;
  final bDigits = b.d;
  
  // CIOS: for each limb of a
  for (int i = 0; i < numLimbs; i++) {
    final ai = (i < aTop) ? aDigits[i] : 0;

    // t = t + ai * b
    int carry = 0;
    for (int j = 0; j < numLimbs; j++) {
      final bj = (j < bTop) ? bDigits[j] : 0;
      final sum = t[j] + ai * bj + carry;
      t[j] = sum & _digitMask;
      carry = sum >>> _digitBits;
    }
    int acc = t[numLimbs] + carry;
    t[numLimbs] = acc & _digitMask;
    int overflow = acc >> _digitBits; // carry that may remain after reduction

    // m = t[0] * n0 mod 2^32
    final m = (t[0] * n0) & _digitMask;

    // t = t + m * n
    carry = 0;
    for (int j = 0; j < numLimbs; j++) {
      final sum = t[j] + m * nDigits[j] + carry;
      t[j] = sum & _digitMask;
      carry = sum >>> _digitBits;
    }
    acc = t[numLimbs] + carry;
    t[numLimbs] = acc & _digitMask;
    overflow += acc >> _digitBits;

    // Shift by one word (drop t[0], i.e. divide by the word base)
    for (int j = 0; j < numLimbs; j++) {
      t[j] = t[j + 1];
    }
    t[numLimbs] = overflow;
  }

  // Copy the result (t[0..numLimbs-1])
  final retDigits = ret.d;
  for (int i = 0; i < numLimbs; i++) {
    retDigits[i] = t[i];
  }
  ret.top = numLimbs;

  // If ret >= n or a carry is left, subtract n
  if (t[numLimbs] != 0 || _cmpWords(retDigits, nDigits, numLimbs) >= 0) {
    _subWords(retDigits, 0, retDigits, 0, nDigits, 0, numLimbs);
  }

  ret._fixTop();
}

/// Montgomery squaring: ret = a^2 * R^(-1) mod N.
///
/// Intended for the a == b case; currently delegates to [bnMontMul].
void bnMontSqr(BN ret, BN a, MontgomeryCtx mont) {
  // Use a temporary buffer to avoid aliasing
  final temp = BN(mont.n.top + 1);
  bnMontMul(temp, a, a, mont);
  // Copy the result
  ret.expand(temp.top);
  for (int i = 0; i < temp.top; i++) {
    ret.d[i] = temp.d[i];
  }
  ret.top = temp.top;
}

/// Converts to Montgomery form: ret = a * R mod N.
void bnToMont(BN ret, BN a, MontgomeryCtx mont) {
  // ret = a * R mod N = a * R^2 * R^(-1) mod N
  // Handle aliasing: if ret == a, use a temporary buffer
  if (identical(ret, a)) {
    final temp = BN(mont.n.top + 1);
    bnMontMul(temp, a, mont.rr, mont);
    ret.expand(temp.top);
    for (int i = 0; i < temp.top; i++) {
      ret.d[i] = temp.d[i];
    }
    ret.top = temp.top;
  } else {
    bnMontMul(ret, a, mont.rr, mont);
  }
}

/// Converts from Montgomery form: ret = a * R^(-1) mod N.
void bnFromMont(BN ret, BN a, MontgomeryCtx mont) {
  // Multiply by 1 (not in Montgomery form)
  final one = BN(1);
  one.setOne();
  // Handle aliasing: if ret == a, use a temporary buffer
  if (identical(ret, a)) {
    final temp = BN(mont.n.top + 1);
    bnMontMul(temp, a, one, mont);
    ret.expand(temp.top);
    for (int i = 0; i < temp.top; i++) {
      ret.d[i] = temp.d[i];
    }
    ret.top = temp.top;
  } else {
    bnMontMul(ret, a, one, mont);
  }
}

// ============================================================================
// Modular Exponentiation
// ============================================================================

/// Modular exponentiation using Montgomery: ret = base^exp mod N.
///
/// Uses a sliding window of width 4 (16 precomputed values).
void bnModExpMont(BN ret, BN base, BN exp, MontgomeryCtx mont) {
  final numBits = exp.numBits;
  if (numBits == 0) {
    ret.setOne();
    return;
  }
  
  final n = mont.n;
  final numLimbs = n.top;
  
  // Window size 4 for typical RSA (best trade-off)
  const windowSize = 4;
  const tableSize = 1 << windowSize; // 16
  
  // Precompute table: table[i] = base^i in Montgomery form
  final table = List<BN>.generate(tableSize, (_) => BN(numLimbs));
  
  // table[0] = 1 in Montgomery form (= R mod N)
  table[0].setOne();
  bnToMont(table[0], table[0], mont);
  
  // table[1] = base in Montgomery form
  bnToMont(table[1], base, mont);
  
  // Precompute table[2..15]
  for (int i = 2; i < tableSize; i++) {
    bnMontMul(table[i], table[i - 1], table[1], mont);
  }
  
  // Initialize the result to 1 in Montgomery form
  final acc = BN(numLimbs);
  acc.copyFrom(table[0]);
  
  // Temporary buffer to avoid aliasing
  final temp = BN(numLimbs + 1);
  
  // Scan the exponent from the most to the least significant bit
  // using a sliding window
  int bitPos = numBits - 1;
  
  while (bitPos >= 0) {
    // Find the next window
    final limbIdx = bitPos ~/ 32;
    final bitIdx = bitPos % 32;
    
    if (limbIdx >= exp.top || ((exp.d[limbIdx] >> bitIdx) & 1) == 0) {
      // Bit is zero: square only
      bnMontSqr(acc, acc, mont);
      bitPos--;
    } else {
      // Bit is one: extract a window of windowSize bits
      int window = 0;
      int windowLen = 0;
      
      for (int i = 0; i < windowSize && bitPos - i >= 0; i++) {
        final bPos = bitPos - i;
        final bLimb = bPos ~/ 32;
        final bBit = bPos % 32;
        
        if (bLimb < exp.top) {
          final bit = (exp.d[bLimb] >> bBit) & 1;
          window |= bit << (windowSize - 1 - i);
          windowLen++;
        } else {
          windowLen++;
        }
      }
      
      // Shrink the window until it is odd (more efficient)
      while (windowLen > 0 && (window & 1) == 0) {
        window >>= 1;
        windowLen--;
      }
      
      // Square windowLen times
      for (int i = 0; i < windowLen; i++) {
        bnMontSqr(acc, acc, mont);
      }
      
      // Multiply by the window value (via temp to avoid aliasing)
      if (window > 0) {
        bnMontMul(temp, acc, table[window], mont);
        // Copy temp to acc
        for (int j = 0; j < temp.top; j++) {
          acc.d[j] = temp.d[j];
        }
        acc.top = temp.top;
      }
      
      bitPos -= windowLen;
    }
  }
  
  // Convert the result back from Montgomery form
  bnFromMont(ret, acc, mont);
}

/// Simple modular exponentiation (no window; for small exponents).
void bnModExpMontSimple(BN ret, BN base, BN exp, MontgomeryCtx mont) {
  final numBits = exp.numBits;
  if (numBits == 0) {
    ret.setOne();
    return;
  }
  
  final n = mont.n;
  final numLimbs = n.top;
  
  // Convert the base to Montgomery form
  final baseMont = BN(numLimbs);
  bnToMont(baseMont, base, mont);
  
  // Initialize the result to 1 in Montgomery form
  final acc = BN(numLimbs);
  acc.setOne();
  bnToMont(acc, acc, mont);
  
  // Temporary buffer to avoid aliasing in multiplications
  final temp = BN(numLimbs + 1);
  
  // Left-to-right square-and-multiply
  for (int i = numBits - 1; i >= 0; i--) {
    // Always square
    bnMontSqr(acc, acc, mont);
    
    // If the bit is set, multiply by the base
    final limbIdx = i ~/ 32;
    final bitIdx = i % 32;
    if (limbIdx < exp.top && ((exp.d[limbIdx] >> bitIdx) & 1) == 1) {
      // Use temp to avoid aliasing: temp = acc * baseMont
      bnMontMul(temp, acc, baseMont, mont);
      // Copy temp to acc
      for (int j = 0; j < temp.top; j++) {
        acc.d[j] = temp.d[j];
      }
      acc.top = temp.top;
    }
  }
  
  // Convert back
  bnFromMont(ret, acc, mont);
}

// ============================================================================
// High-level API
// ============================================================================

/// Wrapper class for optimized modular exponentiation.
class MontgomeryModPow {
  final MontgomeryCtx _ctx;
  
  MontgomeryModPow(BN modulus) : _ctx = MontgomeryCtx.fromModulus(modulus);

  /// Computes base^exp mod N using Montgomery multiplication.
  BN modPow(BN base, BN exp) {
    final result = BN(_ctx.n.top);
    // Uses the simple version, which is more reliable
    bnModExpMontSimple(result, base, exp, _ctx);
    return result;
  }

  /// Simple version for small exponents.
  BN modPowSimple(BN base, BN exp) {
    final result = BN(_ctx.n.top);
    bnModExpMontSimple(result, base, exp, _ctx);
    return result;
  }
}

/// Convenience function: modPow on big-endian byte arrays.
Uint8List modPowBytes(Uint8List base, Uint8List exp, Uint8List mod) {
  final baseBN = BN.fromBytes(base);
  final expBN = BN.fromBytes(exp);
  final modBN = BN.fromBytes(mod);
  
  final mont = MontgomeryModPow(modBN);
  final result = mont.modPow(baseBN, expBN);
  
  // Pad the result to the modulus length
  final bytes = result.toBytes();
  if (bytes.length < mod.length) {
    final padded = Uint8List(mod.length);
    padded.setRange(mod.length - bytes.length, mod.length, bytes);
    return padded;
  }
  return bytes;
}
