/**
 * Montgomery modPow for 4 limbs (256-bit)
 *  C:\MyDartProjects\tlslite\referencias\sdk-main\sdk\lib\_internal\vm_shared\lib\bigint_patch.dart
 * Compile with:
 *   cl /O2 /c mont_modpow_4limbs.c
 *   
 * Or GCC:
 *   gcc -O3 -S -masm=intel mont_modpow_4limbs.c -o mont_modpow_4limbs.s
 *   gcc -O3 -c mont_modpow_4limbs.c -o mont_modpow_4limbs.o
 *
 * For shellcode (no CRT):
 *   gcc -O3 -fno-stack-protector -fno-asynchronous-unwind-tables -nostdlib -c mont_modpow_4limbs.c
 */

#include <stdint.h>

typedef uint64_t u64;
typedef __uint128_t u128;

// Montgomery multiplication: result = a * b * R^-1 mod n
// Uses CIOS (Coarsely Integrated Operand Scanning)
__attribute__((always_inline))
static inline void mont_mul(u64 result[4], const u64 a[4], const u64 b[4], 
                            const u64 n[4], u64 n0) {
    u64 acc[5] = {0, 0, 0, 0, 0};  // 5 limbs for overflow
    u64 overflow = 0;  // Track overflow beyond acc[4]
    
    for (int i = 0; i < 4; i++) {
        // Multiply: acc += a[i] * b
        u64 carry = 0;
        for (int j = 0; j < 4; j++) {
            u128 prod = (u128)a[i] * b[j] + acc[j] + carry;
            acc[j] = (u64)prod;
            carry = (u64)(prod >> 64);
        }
        u128 sum = (u128)acc[4] + carry;
        acc[4] = (u64)sum;
        overflow += (u64)(sum >> 64);  // Accumulate overflow
        
        // Reduce: m = acc[0] * n0 mod 2^64, then acc += m * n
        u64 m = acc[0] * n0;
        carry = 0;
        for (int j = 0; j < 4; j++) {
            u128 prod = (u128)m * n[j] + acc[j] + carry;
            acc[j] = (u64)prod;
            carry = (u64)(prod >> 64);
        }
        sum = (u128)acc[4] + carry;
        acc[4] = (u64)sum;
        overflow += (u64)(sum >> 64);  // Accumulate overflow
        
        // Shift right by 64 bits
        acc[0] = acc[1];
        acc[1] = acc[2];
        acc[2] = acc[3];
        acc[3] = acc[4];
        acc[4] = overflow;  // Preserve overflow
        overflow = 0;
    }
    
    // Conditional subtraction if acc >= n
    // Need to handle acc[4] != 0 case
    if (acc[4] > 0 || (acc[3] > n[3] || (acc[3] == n[3] && 
        (acc[2] > n[2] || (acc[2] == n[2] && 
        (acc[1] > n[1] || (acc[1] == n[1] && acc[0] >= n[0]))))))) {
        // Subtract n
        u64 borrow = 0;
        for (int j = 0; j < 4; j++) {
            u128 diff = (u128)acc[j] - n[j] - borrow;
            result[j] = (u64)diff;
            borrow = (diff >> 64) & 1;
        }
    } else {
        for (int j = 0; j < 4; j++) result[j] = acc[j];
    }
}

// Montgomery squaring: result = a^2 * R^-1 mod n
// Optimized: exploits symmetry a[i]*a[j] = a[j]*a[i]
static inline void mont_sqr(u64 result[4], const u64 a[4], 
                            const u64 n[4], u64 n0) {
    // For simplicity, just use multiplication
    // A more optimized version would exploit symmetry
    mont_mul(result, a, a, n, n0);
}

// Count bits in exponent
static inline int count_bits(const u64 exp[4]) {
    for (int i = 3; i >= 0; i--) {
        if (exp[i] != 0) {
            // Find highest bit in this limb
            u64 x = exp[i];
            int bits = i * 64;
            while (x) {
                bits++;
                x >>= 1;
            }
            return bits;
        }
    }
    return 0;
}

/**
 * Montgomery modular exponentiation: result = base^exp mod n
 * 
 * All values are 4 limbs (256-bit), little-endian
 * 
 * Uses sliding-window exponentiation for better performance with larger exponents.
 * Window size is chosen based on exponent bit length:
 *   < 18 bits:  k=1 (binary exponentiation)
 *   < 48 bits:  k=3
 *   < 144 bits: k=4
 *   >= 144 bits: k=5
 * 
 * Parameters (Windows x64 ABI):
 *   RCX = result pointer (4 x u64)
 *   RDX = base pointer (4 x u64)  
 *   R8  = exp pointer (4 x u64)
 *   R9  = n pointer (4 x u64)
 *   [RSP+40] = n0 (u64)
 *   [RSP+48] = rr pointer (4 x u64) - R^2 mod n for Montgomery conversion
 */
void mont_modpow_4limbs(u64 *result, const u64 *base, const u64 *exp, 
                         const u64 *n, u64 n0, const u64 *rr) {
    u64 one[4] = {1, 0, 0, 0};
    u64 baseMont[4];
    u64 temp[4];
    
    // Convert base to Montgomery domain: baseMont = base * R mod n
    mont_mul(baseMont, base, rr, n, n0);
    
    int expBits = count_bits(exp);
    if (expBits == 0) {
        result[0] = 1;
        result[1] = 0;
        result[2] = 0;
        result[3] = 0;
        return;
    }
    
    // Choose window size based on exponent bit length (like Dart BigInt)
    int k;
    if (expBits < 18) {
        k = 1;  // Binary exponentiation
    } else if (expBits < 48) {
        k = 3;
    } else if (expBits < 144) {
        k = 4;
    } else {
        k = 5;
    }
    
    // For small k, use simple binary exponentiation
    if (k == 1) {
        u64 acc[4];
        // Initialize accumulator as 1 in Montgomery: acc = 1 * R mod n
        mont_mul(acc, one, rr, n, n0);
        
        for (int i = expBits - 1; i >= 0; i--) {
            // Square: acc = acc^2
            mont_sqr(temp, acc, n, n0);
            for (int j = 0; j < 4; j++) acc[j] = temp[j];
            
            // Multiply if bit is set
            int limbIdx = i / 64;
            int bitIdx = i % 64;
            if ((exp[limbIdx] >> bitIdx) & 1) {
                mont_mul(temp, acc, baseMont, n, n0);
                for (int j = 0; j < 4; j++) acc[j] = temp[j];
            }
        }
        
        // Convert back from Montgomery: result = acc * 1 * R^-1 mod n
        mont_mul(result, acc, one, n, n0);
        
        // DEBUG: verify acc before final conversion
        // After loop, acc should be the result in Montgomery form
        // result should be acc * R^-1
        
        return;
    }
    
    // Sliding-window exponentiation for k > 1
    const int k1 = k - 1;
    const int km = (1 << k) - 1;  // 2^k - 1
    
    // Pre-compute odd powers: g[1], g[3], g[5], ..., g[2^k-1]
    // We need (2^k-1)/2 = 2^(k-1) entries
    u64 g[32][4];  // Max window size k=5 needs 16 entries
    
    // g[1] = baseMont
    for (int j = 0; j < 4; j++) g[1][j] = baseMont[j];
    
    if (k > 1) {
        // g[2] = baseMont^2
        u64 g2[4];
        mont_sqr(g2, baseMont, n, n0);
        
        // Pre-compute odd powers: g[3], g[5], ..., g[2^k-1]
        for (int i = 3; i <= km; i += 2) {
            mont_mul(g[i], g[i - 2], g2, n, n0);
        }
    }
    
    // Main exponentiation loop
    u64 acc[4];
    int isOne = 1;  // Track if acc is still 1
    
    // Start from most significant limb
    int j = 3;
    while (j >= 0 && exp[j] == 0) j--;
    if (j < 0) {
        result[0] = 1;
        result[1] = 0;
        result[2] = 0;
        result[3] = 0;
        return;
    }
    
    // Find bit position of MSB in exp[j]
    int i = 63;
    while (i >= 0 && !((exp[j] >> i) & 1)) i--;
    
    // Process bits
    while (j >= 0) {
        int w;
        if (i >= k1) {
            // Extract k-bit window
            w = (exp[j] >> (i - k1)) & km;
        } else {
            // Window spans limb boundary
            w = (exp[j] & ((1ULL << (i + 1)) - 1)) << (k1 - i);
            if (j > 0) {
                w |= exp[j - 1] >> (64 + i - k1);
            }
        }
        
        // Skip leading zeros in window
        int nSquares = k;
        while ((w & 1) == 0) {
            w >>= 1;
            --nSquares;
        }
        
        // Update bit position
        i -= nSquares;
        if (i < 0) {
            i += 64;
            --j;
        }
        
        // Skip if w became 0 (shouldn't happen in correct implementation)
        if (w == 0) continue;
        
        if (isOne) {
            // First non-zero window: acc = g[w]
            for (int idx = 0; idx < 4; idx++) acc[idx] = g[w][idx];
            isOne = 0;
        } else {
            // Square nSquares times
            while (nSquares > 1) {
                mont_sqr(temp, acc, n, n0);
                mont_sqr(acc, temp, n, n0);
                nSquares -= 2;
            }
            if (nSquares > 0) {
                mont_sqr(temp, acc, n, n0);
                for (int idx = 0; idx < 4; idx++) acc[idx] = temp[idx];
            }
            
            // Multiply by g[w]
            mont_mul(temp, acc, g[w], n, n0);
            for (int idx = 0; idx < 4; idx++) acc[idx] = temp[idx];
        }
        
        // Square for remaining zero bits until next window
        while (j >= 0 && !((exp[j] >> i) & 1)) {
            mont_sqr(temp, acc, n, n0);
            for (int idx = 0; idx < 4; idx++) acc[idx] = temp[idx];
            
            if (--i < 0) {
                i = 63;
                --j;
            }
        }
    }
    
    // Convert back from Montgomery: result = acc * 1 * R^-1 mod n
    mont_mul(result, acc, one, n, n0);
}
