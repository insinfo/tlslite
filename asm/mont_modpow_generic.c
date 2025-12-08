/**
 * Montgomery modular exponentiation genérico
 * Suporta tamanhos: 512, 1024 bits (8, 16 limbs)
 * 
 * NOTA: 
 * - Não usar VLAs pois não funcionam em shellcode!
 * - Usar __attribute__((always_inline)) para forçar inline
 * - Não chamar funções externas (memset, memcpy, etc)
 * 
 * Compilar com:
 * gcc -O3 -fno-stack-protector -fno-asynchronous-unwind-tables -nostdlib -fPIC -c mont_modpow_generic.c -o mont_modpow_generic.o
 * objcopy -O binary -j .text mont_modpow_generic.o mont_modpow_generic.bin
 */

#include <stdint.h>

// Tamanho máximo suportado: 1024 bits = 16 limbs de 64 bits
#define MAX_LIMBS 16

typedef uint64_t u64;
typedef __uint128_t u128;

// Multiplicação Montgomery CIOS genérica - FORÇAR INLINE!
__attribute__((always_inline))
static inline void mont_mul(u64 *result, const u64 *a, const u64 *b,
                            const u64 *n, u64 n0, u64 num_limbs) {
    u64 t[MAX_LIMBS * 2 + 2];  // Buffer fixo para produto
    
    // Zera t manualmente (não usar memset!)
    for (u64 i = 0; i < MAX_LIMBS * 2 + 2; i++) {
        t[i] = 0;
    }
    
    // CIOS algorithm
    for (u64 i = 0; i < num_limbs; i++) {
        u64 carry = 0;
        u64 ai = a[i];
        
        // t += ai * b
        for (u64 j = 0; j < num_limbs; j++) {
            u128 prod = (u128)ai * b[j] + t[i + j] + carry;
            t[i + j] = (u64)prod;
            carry = (u64)(prod >> 64);
        }
        t[i + num_limbs] += carry;
        if (t[i + num_limbs] < carry) {
            t[i + num_limbs + 1]++;
        }
        
        // m = t[i] * n0 mod 2^64
        u64 m = t[i] * n0;
        
        // t += m * n
        carry = 0;
        for (u64 j = 0; j < num_limbs; j++) {
            u128 prod = (u128)m * n[j] + t[i + j] + carry;
            t[i + j] = (u64)prod;
            carry = (u64)(prod >> 64);
        }
        
        // Propaga carry
        for (u64 j = num_limbs; t[i + j] + carry < t[i + j] || carry; j++) {
            u64 old = t[i + j];
            t[i + j] += carry;
            carry = (t[i + j] < old) ? 1 : 0;
            if (j >= num_limbs * 2) break;
        }
    }
    
    // Copia resultado (parte alta de t)
    for (u64 i = 0; i < num_limbs; i++) {
        result[i] = t[num_limbs + i];
    }
    
    // Redução condicional se result >= n
    // Primeiro verifica se há overflow (t[num_limbs*2] > 0) ou result >= n
    int need_sub = 0;
    if (t[num_limbs * 2] > 0) {
        need_sub = 1;
    } else {
        // Compara result com n
        for (int i = num_limbs - 1; i >= 0; i--) {
            if (result[i] > n[i]) {
                need_sub = 1;
                break;
            } else if (result[i] < n[i]) {
                break;
            }
        }
    }
    
    if (need_sub) {
        u64 borrow = 0;
        for (u64 i = 0; i < num_limbs; i++) {
            u128 diff = (u128)result[i] - n[i] - borrow;
            result[i] = (u64)diff;
            borrow = (diff >> 64) & 1;
        }
    }
}

// Conta bits do expoente - FORÇAR INLINE!
__attribute__((always_inline))
static inline u64 count_bits(const u64 *exp, u64 num_limbs) {
    for (int i = num_limbs - 1; i >= 0; i--) {
        if (exp[i] != 0) {
            u64 limb = exp[i];
            u64 bits = 0;
            while (limb > 0) {
                bits++;
                limb >>= 1;
            }
            return i * 64 + bits;
        }
    }
    return 0;
}

/**
 * Montgomery modular exponentiation genérico
 * 
 * result = base^exp mod n
 * 
 * Parâmetros (Windows x64 calling convention):
 *   RCX: result      - ponteiro para resultado (num_limbs limbs)
 *   RDX: base        - ponteiro para base (num_limbs limbs)
 *   R8:  exp         - ponteiro para expoente (num_limbs limbs)
 *   R9:  n           - ponteiro para módulo (num_limbs limbs)
 *   [RSP+40]: n0     - -n^-1 mod 2^64
 *   [RSP+48]: rr     - ponteiro para R^2 mod n (num_limbs limbs)
 *   [RSP+56]: num_limbs - número de limbs (8, 16 para 512, 1024 bits)
 */
void mont_modpow_generic(u64 *result, const u64 *base, 
                        const u64 *exp, const u64 *n,
                        u64 n0, const u64 *rr, u64 num_limbs) {
    // Buffers com tamanho máximo fixo (evita VLAs)
    u64 base_mont[MAX_LIMBS];
    u64 acc[MAX_LIMBS];
    u64 temp[MAX_LIMBS];
    u64 one[MAX_LIMBS];
    
    // Limita num_limbs ao máximo suportado
    if (num_limbs > MAX_LIMBS) {
        num_limbs = MAX_LIMBS;
    }
    
    // Inicializa one = 1 (manualmente, sem memset)
    one[0] = 1;
    for (u64 i = 1; i < MAX_LIMBS; i++) {
        one[i] = 0;
    }
    
    // Zera outros buffers (manualmente)
    for (u64 i = 0; i < MAX_LIMBS; i++) {
        base_mont[i] = 0;
        acc[i] = 0;
        temp[i] = 0;
    }
    
    // Converte base para Montgomery: base_mont = base * R mod n
    mont_mul(base_mont, base, rr, n, n0, num_limbs);
    
    // Conta bits do expoente
    u64 exp_bits = count_bits(exp, num_limbs);
    if (exp_bits == 0) {
        // exp = 0, retorna 1
        for (u64 i = 0; i < num_limbs; i++) {
            result[i] = (i == 0) ? 1 : 0;
        }
        return;
    }
    
    // Inicializa acc = 1 em Montgomery: acc = 1 * R mod n
    mont_mul(acc, one, rr, n, n0, num_limbs);
    
    // Exponenciação binária simples (left-to-right)
    for (int i = exp_bits - 1; i >= 0; i--) {
        // Square: acc = acc^2
        mont_mul(temp, acc, acc, n, n0, num_limbs);
        // Copia temp -> acc (manualmente)
        for (u64 j = 0; j < num_limbs; j++) {
            acc[j] = temp[j];
        }
        
        // Multiply se bit está setado
        u64 limb_idx = i / 64;
        u64 bit_idx = i % 64;
        if ((exp[limb_idx] & (1ULL << bit_idx)) != 0) {
            mont_mul(temp, acc, base_mont, n, n0, num_limbs);
            for (u64 j = 0; j < num_limbs; j++) {
                acc[j] = temp[j];
            }
        }
    }
    
    // Converte de volta do domínio Montgomery: result = acc * 1
    mont_mul(result, acc, one, n, n0, num_limbs);
}
