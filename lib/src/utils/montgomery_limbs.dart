// dart format width=5000
//
// Montgomery Multiplication para RSA otimizado
//
// Esta implementação usa aritmética de limbs (base 2^32) para evitar BigInt
// em operações frequentes. Montgomery multiplication converte a exponenciação
// modular em multiplicações sem divisão.
//
// Referência: OpenSSL bn_asm.c, bn_local.h, bn_mont.c
// Limbs vs BigInt: Limbs é 20.90x mais lento que BigInt
// No Dart:
// - int é 64-bit em VM nativa
// - Usamos limbs de 32-bit para multiplicação 32x32→64 sem overflow
// - Similar ao BN_LLONG mode do OpenSSL

import 'dart:typed_data';

// ============================================================================
// Constantes e máscaras (similar ao OpenSSL bn_local.h)
// ============================================================================

const int _BN_BITS2 = 32; // Bits por limb
const int _BN_MASK2 = 0xFFFFFFFF; // Máscara para 32 bits

// ============================================================================
// Operações primitivas (similar ao OpenSSL bn_asm.c)
// ============================================================================

/// Extrai low word de um valor 64-bit
@pragma('vm:prefer-inline')
int _Lw(int t) => t & _BN_MASK2;

/// Extrai high word de um valor 64-bit
@pragma('vm:prefer-inline')
int _Hw(int t) => (t >> _BN_BITS2) & _BN_MASK2;

/// Multiply-add: r = a * w + r + c, retorna carry
/// Similar ao macro mul_add do OpenSSL
@pragma('vm:prefer-inline')
int _mulAdd(Uint32List r, int rIdx, int a, int w, int c) {
  // t = w * a + r[rIdx] + c (tudo em 64-bit)
  final t = w * a + r[rIdx] + c;
  r[rIdx] = _Lw(t);
  return _Hw(t);
}

/// Multiply: r = a * w + c, retorna carry
/// Similar ao macro mul do OpenSSL
@pragma('vm:prefer-inline')
int _mul(Uint32List r, int rIdx, int a, int w, int c) {
  final t = w * a + c;
  r[rIdx] = _Lw(t);
  return _Hw(t);
}

/// Square: (r1, r0) = a * a
@pragma('vm:prefer-inline')
void _sqr(Uint32List r, int rIdx, int a) {
  final t = a * a;
  r[rIdx] = _Lw(t);
  r[rIdx + 1] = _Hw(t);
}

// ============================================================================
// Funções de array (similar ao OpenSSL bn_asm.c)
// ============================================================================

/// bn_mul_add_words: rp += ap * w, retorna carry final
/// Similar ao OpenSSL bn_mul_add_words
int bnMulAddWords(Uint32List rp, int rpOff, Uint32List ap, int apOff, int num, int w) {
  int c = 0;
  
  // Unroll por 4 para performance (como OpenSSL)
  while (num >= 4) {
    c = _mulAdd(rp, rpOff + 0, ap[apOff + 0], w, c);
    c = _mulAdd(rp, rpOff + 1, ap[apOff + 1], w, c);
    c = _mulAdd(rp, rpOff + 2, ap[apOff + 2], w, c);
    c = _mulAdd(rp, rpOff + 3, ap[apOff + 3], w, c);
    rpOff += 4;
    apOff += 4;
    num -= 4;
  }
  
  while (num > 0) {
    c = _mulAdd(rp, rpOff, ap[apOff], w, c);
    rpOff++;
    apOff++;
    num--;
  }
  
  return c;
}

/// bn_mul_words: rp = ap * w, retorna carry final
int bnMulWords(Uint32List rp, int rpOff, Uint32List ap, int apOff, int num, int w) {
  int c = 0;
  
  while (num >= 4) {
    c = _mul(rp, rpOff + 0, ap[apOff + 0], w, c);
    c = _mul(rp, rpOff + 1, ap[apOff + 1], w, c);
    c = _mul(rp, rpOff + 2, ap[apOff + 2], w, c);
    c = _mul(rp, rpOff + 3, ap[apOff + 3], w, c);
    rpOff += 4;
    apOff += 4;
    num -= 4;
  }
  
  while (num > 0) {
    c = _mul(rp, rpOff, ap[apOff], w, c);
    rpOff++;
    apOff++;
    num--;
  }
  
  return c;
}

/// bn_add_words: rp = ap + bp, retorna carry
int bnAddWords(Uint32List rp, int rpOff, Uint32List ap, int apOff, Uint32List bp, int bpOff, int num) {
  int c = 0;
  
  while (num >= 4) {
    int t = ap[apOff + 0] + bp[bpOff + 0] + c;
    rp[rpOff + 0] = _Lw(t);
    c = _Hw(t);
    
    t = ap[apOff + 1] + bp[bpOff + 1] + c;
    rp[rpOff + 1] = _Lw(t);
    c = _Hw(t);
    
    t = ap[apOff + 2] + bp[bpOff + 2] + c;
    rp[rpOff + 2] = _Lw(t);
    c = _Hw(t);
    
    t = ap[apOff + 3] + bp[bpOff + 3] + c;
    rp[rpOff + 3] = _Lw(t);
    c = _Hw(t);
    
    rpOff += 4;
    apOff += 4;
    bpOff += 4;
    num -= 4;
  }
  
  while (num > 0) {
    final t = ap[apOff] + bp[bpOff] + c;
    rp[rpOff] = _Lw(t);
    c = _Hw(t);
    rpOff++;
    apOff++;
    bpOff++;
    num--;
  }
  
  return c;
}

/// bn_sub_words: rp = ap - bp, retorna borrow
int bnSubWords(Uint32List rp, int rpOff, Uint32List ap, int apOff, Uint32List bp, int bpOff, int num) {
  int c = 0; // borrow
  
  while (num >= 4) {
    int t = ap[apOff + 0] - bp[bpOff + 0] - c;
    rp[rpOff + 0] = _Lw(t);
    c = (t < 0) ? 1 : 0;
    
    t = ap[apOff + 1] - bp[bpOff + 1] - c;
    rp[rpOff + 1] = _Lw(t);
    c = (t < 0) ? 1 : 0;
    
    t = ap[apOff + 2] - bp[bpOff + 2] - c;
    rp[rpOff + 2] = _Lw(t);
    c = (t < 0) ? 1 : 0;
    
    t = ap[apOff + 3] - bp[bpOff + 3] - c;
    rp[rpOff + 3] = _Lw(t);
    c = (t < 0) ? 1 : 0;
    
    rpOff += 4;
    apOff += 4;
    bpOff += 4;
    num -= 4;
  }
  
  while (num > 0) {
    final t = ap[apOff] - bp[bpOff] - c;
    rp[rpOff] = _Lw(t);
    c = (t < 0) ? 1 : 0;
    rpOff++;
    apOff++;
    bpOff++;
    num--;
  }
  
  return c;
}

/// Compara dois arrays: retorna 1 se a > b, -1 se a < b, 0 se iguais
int bnCmpWords(Uint32List a, Uint32List b, int num) {
  for (int i = num - 1; i >= 0; i--) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

// ============================================================================
// BigNum - Representação de número grande como array de limbs
// ============================================================================

/// Número grande representado como array de limbs (little-endian)
class BN {
  /// Array de limbs (little-endian: limbs[0] é o menos significativo)
  Uint32List d;
  
  /// Número de limbs usados (top)
  int top;
  
  /// Capacidade alocada
  int dmax;
  
  /// Sinal negativo
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

  /// Cria BN a partir de bytes big-endian
  factory BN.fromBytes(Uint8List bytes) {
    if (bytes.isEmpty) return BN(1);
    
    // Calcula número de limbs necessários
    final numLimbs = (bytes.length + 3) ~/ 4;
    final bn = BN(numLimbs);
    
    // Converte big-endian bytes para little-endian limbs
    int limbIdx = 0;
    int shift = 0;
    int limb = 0;
    
    for (int i = bytes.length - 1; i >= 0; i--) {
      limb |= bytes[i] << shift;
      shift += 8;
      if (shift >= 32) {
        bn.d[limbIdx++] = limb & _BN_MASK2;
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

  /// Remove zeros à esquerda
  void _fixTop() {
    while (top > 0 && d[top - 1] == 0) {
      top--;
    }
    if (top == 0) neg = false;
  }

  /// Copia de outro BN
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

  /// Zera o número
  void zero() {
    for (int i = 0; i < dmax; i++) {
      d[i] = 0;
    }
    top = 0;
    neg = false;
  }

  /// Seta valor 1
  void setOne() {
    zero();
    d[0] = 1;
    top = 1;
  }

  /// Retorna se é zero
  bool get isZero => top == 0;

  /// Retorna se é um
  bool get isOne => top == 1 && d[0] == 1 && !neg;

  /// Número de bits
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

  /// Converte para bytes big-endian
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

  /// Expande capacidade se necessário
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

/// Contexto Montgomery para multiplicação modular eficiente
/// Similar ao bn_mont_ctx_st do OpenSSL
class MontgomeryCtx {
  /// Módulo N
  final BN n;
  
  /// R*R mod N (para converter para Montgomery form)
  final BN rr;
  
  /// Constante n0 = -N^(-1) mod 2^32
  /// (ou n0[0] e n0[1] para versão 64-bit)
  final int n0;
  
  /// Número de bits em R (ri)
  final int ri;

  MontgomeryCtx._({
    required this.n,
    required this.rr,
    required this.n0,
    required this.ri,
  });

  /// Cria contexto a partir do módulo
  factory MontgomeryCtx.fromModulus(BN mod) {
    final numLimbs = mod.top;
    final ri = numLimbs * _BN_BITS2;
    
    // Calcula n0 = -N^(-1) mod 2^32
    final n0 = _computeN0Inv(mod.d[0]);
    
    // Calcula R*R mod N
    final rr = _computeRR(mod, ri);
    
    // Copia módulo
    final n = BN(numLimbs);
    n.copyFrom(mod);
    
    return MontgomeryCtx._(n: n, rr: rr, n0: n0, ri: ri);
  }

  /// Calcula -N^(-1) mod 2^32 usando Newton's method
  static int _computeN0Inv(int n0) {
    // n0 deve ser ímpar para RSA
    // x = x * (2 - n0 * x) mod 2^k, dobrando k a cada iteração
    int x = n0; // x0 = n0 (works because n0 is odd)
    
    // 5 iterações para convergir em 32 bits
    x = (x * (2 - ((n0 * x) & _BN_MASK2))) & _BN_MASK2;
    x = (x * (2 - ((n0 * x) & _BN_MASK2))) & _BN_MASK2;
    x = (x * (2 - ((n0 * x) & _BN_MASK2))) & _BN_MASK2;
    x = (x * (2 - ((n0 * x) & _BN_MASK2))) & _BN_MASK2;
    x = (x * (2 - ((n0 * x) & _BN_MASK2))) & _BN_MASK2;
    
    return (-x) & _BN_MASK2;
  }

  /// Calcula R*R mod N onde R = 2^ri
  static BN _computeRR(BN mod, int ri) {
    final numLimbs = mod.top;
    
    // R = 2^ri, R*R = 2^(2*ri)
    // Calculamos 2^(2*ri) mod N usando shifts e subtrações
    
    // Começa com 1
    final rr = BN(numLimbs * 2 + 1);
    rr.setOne();
    
    // Shift left 2*ri bits, fazendo mod N a cada passo
    for (int i = 0; i < ri * 2; i++) {
      // rr = rr * 2
      int carry = 0;
      for (int j = 0; j < rr.top; j++) {
        int t = (rr.d[j] << 1) | carry;
        rr.d[j] = t & _BN_MASK2;
        carry = t >> 32;
      }
      if (carry != 0) {
        if (rr.top < rr.dmax) {
          rr.d[rr.top] = carry;
          rr.top++;
        }
      }
      
      // Se rr >= mod, subtrai mod (apenas uma vez por iteração)
      if (_bnCmp(rr, mod) >= 0) {
        _bnSubInPlace(rr, mod);
      }
    }
    
    return rr;
  }
  
  /// Compara dois BN: retorna 1 se a > b, -1 se a < b, 0 se iguais
  static int _bnCmp(BN a, BN b) {
    if (a.top > b.top) return 1;
    if (a.top < b.top) return -1;
    for (int i = a.top - 1; i >= 0; i--) {
      if (a.d[i] > b.d[i]) return 1;
      if (a.d[i] < b.d[i]) return -1;
    }
    return 0;
  }
  
  /// Subtrai b de a in-place: a = a - b (assume a >= b)
  static void _bnSubInPlace(BN a, BN b) {
    int borrow = 0;
    for (int i = 0; i < a.top; i++) {
      final bi = i < b.top ? b.d[i] : 0;
      final diff = a.d[i] - bi - borrow;
      if (diff < 0) {
        a.d[i] = (diff + 0x100000000) & _BN_MASK2;
        borrow = 1;
      } else {
        a.d[i] = diff & _BN_MASK2;
        borrow = 0;
      }
    }
    a._fixTop();
  }
}

// ============================================================================
// Montgomery Multiplication
// ============================================================================

/// Multiplicação Montgomery: ret = a * b * R^(-1) mod N
/// Implementa o algoritmo CIOS (Coarsely Integrated Operand Scanning)
void bnMontMul(BN ret, BN a, BN b, MontgomeryCtx mont) {
  final n = mont.n;
  final numLimbs = n.top;
  final n0 = mont.n0;
  
  // Garante espaço suficiente
  ret.expand(numLimbs + 1);
  
  // Temp para resultado intermediário (precisa de 2*numLimbs + 1)
  final t = Uint32List(numLimbs * 2 + 2);
  
  // CIOS: Para cada limb de a
  for (int i = 0; i < numLimbs; i++) {
    final ai = i < a.top ? a.d[i] : 0;
    
    // t = t + a[i] * b
    int carry = 0;
    for (int j = 0; j < numLimbs; j++) {
      final bj = j < b.top ? b.d[j] : 0;
      // Multiplica 32x32 usando int de 64 bits do Dart
      // ai * bj cabe em 64 bits (32+32=64)
      final prod = ai * bj; // até 64 bits
      final sum = t[i + j] + (prod & 0xFFFFFFFF) + carry;
      t[i + j] = sum & 0xFFFFFFFF;
      carry = (prod >>> 32) + (sum >>> 32);
    }
    // Propaga carry para palavras superiores
    int idx = i + numLimbs;
    while (carry != 0 && idx < t.length) {
      final sum = t[idx] + carry;
      t[idx] = sum & 0xFFFFFFFF;
      carry = sum >>> 32;
      idx++;
    }
    
    // m = t[i] * n0 mod 2^32
    final m = (t[i] * n0) & 0xFFFFFFFF;
    
    // t = t + m * n
    carry = 0;
    for (int j = 0; j < numLimbs; j++) {
      final nj = n.d[j];
      final prod = m * nj;
      final sum = t[i + j] + (prod & 0xFFFFFFFF) + carry;
      t[i + j] = sum & 0xFFFFFFFF;
      carry = (prod >>> 32) + (sum >>> 32);
    }
    // Propaga carry
    idx = i + numLimbs;
    while (carry != 0 && idx < t.length) {
      final sum = t[idx] + carry;
      t[idx] = sum & 0xFFFFFFFF;
      carry = sum >>> 32;
      idx++;
    }
  }
  
  // Copia resultado (shift right por numLimbs words)
  for (int i = 0; i < numLimbs; i++) {
    ret.d[i] = t[i + numLimbs];
  }
  ret.top = numLimbs;
  
  // Se ret >= n, subtrai n
  if (t[numLimbs * 2] != 0 || bnCmpWords(ret.d, n.d, numLimbs) >= 0) {
    bnSubWords(ret.d, 0, ret.d, 0, n.d, 0, numLimbs);
  }
  
  ret._fixTop();
}

/// Quadrado Montgomery: ret = a^2 * R^(-1) mod N
/// Otimizado para quando a == b
void bnMontSqr(BN ret, BN a, MontgomeryCtx mont) {
  // Por enquanto, usa multiplicação normal
  // TODO: Otimizar com squaring específico
  bnMontMul(ret, a, a, mont);
}

/// Converte para Montgomery form: ret = a * R mod N
void bnToMont(BN ret, BN a, MontgomeryCtx mont) {
  // ret = a * R mod N = a * R^2 * R^(-1) mod N
  bnMontMul(ret, a, mont.rr, mont);
}

/// Converte de Montgomery form: ret = a * R^(-1) mod N
void bnFromMont(BN ret, BN a, MontgomeryCtx mont) {
  // Multiplica por 1 (que não está em Montgomery form)
  final one = BN(1);
  one.setOne();
  bnMontMul(ret, a, one, mont);
}

// ============================================================================
// Modular Exponentiation
// ============================================================================

/// Exponenciação modular usando Montgomery: ret = base^exp mod N
/// Usa sliding window com width 4 (16 precomputations)
void bnModExpMont(BN ret, BN base, BN exp, MontgomeryCtx mont) {
  final numBits = exp.numBits;
  if (numBits == 0) {
    ret.setOne();
    return;
  }
  
  final n = mont.n;
  final numLimbs = n.top;
  
  // Window size 4 para RSA típico (melhor trade-off)
  const windowSize = 4;
  const tableSize = 1 << windowSize; // 16
  
  // Precomputa tabela: table[i] = base^i em Montgomery form
  final table = List<BN>.generate(tableSize, (_) => BN(numLimbs));
  
  // table[0] = 1 em Montgomery form (= R mod N)
  table[0].setOne();
  bnToMont(table[0], table[0], mont);
  
  // table[1] = base em Montgomery form
  bnToMont(table[1], base, mont);
  
  // Precomputa table[2..15]
  for (int i = 2; i < tableSize; i++) {
    bnMontMul(table[i], table[i - 1], table[1], mont);
  }
  
  // Inicializa resultado com 1 em Montgomery form
  final acc = BN(numLimbs);
  acc.copyFrom(table[0]);
  
  // Processa expoente do bit mais significativo para o menos significativo
  // usando sliding window
  int bitPos = numBits - 1;
  
  while (bitPos >= 0) {
    // Encontra próxima janela
    final limbIdx = bitPos ~/ 32;
    final bitIdx = bitPos % 32;
    
    if (limbIdx >= exp.top || ((exp.d[limbIdx] >> bitIdx) & 1) == 0) {
      // Bit é zero, só faz um squaring
      bnMontSqr(acc, acc, mont);
      bitPos--;
    } else {
      // Bit é 1, extrai janela de windowSize bits
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
      
      // Ajusta janela para ser ímpar (mais eficiente)
      while (windowLen > 0 && (window & 1) == 0) {
        window >>= 1;
        windowLen--;
      }
      
      // Faz windowLen squarings
      for (int i = 0; i < windowLen; i++) {
        bnMontSqr(acc, acc, mont);
      }
      
      // Multiplica pelo valor da janela
      if (window > 0) {
        bnMontMul(acc, acc, table[window], mont);
      }
      
      bitPos -= windowLen;
    }
  }
  
  // Converte resultado de volta do Montgomery form
  bnFromMont(ret, acc, mont);
}

/// Exponenciação modular simples (sem window, para expoentes pequenos)
void bnModExpMontSimple(BN ret, BN base, BN exp, MontgomeryCtx mont) {
  final numBits = exp.numBits;
  if (numBits == 0) {
    ret.setOne();
    return;
  }
  
  final n = mont.n;
  final numLimbs = n.top;
  
  // Converte base para Montgomery form
  final baseMont = BN(numLimbs);
  bnToMont(baseMont, base, mont);
  
  // Inicializa resultado com 1 em Montgomery form
  final acc = BN(numLimbs);
  acc.setOne();
  bnToMont(acc, acc, mont);
  
  // Square-and-multiply da esquerda para direita
  for (int i = numBits - 1; i >= 0; i--) {
    // Sempre faz squaring
    bnMontSqr(acc, acc, mont);
    
    // Se bit é 1, multiplica pela base
    final limbIdx = i ~/ 32;
    final bitIdx = i % 32;
    if (limbIdx < exp.top && ((exp.d[limbIdx] >> bitIdx) & 1) == 1) {
      bnMontMul(acc, acc, baseMont, mont);
    }
  }
  
  // Converte de volta
  bnFromMont(ret, acc, mont);
}

// ============================================================================
// API de Alto Nível
// ============================================================================

/// Classe wrapper para exponenciação modular otimizada
class MontgomeryModPow {
  final MontgomeryCtx _ctx;
  
  MontgomeryModPow(BN modulus) : _ctx = MontgomeryCtx.fromModulus(modulus);

  /// Calcula base^exp mod N usando Montgomery multiplication
  BN modPow(BN base, BN exp) {
    final result = BN(_ctx.n.top);
    // Usa versão simples que é mais confiável
    bnModExpMontSimple(result, base, exp, _ctx);
    return result;
  }

  /// Versão simples para expoentes pequenos
  BN modPowSimple(BN base, BN exp) {
    final result = BN(_ctx.n.top);
    bnModExpMontSimple(result, base, exp, _ctx);
    return result;
  }
}

/// Função conveniente para modPow com bytes
Uint8List modPowBytes(Uint8List base, Uint8List exp, Uint8List mod) {
  final baseBN = BN.fromBytes(base);
  final expBN = BN.fromBytes(exp);
  final modBN = BN.fromBytes(mod);
  
  final mont = MontgomeryModPow(modBN);
  final result = mont.modPow(baseBN, expBN);
  
  // Retorna com padding para tamanho do módulo
  final bytes = result.toBytes();
  if (bytes.length < mod.length) {
    final padded = Uint8List(mod.length);
    padded.setRange(mod.length - bytes.length, mod.length, bytes);
    return padded;
  }
  return bytes;
}
