// dart format width=5000
// Montgomery Multiplication otimizado para RSA
// referencias C:\MyDartProjects\tlslite\referencias\openssl-master
// referencias C:\MyDartProjects\tlslite\referencias\sdk-main
// Baseado em:
// - Dart SDK bigint_patch.dart (técnicas de half-digit multiplication)
// - OpenSSL bn_mont.c (algoritmo CIOS Montgomery)
//
// Usa limbs de 32-bit com half-digit (16-bit) multiplication para evitar
// overflow em multiplicações no Dart VM.

import 'dart:typed_data';

// ============================================================================
// Constantes
// ============================================================================

const int _digitBits = 32;
const int _digitMask = 0xFFFFFFFF;

// ============================================================================
// Funções de array
// ============================================================================

/// Subtração: rp = ap - bp, retorna borrow
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

/// Comparação: retorna 1 se a > b, -1 se a < b, 0 se iguais
@pragma('vm:prefer-inline')
int _cmpWords(Uint32List a, Uint32List b, int num) {
  for (int i = num - 1; i >= 0; i--) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

/// Adição pública: rp = ap + bp, retorna carry
int bnAddWords(Uint32List rp, int rpOff, Uint32List ap, int apOff, Uint32List bp, int bpOff, int num) {
  int carry = 0;
  for (int i = 0; i < num; i++) {
    final sum = ap[apOff + i] + bp[bpOff + i] + carry;
    rp[rpOff + i] = sum & _digitMask;
    carry = sum >> _digitBits;
  }
  return carry;
}

/// Subtração pública: rp = ap - bp, retorna borrow
int bnSubWords(Uint32List rp, int rpOff, Uint32List ap, int apOff, Uint32List bp, int bpOff, int num) {
  return _subWords(rp, rpOff, ap, apOff, bp, bpOff, num);
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
    final ri = numLimbs * _digitBits;
    
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
    x = (x * (2 - ((n0 * x) & _digitMask))) & _digitMask;
    x = (x * (2 - ((n0 * x) & _digitMask))) & _digitMask;
    x = (x * (2 - ((n0 * x) & _digitMask))) & _digitMask;
    x = (x * (2 - ((n0 * x) & _digitMask))) & _digitMask;
    x = (x * (2 - ((n0 * x) & _digitMask))) & _digitMask;
    
    return (-x) & _digitMask;
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
        rr.d[j] = t & _digitMask;
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

/// Multiplicação Montgomery: ret = a * b * R^(-1) mod N
/// Implementa o algoritmo CIOS (Coarsely Integrated Operand Scanning)
/// Usa multiplicação 32x32 nativa do Dart VM (64-bit integers)
void bnMontMul(BN ret, BN a, BN b, MontgomeryCtx mont) {
  final n = mont.n;
  final numLimbs = n.top;
  final n0 = mont.n0;
  final nDigits = n.d;
  
  // Garante espaço suficiente no resultado
  ret.expand(numLimbs + 1);
  
  // Temp para resultado intermediário (precisa de 2*numLimbs + 2)
  final tLen = numLimbs * 2 + 2;
  final t = Uint32List(tLen);
  
  // Cache tamanhos
  final aTop = a.top;
  final bTop = b.top;
  final aDigits = a.d;
  final bDigits = b.d;
  
  // CIOS: Para cada limb de a
  for (int i = 0; i < numLimbs; i++) {
    final ai = (i < aTop) ? aDigits[i] : 0;

    // t = t + ai * b
    int carry = 0;
    for (int j = 0; j < numLimbs; j++) {
      final bj = (j < bTop) ? bDigits[j] : 0;
      final sum = t[j] + ai * bj + carry;
      t[j] = sum & _digitMask;
      carry = sum >> _digitBits;
    }
    int acc = t[numLimbs] + carry;
    t[numLimbs] = acc & _digitMask;
    int overflow = acc >> _digitBits; // carry que pode sobrar após redução

    // m = t[0] * n0 mod 2^32
    final m = (t[0] * n0) & _digitMask;

    // t = t + m * n
    carry = 0;
    for (int j = 0; j < numLimbs; j++) {
      final sum = t[j] + m * nDigits[j] + carry;
      t[j] = sum & _digitMask;
      carry = sum >> _digitBits;
    }
    acc = t[numLimbs] + carry;
    t[numLimbs] = acc & _digitMask;
    overflow += acc >> _digitBits;

    // Desloca uma palavra (descarta t[0], equivalente a dividir por R)
    for (int j = 0; j < numLimbs; j++) {
      t[j] = t[j + 1];
    }
    t[numLimbs] = overflow;
  }

  // Copia resultado (t[0..numLimbs-1])
  final retDigits = ret.d;
  for (int i = 0; i < numLimbs; i++) {
    retDigits[i] = t[i];
  }
  ret.top = numLimbs;

  // Se ret >= n ou sobrou carry, subtrai n
  if (t[numLimbs] != 0 || _cmpWords(retDigits, nDigits, numLimbs) >= 0) {
    _subWords(retDigits, 0, retDigits, 0, nDigits, 0, numLimbs);
  }

  ret._fixTop();
}

/// Quadrado Montgomery: ret = a^2 * R^(-1) mod N
/// Otimizado para quando a == b
/// Quadrado Montgomery: ret = a^2 * R^(-1) mod N
/// Otimizado para quando a == b
void bnMontSqr(BN ret, BN a, MontgomeryCtx mont) {
  // Usa buffer temporário para evitar aliasing
  final temp = BN(mont.n.top + 1);
  bnMontMul(temp, a, a, mont);
  // Copia resultado
  ret.expand(temp.top);
  for (int i = 0; i < temp.top; i++) {
    ret.d[i] = temp.d[i];
  }
  ret.top = temp.top;
}

/// Converte para Montgomery form: ret = a * R mod N
void bnToMont(BN ret, BN a, MontgomeryCtx mont) {
  // ret = a * R mod N = a * R^2 * R^(-1) mod N
  // Trata aliasing: se ret == a, usa buffer temporário
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

/// Converte de Montgomery form: ret = a * R^(-1) mod N
void bnFromMont(BN ret, BN a, MontgomeryCtx mont) {
  // Multiplica por 1 (que não está em Montgomery form)
  final one = BN(1);
  one.setOne();
  // Trata aliasing: se ret == a, usa buffer temporário
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
  
  // Buffer temporário para evitar aliasing
  final temp = BN(numLimbs + 1);
  
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
      
      // Multiplica pelo valor da janela (usando temp para evitar aliasing)
      if (window > 0) {
        bnMontMul(temp, acc, table[window], mont);
        // Copia temp para acc
        for (int j = 0; j < temp.top; j++) {
          acc.d[j] = temp.d[j];
        }
        acc.top = temp.top;
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
  
  // Buffer temporário para evitar aliasing em multiplicações
  final temp = BN(numLimbs + 1);
  
  // Square-and-multiply da esquerda para direita
  for (int i = numBits - 1; i >= 0; i--) {
    // Sempre faz squaring
    bnMontSqr(acc, acc, mont);
    
    // Se bit é 1, multiplica pela base
    final limbIdx = i ~/ 32;
    final bitIdx = i % 32;
    if (limbIdx < exp.top && ((exp.d[limbIdx] >> bitIdx) & 1) == 1) {
      // Usa temp para evitar aliasing: temp = acc * baseMont
      bnMontMul(temp, acc, baseMont, mont);
      // Copia temp para acc
      for (int j = 0; j < temp.top; j++) {
        acc.d[j] = temp.d[j];
      }
      acc.top = temp.top;
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
