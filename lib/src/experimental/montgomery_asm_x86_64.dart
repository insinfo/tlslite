// dart format width=5000
//
// Montgomery modPow otimizado usando shellcodes C compilados para x86_64
// 
// Suporta dois modos:
// - 256-bit (4 limbs): shellcode otimizado (23KB) com sliding-window
// - Genérico (qualquer tamanho): shellcode (2KB) com exponenciação binária
//
// Os shellcodes implementam modPow completo internamente (Montgomery + exponenciação)
// Compatível com: Qualquer CPU x86_64 (Windows/Linux)

// ignore_for_file: unused_field

import 'dart:ffi' as ffi;
import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkg_ffi;

import 'rijndael_fast_asm_x86_64.dart' show ExecutableMemory;
import 'montgomery_modpow_256_bit_shellcode.dart';
import 'montgomery_modpow_generic_shellcode.dart';

// ============================================================================
// FFI Types
// ============================================================================

/// Assinatura do shellcode Montgomery modPow 256-bit (4 limbs):
/// void mont_modpow_256(uint64_t *result, const uint64_t *base, const uint64_t *exp, 
///                      const uint64_t *n, uint64_t n0, const uint64_t *rr)
typedef _MontModPow256Native = ffi.Void Function(
  ffi.Pointer<ffi.Uint64> result,
  ffi.Pointer<ffi.Uint64> base,
  ffi.Pointer<ffi.Uint64> exp,
  ffi.Pointer<ffi.Uint64> n,
  ffi.Uint64 n0,
  ffi.Pointer<ffi.Uint64> rr,
);

typedef _MontModPow256Dart = void Function(
  ffi.Pointer<ffi.Uint64> result,
  ffi.Pointer<ffi.Uint64> base,
  ffi.Pointer<ffi.Uint64> exp,
  ffi.Pointer<ffi.Uint64> n,
  int n0,
  ffi.Pointer<ffi.Uint64> rr,
);

/// Assinatura do shellcode Montgomery modPow genérico (qualquer tamanho):
/// void mont_modpow_generic(uint64_t *result, const uint64_t *base, const uint64_t *exp, 
///                          const uint64_t *n, uint64_t n0, const uint64_t *rr, uint64_t num_limbs)
typedef _MontModPowGenericNative = ffi.Void Function(
  ffi.Pointer<ffi.Uint64> result,
  ffi.Pointer<ffi.Uint64> base,
  ffi.Pointer<ffi.Uint64> exp,
  ffi.Pointer<ffi.Uint64> n,
  ffi.Uint64 n0,
  ffi.Pointer<ffi.Uint64> rr,
  ffi.Uint64 numLimbs,
);

typedef _MontModPowGenericDart = void Function(
  ffi.Pointer<ffi.Uint64> result,
  ffi.Pointer<ffi.Uint64> base,
  ffi.Pointer<ffi.Uint64> exp,
  ffi.Pointer<ffi.Uint64> n,
  int n0,
  ffi.Pointer<ffi.Uint64> rr,
  int numLimbs,
);

// ============================================================================
// Shellcode compilado de C (mont_modpow_*.c)
// ============================================================================

/// Cache dos shellcodes carregados
Uint8List? _cached256BitShellcode;
Uint8List? _cachedGenericShellcode;

/// Retorna shellcode otimizado para 256-bit (4 limbs)
Uint8List _get256BitShellcode() {
  _cached256BitShellcode ??= Uint8List.fromList(kMontgomeryModPow256BitShellcode);
  return _cached256BitShellcode!;
}

/// Retorna shellcode genérico (512/1024/2048/4096 bits)
Uint8List _getGenericShellcode() {
  _cachedGenericShellcode ??= Uint8List.fromList(kMontgomeryModPowGenericShellcode);
  return _cachedGenericShellcode!;
}

// ============================================================================
// Detecção de suporte CPU
// ============================================================================

class MontgomeryAsmSupport {
  static bool? _bmi2Supported;
  static bool? _adxSupported;
  static bool? _x64Supported;

  static bool get isBmi2Supported {
    _bmi2Supported ??= _checkCpuidBit(7, 0, 'ebx', 8);
    return _bmi2Supported!;
  }

  static bool get isAdxSupported {
    _adxSupported ??= _checkCpuidBit(7, 0, 'ebx', 19);
    return _adxSupported!;
  }

  static bool get isX64Supported {
    _x64Supported ??= Platform.isWindows || Platform.isLinux;
    return _x64Supported!;
  }

  static bool get isModernSupported => isBmi2Supported && isAdxSupported;
  static bool get isAsmSupported => isX64Supported;

  static String get backendDescription {
    if (isModernSupported) return 'Modern (BMI2/ADX)';
    if (isX64Supported) return 'Legacy NASM (MUL/ADD/ADC)';
    return 'Pure Dart (no ASM)';
  }

  static bool _checkCpuidBit(int leaf, int subleaf, String register, int bit) {
    if (!Platform.isWindows && !Platform.isLinux) return false;
    try {
      int regCode;
      switch (register) {
        case 'eax': regCode = 0xC0; break;
        case 'ebx': regCode = 0xD8; break;
        case 'ecx': regCode = 0xC8; break;
        case 'edx': regCode = 0xD0; break;
        default: return false;
      }

      final cpuidCode = Uint8List.fromList([
        0x53,
        0xB8, leaf & 0xFF, (leaf >> 8) & 0xFF, (leaf >> 16) & 0xFF, (leaf >> 24) & 0xFF,
        0xB9, subleaf & 0xFF, (subleaf >> 8) & 0xFF, (subleaf >> 16) & 0xFF, (subleaf >> 24) & 0xFF,
        0x0F, 0xA2,
        0x89, regCode,
        0xC1, 0xE8, bit & 0xFF,
        0x83, 0xE0, 0x01,
        0x5B,
        0xC3,
      ]);

      final execMem = ExecutableMemory.allocate(cpuidCode);
      try {
        final funcPtr = execMem.pointer.cast<ffi.NativeFunction<ffi.Int32 Function()>>();
        final func = funcPtr.asFunction<int Function()>();
        return func() == 1;
      } finally {
        execMem.free();
      }
    } catch (e) {
      return false;
    }
  }
}

// ============================================================================
// Montgomery Context com ASM
// ============================================================================

class MontgomeryAsmContext {
  final int numLimbs;
  final Uint64List modulus;
  final int n0;
  final Uint64List rr;

  // FFI Resources
  ExecutableMemory? _execMem;
  _MontModPow256Dart? _modpow256Asm;
  _MontModPowGenericDart? _modpowGenericAsm;

  // Buffers nativos reutilizáveis (evita malloc em cada chamada)
  ffi.Pointer<ffi.Uint64>? _bufResult;
  ffi.Pointer<ffi.Uint64>? _bufA;
  ffi.Pointer<ffi.Uint64>? _bufB;
  ffi.Pointer<ffi.Uint64>? _bufN;
  
  // Buffer extra para modPow com swap de ponteiros
  ffi.Pointer<ffi.Uint64>? _bufAcc;
  ffi.Pointer<ffi.Uint64>? _bufBase;

  // Buffers de trabalho para modPow (reutilizáveis)
  Uint64List? _workAcc;
  Uint64List? _workTemp;
  Uint64List? _workBase;
  Uint64List? _workBaseMont;
  Uint64List? _workOne;

  MontgomeryAsmContext._({
    required this.numLimbs,
    required this.modulus,
    required this.n0,
    required this.rr,
  }) {
    _initAsm();
  }

  void _initAsm() {
    // Aloca buffers de trabalho Dart (sempre úteis)
    _workAcc = Uint64List(numLimbs);
    _workTemp = Uint64List(numLimbs);
    _workBase = Uint64List(numLimbs);
    _workBaseMont = Uint64List(numLimbs);
    _workOne = Uint64List(numLimbs);

    if (!MontgomeryAsmSupport.isAsmSupported) return;

    try {
      if (numLimbs == 4) {
        // Shellcode otimizado para 256-bit com modPow integrado
        final shellcode = _get256BitShellcode();
        _execMem = ExecutableMemory.allocate(shellcode);
        final funcPtr = _execMem!.pointer.cast<ffi.NativeFunction<_MontModPow256Native>>();
        _modpow256Asm = funcPtr.asFunction<_MontModPow256Dart>();
      } else {
        // Shellcode genérico para outros tamanhos
        final shellcode = _getGenericShellcode();
        _execMem = ExecutableMemory.allocate(shellcode);
        final funcPtr = _execMem!.pointer.cast<ffi.NativeFunction<_MontModPowGenericNative>>();
        _modpowGenericAsm = funcPtr.asFunction<_MontModPowGenericDart>();
      }

      // Aloca buffers nativos persistentes
      _bufResult = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
      _bufA = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
      _bufB = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
      _bufN = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
      
      // Buffers extras para modPow (evita cópias no loop)
      _bufAcc = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
      _bufBase = pkg_ffi.calloc<ffi.Uint64>(numLimbs);

      // Copia modulus para buffer nativo (constante)
      final nList = _bufN!.asTypedList(numLimbs);
      for (int i = 0; i < numLimbs; i++) {
        nList[i] = modulus[i];
      }
    } catch (e) {
      print('Erro ao inicializar ASM: $e');
      _modpow256Asm = null;
      _modpowGenericAsm = null;
    }
  }

  factory MontgomeryAsmContext.fromModulus(Uint8List modulusBytes) {
    final numLimbs = (modulusBytes.length + 7) ~/ 8;
    final modulus = _bytesToLimbs64(modulusBytes, numLimbs);
    final n0 = _computeN0Inv64(modulus[0]);
    final rr = _computeRR64(modulus, numLimbs);

    return MontgomeryAsmContext._(
      numLimbs: numLimbs,
      modulus: modulus,
      n0: n0,
      rr: rr,
    );
  }

  /// Montgomery multiplication: result = a * b * R^-1 mod n
  void montMul(Uint64List result, Uint64List a, Uint64List b) {
    // Usa Dart puro (32-bit limbs para evitar overflow)
    // Os shellcodes disponíveis são para modPow completo, não montMul individual
    _montMulDart(result, a, b);
  }

  /// Fallback Dart puro usando limbs de 32 bits
  void _montMulDart(Uint64List result, Uint64List a, Uint64List b) {
    final n32 = numLimbs * 2;
    final a32 = Uint32List(n32);
    final b32 = Uint32List(n32);
    final mod32 = Uint32List(n32);
    final t = Uint64List(n32 * 2 + 2);

    // Expande 64->32 bits
    for (var i = 0; i < numLimbs; i++) {
      a32[i * 2] = a[i] & 0xFFFFFFFF;
      a32[i * 2 + 1] = (a[i] >> 32) & 0xFFFFFFFF;
      b32[i * 2] = b[i] & 0xFFFFFFFF;
      b32[i * 2 + 1] = (b[i] >> 32) & 0xFFFFFFFF;
      mod32[i * 2] = modulus[i] & 0xFFFFFFFF;
      mod32[i * 2 + 1] = (modulus[i] >> 32) & 0xFFFFFFFF;
    }

    // Recalcula n0 para 32 bits: -mod[0]^-1 mod 2^32
    final n0_32 = _computeN0Inv32(mod32[0]);

    // CIOS com 32-bit limbs
    for (var i = 0; i < n32; i++) {
      int carry = 0;
      final ai = a32[i];
      for (var j = 0; j < n32; j++) {
        final prod = ai * b32[j] + t[i + j] + carry;
        t[i + j] = prod & 0xFFFFFFFF;
        carry = prod >> 32;
      }
      // Propaga carry para palavras superiores
      int idx = i + n32;
      while (carry != 0 && idx < t.length) {
        final sum = t[idx] + carry;
        t[idx] = sum & 0xFFFFFFFF;
        carry = sum >> 32;
        idx++;
      }

      final m = (t[i] * n0_32) & 0xFFFFFFFF;

      carry = 0;
      for (var j = 0; j < n32; j++) {
        final prod = m * mod32[j] + t[i + j] + carry;
        t[i + j] = prod & 0xFFFFFFFF;
        carry = prod >> 32;
      }
      // Propaga carry para palavras superiores
      idx = i + n32;
      while (carry != 0 && idx < t.length) {
        final sum = t[idx] + carry;
        t[idx] = sum & 0xFFFFFFFF;
        carry = sum >> 32;
        idx++;
      }
    }

    // Copia parte alta e converte 32->64 bits
    for (var i = 0; i < numLimbs; i++) {
      final lo = t[n32 + i * 2] & 0xFFFFFFFF;
      final hi = t[n32 + i * 2 + 1] & 0xFFFFFFFF;
      result[i] = lo | (hi << 32);
    }

    // Subtração condicional
    if (_cmpUnsigned(result, modulus) >= 0) {
      _subInPlace(result, modulus);
    }
  }

  static int _cmpUnsigned(Uint64List a, Uint64List b) {
    for (var i = a.length - 1; i >= 0; i--) {
      // Comparação unsigned: trata bits negativos como valores grandes
      final ai = a[i];
      final bi = b[i];
      if (ai == bi) continue;
      // Se sinais diferentes (bit 63): negativo é maior em unsigned
      final aSign = ai < 0;
      final bSign = bi < 0;
      if (aSign != bSign) return aSign ? 1 : -1;
      return ai > bi ? 1 : -1;
    }
    return 0;
  }

  static void _subInPlace(Uint64List a, Uint64List b) {
    int borrow = 0;
    for (var i = 0; i < a.length; i++) {
      final ai = a[i];
      final bi = b[i];
      final diff = ai - bi - borrow;
      a[i] = diff;
      // Borrow detection usando Hacker's Delight
      borrow = ((~ai & bi) | ((~ai | bi) & diff)) >>> 63;
    }
  }

  /// Exponenciação modular: base^exp mod n
  Uint8List modPow(Uint8List baseBytes, Uint8List expBytes) {
    // Se temos shellcode ASM para 256-bit (4 limbs), usa versão nativa
    if (_modpow256Asm != null && numLimbs == 4) {
      return _modPowAsm256(baseBytes, expBytes);
    }
    
    // Shellcode genérico para tamanhos até 1024-bit (16 limbs)
    // MAX_LIMBS no código C é 16
    if (_modpowGenericAsm != null && numLimbs <= 16) {
      return _modPowAsmGeneric(baseBytes, expBytes);
    }
    
    // Para tamanhos maiores ou sem shellcode, usa Dart
    return _modPowDart(baseBytes, expBytes);
  }
  
  /// modPow usando shellcode otimizado para 256-bit (4 limbs)
  /// O shellcode faz modPow completo: base^exp mod n
  Uint8List _modPowAsm256(Uint8List baseBytes, Uint8List expBytes) {
    // Ponteiros para os buffers
    final pResult = _bufResult!;
    final pBase = _bufA!;
    final pExp = _bufB!;
    final pN = _bufN!;
    final pRR = _bufAcc!;  // Reutiliza buffer para RR
    
    // Typed lists
    final resultList = pResult.asTypedList(4);
    final baseList = pBase.asTypedList(4);
    final expList = pExp.asTypedList(4);
    final rrList = pRR.asTypedList(4);
    
    // Converte base para limbs e copia para buffer nativo
    final base = _bytesToLimbs64(baseBytes, 4);
    for (int i = 0; i < 4; i++) {
      baseList[i] = base[i];
    }
    
    // Converte expoente para limbs
    final exp = _bytesToLimbs64(expBytes, 4);
    for (int i = 0; i < 4; i++) {
      expList[i] = exp[i];
    }
    
    // Copia RR para buffer nativo
    for (int i = 0; i < 4; i++) {
      rrList[i] = rr[i];
    }
    
    // Chama shellcode: mont_modpow_256(result, base, exp, n, n0, rr)
    _modpow256Asm!(pResult, pBase, pExp, pN, n0, pRR);
    
    // Copia resultado para Dart e converte para bytes
    final result = Uint64List(4);
    for (int i = 0; i < 4; i++) {
      result[i] = resultList[i];
    }
    
    return _limbs64ToBytes(result, 4);
  }
  
  /// modPow usando shellcode genérico (qualquer tamanho)
  /// O shellcode faz modPow completo: base^exp mod n
  Uint8List _modPowAsmGeneric(Uint8List baseBytes, Uint8List expBytes) {
    // Ponteiros para os buffers
    final pResult = _bufResult!;
    final pBase = _bufA!;
    final pExp = _bufB!;
    final pN = _bufN!;
    final pRR = _bufAcc!;  // Reutiliza buffer para RR
    
    // Typed lists
    final resultList = pResult.asTypedList(numLimbs);
    final baseList = pBase.asTypedList(numLimbs);
    final expList = pExp.asTypedList(numLimbs);
    final rrList = pRR.asTypedList(numLimbs);
    
    // Converte base para limbs e copia para buffer nativo
    final base = _bytesToLimbs64(baseBytes, numLimbs);
    for (int i = 0; i < numLimbs; i++) {
      baseList[i] = base[i];
    }
    
    // Converte expoente para limbs
    final exp = _bytesToLimbs64(expBytes, numLimbs);
    for (int i = 0; i < numLimbs; i++) {
      expList[i] = exp[i];
    }
    
    // Copia RR para buffer nativo
    for (int i = 0; i < numLimbs; i++) {
      rrList[i] = rr[i];
    }
    
    // Chama shellcode: mont_modpow_generic(result, base, exp, n, n0, rr, num_limbs)
    _modpowGenericAsm!(pResult, pBase, pExp, pN, n0, pRR, numLimbs);
    
    // Copia resultado para Dart e converte para bytes
    final result = Uint64List(numLimbs);
    for (int i = 0; i < numLimbs; i++) {
      result[i] = resultList[i];
    }
    
    return _limbs64ToBytes(result, numLimbs);
  }
  
  /// modPow fallback usando BigInt (para tamanhos > 1024-bit ou sem shellcode)
  Uint8List _modPowDart(Uint8List baseBytes, Uint8List expBytes) {
    // Converte para BigInt
    BigInt baseBig = BigInt.zero;
    for (int i = 0; i < baseBytes.length; i++) {
      baseBig = (baseBig << 8) | BigInt.from(baseBytes[i]);
    }
    
    BigInt expBig = BigInt.zero;
    for (int i = 0; i < expBytes.length; i++) {
      expBig = (expBig << 8) | BigInt.from(expBytes[i]);
    }
    
    BigInt modBig = BigInt.zero;
    for (int i = numLimbs - 1; i >= 0; i--) {
      modBig = (modBig << 64) | BigInt.from(modulus[i]).toUnsigned(64);
    }
    
    // Usa BigInt.modPow nativo do Dart
    final result = baseBig.modPow(expBig, modBig);
    
    // Converte de volta para bytes
    final resultBytes = <int>[];
    var temp = result;
    while (temp > BigInt.zero) {
      resultBytes.insert(0, (temp & BigInt.from(0xFF)).toInt());
      temp >>= 8;
    }
    if (resultBytes.isEmpty) resultBytes.add(0);
    
    return Uint8List.fromList(resultBytes);
  }

  /// Limpa um array de limbs
  @pragma('vm:prefer-inline')
  static void clearLimbs(Uint64List limbs) {
    for (int i = 0; i < limbs.length; i++) {
      limbs[i] = 0;
    }
  }

  /// Copia limbs de src para dst
  @pragma('vm:prefer-inline')
  static void copyLimbs(Uint64List src, Uint64List dst) {
    for (int i = 0; i < src.length; i++) {
      dst[i] = src[i];
    }
  }

  /// Converte bytes para limbs diretamente em um buffer existente
  void bytesToLimbs64Into(Uint8List bytes, Uint64List limbs) {
    // Limpa primeiro
    for (int i = 0; i < limbs.length; i++) {
      limbs[i] = 0;
    }

    int limbIdx = 0;
    int shift = 0;
    BigInt limb = BigInt.zero;
    final mask64 = BigInt.parse('FFFFFFFFFFFFFFFF', radix: 16);

    for (int i = bytes.length - 1; i >= 0; i--) {
      limb |= BigInt.from(bytes[i]) << shift;
      shift += 8;
      if (shift >= 64) {
        limbs[limbIdx++] = (limb & mask64).toSigned(64).toInt();
        limb = BigInt.zero;
        shift = 0;
      }
    }
    if (shift > 0 && limbIdx < numLimbs) {
      limbs[limbIdx] = (limb & mask64).toSigned(64).toInt();
    }
  }

  void dispose() {
    if (_bufResult != null) pkg_ffi.calloc.free(_bufResult!);
    if (_bufA != null) pkg_ffi.calloc.free(_bufA!);
    if (_bufB != null) pkg_ffi.calloc.free(_bufB!);
    if (_bufN != null) pkg_ffi.calloc.free(_bufN!);
    if (_bufAcc != null) pkg_ffi.calloc.free(_bufAcc!);
    if (_bufBase != null) pkg_ffi.calloc.free(_bufBase!);
    _execMem?.free();
  }

  // ===========================================================================
  // Helper functions
  // ===========================================================================

  static Uint64List _bytesToLimbs64(Uint8List bytes, int numLimbs) {
    final limbs = Uint64List(numLimbs);
    int limbIdx = 0;
    int shift = 0;
    BigInt limb = BigInt.zero;
    final mask64 = BigInt.parse('FFFFFFFFFFFFFFFF', radix: 16);

    // Processa bytes de trás para frente (little-endian limbs)
    for (int i = bytes.length - 1; i >= 0; i--) {
      limb |= BigInt.from(bytes[i]) << shift;
      shift += 8;
      if (shift >= 64) {
        // toSigned(64) preserva todos os 64 bits como unsigned
        limbs[limbIdx++] = (limb & mask64).toSigned(64).toInt();
        limb = BigInt.zero;
        shift = 0;
      }
    }
    if (shift > 0 && limbIdx < numLimbs) {
      limbs[limbIdx] = (limb & mask64).toSigned(64).toInt();
    }
    return limbs;
  }

  static int _computeN0Inv64(int n0word) {
    // Newton-Raphson para calcular -n^-1 mod 2^64
    int x = n0word;
    for (int i = 0; i < 6; i++) {
      x = x * (2 - n0word * x);
    }
    return -x; // Dart wraps automaticamente em 64 bits
  }

  /// Calcula -n^-1 mod 2^32 (para uso com limbs de 32 bits)
  static int _computeN0Inv32(int n0word) {
    // Newton-Raphson para calcular -n^-1 mod 2^32
    int x = n0word;
    for (int i = 0; i < 5; i++) {
      x = (x * (2 - n0word * x)) & 0xFFFFFFFF;
    }
    return (-x) & 0xFFFFFFFF;
  }

  static Uint64List _computeRR64(Uint64List mod, int numLimbs) {
    // Calcula R^2 mod n onde R = 2^(numLimbs*64)
    // Usa BigInt apenas no setup (roda uma vez)
    BigInt mVal = BigInt.zero;
    for (int i = numLimbs - 1; i >= 0; i--) {
      mVal = (mVal << 64) | BigInt.from(mod[i]).toUnsigned(64);
    }

    BigInt r = BigInt.one << (numLimbs * 64);
    BigInt rrVal = (r * r) % mVal;

    final rr = Uint64List(numLimbs);
    final mask64 = BigInt.parse('FFFFFFFFFFFFFFFF', radix: 16);
    for (int i = 0; i < numLimbs; i++) {
      rr[i] = (rrVal & mask64).toSigned(64).toInt();
      rrVal >>= 64;
    }
    return rr;
  }

  static int countBits64(Uint64List limbs) {
    for (int i = limbs.length - 1; i >= 0; i--) {
      if (limbs[i] != 0) {
        return i * 64 + BigInt.from(limbs[i]).toUnsigned(64).bitLength;
      }
    }
    return 0;
  }

  static Uint8List _limbs64ToBytes(Uint64List limbs, int numLimbs) {
    final bytes = Uint8List(numLimbs * 8);
    for (int i = 0; i < numLimbs; i++) {
      var limb = limbs[i];
      for (int j = 0; j < 8; j++) {
        bytes[bytes.length - 1 - (i * 8 + j)] = limb & 0xFF;
        limb >>= 8;
      }
    }
    int start = 0;
    while (start < bytes.length - 1 && bytes[start] == 0) start++;
    return bytes.sublist(start);
  }
}

/// Função conveniente para modPow usando ASM
Uint8List modPowAsm(Uint8List base, Uint8List exp, Uint8List mod) {
  final ctx = MontgomeryAsmContext.fromModulus(mod);
  try {
    return ctx.modPow(base, exp);
  } finally {
    ctx.dispose();
  }
}
