// dart format width=5000
//
// Montgomery Multiplication otimizado usando shell code x86_64
// Compilado com NASM para Ivy Bridge (sem BMI2/ADX)
//
// O shellcode suporta QUALQUER tamanho de chave (256, 512, 1024, 2048, 4096 bits)
// através de parâmetro numLimbs passado na stack.
//
// Algoritmo: CIOS (Coarsely Integrated Operand Scanning)
// Compatível com: Qualquer CPU x86_64 (Ivy Bridge, Haswell, etc.)

import 'dart:ffi' as ffi;
import 'dart:io' show File, Platform;
import 'dart:typed_data';

import 'package:ffi/ffi.dart' as pkg_ffi;

import 'rijndael_fast_asm_x86_64.dart' show ExecutableMemory;

// ============================================================================
// FFI Types
// ============================================================================

/// Assinatura do shellcode Montgomery multiply:
/// Windows x64: RCX=res, RDX=a, R8=b, R9=n, [RSP+40]=n0, [RSP+48]=numLimbs
typedef _MontMulNative = ffi.Void Function(
  ffi.Pointer<ffi.Uint64> res,
  ffi.Pointer<ffi.Uint64> a,
  ffi.Pointer<ffi.Uint64> b,
  ffi.Pointer<ffi.Uint64> n,
  ffi.Uint64 n0,
  ffi.Uint64 numLimbs,
);

typedef _MontMulDart = void Function(
  ffi.Pointer<ffi.Uint64> res,
  ffi.Pointer<ffi.Uint64> a,
  ffi.Pointer<ffi.Uint64> b,
  ffi.Pointer<ffi.Uint64> n,
  int n0,
  int numLimbs,
);

/// Assinatura do shellcode Montgomery squaring (4 limbs):
/// Windows x64: RCX=res, RDX=a, R8=n, R9=n0
typedef _MontSqrNative = ffi.Void Function(
  ffi.Pointer<ffi.Uint64> res,
  ffi.Pointer<ffi.Uint64> a,
  ffi.Pointer<ffi.Uint64> n,
  ffi.Int64 n0,
);

typedef _MontSqrDart = void Function(
  ffi.Pointer<ffi.Uint64> res,
  ffi.Pointer<ffi.Uint64> a,
  ffi.Pointer<ffi.Uint64> n,
  int n0,
);

// ============================================================================
// Shellcode compilado com NASM (Ivy Bridge compatible)
// ============================================================================

/// Shellcode Montgomery CIOS compilado com NASM v3
/// Comando: nasm -f bin mont_mul_v3.asm -o mont_mul_v3.bin
/// 
/// Suporta qualquer tamanho de chave via parâmetro numLimbs
/// Usa rep stosq para inicialização mais eficiente
Uint8List? _cachedShellCode;
Uint8List? _cachedShellCode4Limbs;

/// Carrega o shellcode do arquivo .bin ou retorna embedded se não encontrar
Uint8List _getShellCode() {
  if (_cachedShellCode != null) return _cachedShellCode!;
  
  // Tenta carregar do arquivo (útil para desenvolvimento/teste)
  try {
    final binFile = File('asm/mont_mul_v3.bin');
    if (binFile.existsSync()) {
      _cachedShellCode = binFile.readAsBytesSync();
      return _cachedShellCode!;
    }
  } catch (_) {}
  
  // Fallback: shellcode embedded
  _cachedShellCode = _embeddedShellCode;
  return _cachedShellCode!;
}

/// Carrega o shellcode otimizado para 4 limbs (256-bit)
Uint8List _getShellCode4Limbs() {
  if (_cachedShellCode4Limbs != null) return _cachedShellCode4Limbs!;
  
  try {
    final binFile = File('asm/mont_mul_4limbs.bin');
    if (binFile.existsSync()) {
      _cachedShellCode4Limbs = binFile.readAsBytesSync();
      return _cachedShellCode4Limbs!;
    }
  } catch (_) {}
  
  // Fallback para shellcode genérico se não encontrar
  return _getShellCode();
}

/// Shellcode de squaring otimizado para 4 limbs
Uint8List? _cachedShellCodeSqr4Limbs;

Uint8List? _getShellCodeSqr4Limbs() {
  if (_cachedShellCodeSqr4Limbs != null) return _cachedShellCodeSqr4Limbs;
  
  try {
    final binFile = File('asm/mont_sqr_4limbs.bin');
    if (binFile.existsSync()) {
      _cachedShellCodeSqr4Limbs = binFile.readAsBytesSync();
      return _cachedShellCodeSqr4Limbs;
    }
  } catch (_) {}
  
  return null; // Não tem fallback, usa multiply normal
}

/// Shellcode embedded como fallback
final Uint8List _embeddedShellCode = Uint8List.fromList([
  0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,
  0x49, 0x89, 0xCC, 0x49, 0x89, 0xD5, 0x4D, 0x89, 0xC6, 0x4D, 0x89, 0xCF,
  0x48, 0x8B, 0x74, 0x24, 0x68, 0x48, 0x8B, 0x7C, 0x24, 0x70, 0x48, 0x8D,
  0x44, 0x3F, 0x01, 0x48, 0xC1, 0xE0, 0x03, 0x48, 0x83, 0xC0, 0x0F, 0x48,
  0x83, 0xE0, 0xF0, 0x48, 0x29, 0xC4, 0x48, 0x89, 0xE3, 0x50, 0x48, 0x89,
  0xF9, 0x48, 0xD1, 0xE1, 0x48, 0xFF, 0xC1, 0x57, 0x48, 0x89, 0xDF, 0x31,
  0xC0, 0xF3, 0x48, 0xAB, 0x5F, 0x31, 0xED, 0x48, 0x39, 0xFD, 0x0F, 0x8D,
  0x9A, 0x00, 0x00, 0x00, 0x4D, 0x8B, 0x44, 0xED, 0x00, 0x45, 0x31, 0xC9,
  0x45, 0x31, 0xD2, 0x49, 0x39, 0xF9, 0x7D, 0x27, 0x4C, 0x89, 0xC0, 0x4B,
  0xF7, 0x24, 0xCE, 0x4A, 0x8D, 0x4C, 0x0D, 0x00, 0x48, 0x03, 0x04, 0xCB,
  0x48, 0x83, 0xD2, 0x00, 0x4C, 0x01, 0xD0, 0x48, 0x83, 0xD2, 0x00, 0x48,
  0x89, 0x04, 0xCB, 0x49, 0x89, 0xD2, 0x49, 0xFF, 0xC1, 0xEB, 0xD4, 0x48,
  0x8D, 0x4C, 0x3D, 0x00, 0x4C, 0x01, 0x14, 0xCB, 0x48, 0x83, 0x54, 0xCB,
  0x08, 0x00, 0x48, 0x8B, 0x04, 0xEB, 0x48, 0x0F, 0xAF, 0xC6, 0x49, 0x89,
  0xC0, 0x45, 0x31, 0xC9, 0x45, 0x31, 0xD2, 0x49, 0x39, 0xF9, 0x7D, 0x27,
  0x4C, 0x89, 0xC0, 0x4B, 0xF7, 0x24, 0xCF, 0x4A, 0x8D, 0x4C, 0x0D, 0x00,
  0x48, 0x03, 0x04, 0xCB, 0x48, 0x83, 0xD2, 0x00, 0x4C, 0x01, 0xD0, 0x48,
  0x83, 0xD2, 0x00, 0x48, 0x89, 0x04, 0xCB, 0x49, 0x89, 0xD2, 0x49, 0xFF,
  0xC1, 0xEB, 0xD4, 0x48, 0x8D, 0x4C, 0x3D, 0x00, 0x4C, 0x01, 0x14, 0xCB,
  0x48, 0x83, 0x54, 0xCB, 0x08, 0x00, 0x48, 0xFF, 0xC5, 0xE9, 0x5D, 0xFF,
  0xFF, 0xFF, 0x45, 0x31, 0xC9, 0x49, 0x39, 0xF9, 0x7D, 0x11, 0x4A, 0x8D,
  0x0C, 0x0F, 0x48, 0x8B, 0x04, 0xCB, 0x4B, 0x89, 0x04, 0xCC, 0x49, 0xFF,
  0xC1, 0xEB, 0xEA, 0x48, 0x8D, 0x0C, 0x3F, 0x48, 0x8B, 0x04, 0xCB, 0x48,
  0x85, 0xC0, 0x75, 0x1F, 0x49, 0x89, 0xF9, 0x49, 0xFF, 0xC9, 0x4D, 0x85,
  0xC9, 0x78, 0x40, 0x4B, 0x8B, 0x04, 0xCC, 0x4B, 0x8B, 0x0C, 0xCF, 0x48,
  0x39, 0xC8, 0x77, 0x07, 0x72, 0x31, 0x49, 0xFF, 0xC9, 0xEB, 0xE7, 0x45,
  0x31, 0xD2, 0x45, 0x31, 0xC9, 0x49, 0x39, 0xF9, 0x7D, 0x21, 0x4B, 0x8B,
  0x04, 0xCC, 0x4B, 0x8B, 0x0C, 0xCF, 0x48, 0x29, 0xC8, 0x4C, 0x19, 0xD0,
  0x41, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x41, 0x0F, 0x92, 0xC2, 0x4B, 0x89,
  0x04, 0xCC, 0x49, 0xFF, 0xC1, 0xEB, 0xDA, 0x58, 0x48, 0x01, 0xC4, 0x41,
  0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5F, 0x5E, 0x5D, 0x5B, 0xC3
]);

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
  ExecutableMemory? _execMemSqr;
  _MontMulDart? _nativeFunc;
  _MontSqrDart? _nativeFuncSqr;

  // Buffers nativos reutilizáveis (evita malloc em cada chamada)
  ffi.Pointer<ffi.Uint64>? _bufResult;
  ffi.Pointer<ffi.Uint64>? _bufA;
  ffi.Pointer<ffi.Uint64>? _bufB;
  ffi.Pointer<ffi.Uint64>? _bufN;
  
  // Buffer extra para modPow com swap de ponteiros
  ffi.Pointer<ffi.Uint64>? _bufAcc;
  ffi.Pointer<ffi.Uint64>? _bufBase;

  // Typed lists para acesso direto (evita asTypedList repetido)
  Uint64List? _aList;
  Uint64List? _bList;
  Uint64List? _resList;

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
      // Usa shellcode otimizado para 4 limbs (256-bit), senão genérico
      final shellCode = numLimbs == 4 ? _getShellCode4Limbs() : _getShellCode();
      _execMem = ExecutableMemory.allocate(shellCode);
      final funcPtr = _execMem!.pointer.cast<ffi.NativeFunction<_MontMulNative>>();
      _nativeFunc = funcPtr.asFunction<_MontMulDart>();

      // Carrega squaring otimizado para 4 limbs se disponível
      if (numLimbs == 4) {
        final sqrCode = _getShellCodeSqr4Limbs();
        if (sqrCode != null) {
          _execMemSqr = ExecutableMemory.allocate(sqrCode);
          final sqrFuncPtr = _execMemSqr!.pointer.cast<ffi.NativeFunction<_MontSqrNative>>();
          _nativeFuncSqr = sqrFuncPtr.asFunction<_MontSqrDart>();
        }
      }

      // Aloca buffers nativos persistentes
      _bufResult = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
      _bufA = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
      _bufB = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
      _bufN = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
      
      // Buffers extras para modPow (evita cópias no loop)
      _bufAcc = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
      _bufBase = pkg_ffi.calloc<ffi.Uint64>(numLimbs);

      // Cria typed lists para acesso direto (evita asTypedList repetido)
      _aList = _bufA!.asTypedList(numLimbs);
      _bList = _bufB!.asTypedList(numLimbs);
      _resList = _bufResult!.asTypedList(numLimbs);

      // Copia modulus para buffer nativo (constante)
      final nList = _bufN!.asTypedList(numLimbs);
      for (int i = 0; i < numLimbs; i++) {
        nList[i] = modulus[i];
      }
    } catch (e) {
      print('Erro ao inicializar ASM: $e');
      _nativeFunc = null;
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
    if (_nativeFunc != null) {
      // Usa typed lists pré-criados (evita asTypedList)
      final aList = _aList!;
      final bList = _bList!;
      final resList = _resList!;

      // Copia dados para buffers nativos
      for (int i = 0; i < numLimbs; i++) {
        aList[i] = a[i];
        bList[i] = b[i];
      }

      // Executa shellcode ASM!
      _nativeFunc!(_bufResult!, _bufA!, _bufB!, _bufN!, n0, numLimbs);

      // Copia resultado de volta
      for (int i = 0; i < numLimbs; i++) {
        result[i] = resList[i];
      }
    } else {
      // Fallback para Dart puro (32-bit limbs para evitar overflow)
      _montMulDart(result, a, b);
    }
  }

  /// Montgomery multiplication direto nos buffers nativos (evita cópias)
  /// a e b já devem estar nos buffers _aList e _bList
  void _montMulNative() {
    _nativeFunc!(_bufResult!, _bufA!, _bufB!, _bufN!, n0, numLimbs);
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

    final n0_32 = n0 & 0xFFFFFFFF;

    // CIOS com 32-bit limbs
    for (var i = 0; i < n32; i++) {
      int carry = 0;
      final ai = a32[i];
      for (var j = 0; j < n32; j++) {
        final prod = ai * b32[j] + t[i + j] + carry;
        t[i + j] = prod & 0xFFFFFFFF;
        carry = prod >> 32;
      }
      t[i + n32] += carry;

      final m = (t[i] * n0_32) & 0xFFFFFFFF;

      carry = 0;
      for (var j = 0; j < n32; j++) {
        final prod = m * mod32[j] + t[i + j] + carry;
        t[i + j] = prod & 0xFFFFFFFF;
        carry = prod >> 32;
      }
      t[i + n32] += carry;
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
    // Se temos ASM para 4 limbs, usa versão totalmente nativa
    if (_nativeFunc != null && numLimbs == 4) {
      return _modPowNative(baseBytes, expBytes);
    }
    
    // Fallback para versão híbrida
    return _modPowDart(baseBytes, expBytes);
  }
  
  /// modPow totalmente nativo para 4 limbs (minimiza cópias FFI)
  Uint8List _modPowNative(Uint8List baseBytes, Uint8List expBytes) {
    // Ponteiros para os buffers
    final pAcc = _bufAcc!;
    final pBase = _bufBase!;
    final pResult = _bufResult!;
    final pA = _bufA!;
    final pB = _bufB!;
    final pN = _bufN!;
    
    // Typed lists
    final accList = pAcc.asTypedList(4);
    final baseList = pBase.asTypedList(4);
    final resultList = pResult.asTypedList(4);
    final aList = pA.asTypedList(4);
    final bList = pB.asTypedList(4);
    
    // Converte base para limbs e copia para buffer nativo
    final base = _bytesToLimbs64(baseBytes, 4);
    for (int i = 0; i < 4; i++) {
      aList[i] = base[i];
      bList[i] = rr[i];
    }
    
    // baseMont = base * R mod n (via montMul)
    _nativeFunc!(pBase, pA, pB, pN, n0, 4);
    
    // Inicializa acc = 1 * R mod n (one_mont)
    aList[0] = 1;
    aList[1] = 0;
    aList[2] = 0;
    aList[3] = 0;
    // bList já tem rr
    for (int i = 0; i < 4; i++) {
      bList[i] = rr[i];
    }
    _nativeFunc!(pAcc, pA, pB, pN, n0, 4);
    
    // Converte expoente para limbs
    final exp = _bytesToLimbs64(expBytes, 4);
    final expBits = _countBits64(exp);
    
    // Verifica se temos squaring otimizado
    final hasOptimizedSqr = _nativeFuncSqr != null;
    
    // Loop de exponenciação binária
    for (int i = expBits - 1; i >= 0; i--) {
      // Square: acc = acc^2
      if (hasOptimizedSqr) {
        // Copia acc para pA, calcula sqr(acc) -> pResult
        for (int j = 0; j < 4; j++) {
          aList[j] = accList[j];
        }
        _nativeFuncSqr!(pResult, pA, pN, n0);
      } else {
        // Usa multiplicação: acc * acc
        for (int j = 0; j < 4; j++) {
          aList[j] = accList[j];
          bList[j] = accList[j];
        }
        _nativeFunc!(pResult, pA, pB, pN, n0, 4);
      }
      
      // Copia resultado de volta para acc
      for (int j = 0; j < 4; j++) {
        accList[j] = resultList[j];
      }
      
      // Multiply if bit is set
      final limbIdx = i ~/ 64;
      final bitIdx = i % 64;
      if (limbIdx < 4 && ((exp[limbIdx] >> bitIdx) & 1) == 1) {
        // acc = acc * baseMont
        for (int j = 0; j < 4; j++) {
          aList[j] = accList[j];
          bList[j] = baseList[j];
        }
        _nativeFunc!(pResult, pA, pB, pN, n0, 4);
        
        for (int j = 0; j < 4; j++) {
          accList[j] = resultList[j];
        }
      }
    }
    
    // Converte de volta do domínio Montgomery: result = acc * 1
    aList[0] = accList[0];
    aList[1] = accList[1];
    aList[2] = accList[2];
    aList[3] = accList[3];
    bList[0] = 1;
    bList[1] = 0;
    bList[2] = 0;
    bList[3] = 0;
    _nativeFunc!(pResult, pA, pB, pN, n0, 4);
    
    // Copia resultado para Dart e converte para bytes
    final result = Uint64List(4);
    for (int i = 0; i < 4; i++) {
      result[i] = resultList[i];
    }
    
    return _limbs64ToBytes(result, 4);
  }
  
  /// modPow versão Dart/híbrida
  Uint8List _modPowDart(Uint8List baseBytes, Uint8List expBytes) {
    // Usa buffers de trabalho persistentes
    final base = _workBase!;
    final baseMont = _workBaseMont!;
    final acc = _workAcc!;
    final temp = _workTemp!;
    final one = _workOne!;

    // Converte bytes para limbs diretamente nos buffers
    _bytesToLimbs64Into(baseBytes, base);
    final exp = _bytesToLimbs64(expBytes, numLimbs);

    // Converte base para domínio Montgomery: baseMont = base * R mod n
    montMul(baseMont, base, rr);

    // Inicializa acumulador como 1 em Montgomery: 1_Mont = 1 * R mod n
    _clearLimbs(one);
    one[0] = 1;
    montMul(acc, one, rr);

    // Exponenciação binária (left-to-right)
    final expBits = _countBits64(exp);

    if (_nativeFunc != null) {
      // Versão otimizada usando buffers nativos diretamente
      _modPowLoopAsm(acc, baseMont, exp, expBits, temp);
    } else {
      // Versão Dart
      for (int i = expBits - 1; i >= 0; i--) {
        // Square
        montMul(temp, acc, acc);
        _copyLimbs(temp, acc);

        // Multiply if bit is set
        final limbIdx = i ~/ 64;
        final bitIdx = i % 64;
        if (limbIdx < exp.length && ((exp[limbIdx] >> bitIdx) & 1) == 1) {
          montMul(temp, acc, baseMont);
          _copyLimbs(temp, acc);
        }
      }
    }

    // Converte de volta do domínio Montgomery: result = acc * 1 * R^-1 mod n
    _clearLimbs(one);
    one[0] = 1;
    montMul(temp, acc, one);

    return _limbs64ToBytes(temp, numLimbs);
  }

  /// Loop de exponenciação otimizado para ASM
  void _modPowLoopAsm(Uint64List acc, Uint64List baseMont, Uint64List exp, int expBits, Uint64List temp) {
    final aList = _aList!;
    final bList = _bList!;
    final resList = _resList!;

    // Verifica se temos squaring otimizado disponível
    final hasOptimizedSqr = _nativeFuncSqr != null;

    for (int i = expBits - 1; i >= 0; i--) {
      // Square: acc = acc^2
      for (int j = 0; j < numLimbs; j++) {
        aList[j] = acc[j];
      }

      if (hasOptimizedSqr) {
        // Usa squaring otimizado (menos multiplicações)
        _nativeFuncSqr!(_bufResult!, _bufA!, _bufN!, n0);
      } else {
        // Usa multiplicação genérica para squaring
        for (int j = 0; j < numLimbs; j++) {
          bList[j] = acc[j];
        }
        _montMulNative();
      }

      for (int j = 0; j < numLimbs; j++) {
        acc[j] = resList[j];
      }

      // Multiply if bit is set
      final limbIdx = i ~/ 64;
      final bitIdx = i % 64;
      if (limbIdx < exp.length && ((exp[limbIdx] >> bitIdx) & 1) == 1) {
        for (int j = 0; j < numLimbs; j++) {
          aList[j] = acc[j];
          bList[j] = baseMont[j];
        }
        _montMulNative();
        for (int j = 0; j < numLimbs; j++) {
          acc[j] = resList[j];
        }
      }
    }
  }

  /// Limpa um array de limbs
  @pragma('vm:prefer-inline')
  static void _clearLimbs(Uint64List limbs) {
    for (int i = 0; i < limbs.length; i++) {
      limbs[i] = 0;
    }
  }

  /// Copia limbs de src para dst
  @pragma('vm:prefer-inline')
  static void _copyLimbs(Uint64List src, Uint64List dst) {
    for (int i = 0; i < src.length; i++) {
      dst[i] = src[i];
    }
  }

  /// Converte bytes para limbs diretamente em um buffer existente
  void _bytesToLimbs64Into(Uint8List bytes, Uint64List limbs) {
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
    _execMemSqr?.free();
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

  static int _countBits64(Uint64List limbs) {
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