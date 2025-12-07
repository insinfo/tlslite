/// Teste simplificado do Montgomery ASM para debug
/// 
/// Testa com valores pequenos conhecidos para verificar o shellcode

import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:typed_data';
import 'package:ffi/ffi.dart' as pkg_ffi;
import 'package:tlslite/src/utils/rijndael_fast_asm_x86_64.dart' show ExecutableMemory;

// FFI Types - igual ao montgomery_asm_x86_64.dart
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

/// Shellcode v3 de mont_mul_v3.bin (carrega do arquivo ou usa embedded)
Uint8List? _cachedShellCode;

Uint8List _getShellCode() {
  if (_cachedShellCode != null) return _cachedShellCode!;
  
  // Tenta carregar do arquivo
  final binFile = File('native_tools/mont_mul_v3.bin');
  if (binFile.existsSync()) {
    print('  [Carregando shellcode de: ${binFile.absolute.path}]');
    _cachedShellCode = binFile.readAsBytesSync();
    return _cachedShellCode!;
  }
  
  print('  [Usando shellcode embedded]');
  _cachedShellCode = _embeddedShellCode;
  return _cachedShellCode!;
}

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

void main() {
  print('Teste Montgomery ASM Simplificado');
  print('=' * 50);
  
  // Testa com numLimbs = 1 (64 bits)
  // N = 17 (primo pequeno)
  // a = 3, b = 5
  // a*b = 15 mod 17 = 15
  // Mas em Montgomery: resultado = a*b*R^-1 mod N
  
  // Para numLimbs=1, R = 2^64
  // n0 = -N^-1 mod 2^64
  
  print('\n--- Teste com 1 limb (64 bits) ---');
  _testMontMul(
    numLimbs: 1,
    a: [3],
    b: [5],
    n: [17],
    description: '3 * 5 mod 17',
  );
  
  print('\n--- Teste com 2 limbs (128 bits) ---');
  // N = primo de 128 bits (simplificado)
  // Usar valores pequenos que cabem em 64 bits para verificar
  _testMontMul(
    numLimbs: 2,
    a: [7, 0],
    b: [11, 0],
    n: [0xFFFFFFFFFFFFFFC5, 0xFFFFFFFFFFFFFFFF], // 2^128 - 59 (primo)
    description: '7 * 11 mod (2^128-59)',
  );
  
  print('\n--- Teste com 4 limbs (256 bits) ---');
  // Teste com valores menores de 256 bits para evitar overflow
  final n256 = _secp256k1_p(); // Primo secp256k1
  _testMontMul(
    numLimbs: 4,
    a: [0x0000000000001234, 0, 0, 0],  // valor bem pequeno
    b: [0x0000000000005678, 0, 0, 0],  // valor bem pequeno  
    n: n256,
    description: 'valores pequenos mod secp256k1_p',
  );
  
  print('\n--- Teste 2 limbs com valores pequenos ---');
  _testMontMul(
    numLimbs: 2,
    a: [0x12345, 0],
    b: [0x67890, 0],
    n: [0xFFFFFFFFFFFFFFC5, 0xFFFFFFFFFFFFFFFF], // 2^128 - 59 (primo)
    description: 'pequenos mod (2^128-59)',
  );
}

List<int> _secp256k1_p() {
  // p = 2^256 - 2^32 - 977
  // Em little-endian limbs:
  return [
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
  ];
}

void _testMontMul({
  required int numLimbs,
  required List<int> a,
  required List<int> b,
  required List<int> n,
  required String description,
}) {
  print('Teste: $description');
  print('  numLimbs = $numLimbs');
  
  // Converte para BigInt para verificação
  BigInt aBig = BigInt.zero;
  BigInt bBig = BigInt.zero;
  BigInt nBig = BigInt.zero;
  for (int i = numLimbs - 1; i >= 0; i--) {
    aBig = (aBig << 64) | BigInt.from(a[i]).toUnsigned(64);
    bBig = (bBig << 64) | BigInt.from(b[i]).toUnsigned(64);
    nBig = (nBig << 64) | BigInt.from(n[i]).toUnsigned(64);
  }
  
  print('  a = 0x${aBig.toRadixString(16)}');
  print('  b = 0x${bBig.toRadixString(16)}');
  print('  n = 0x${nBig.toRadixString(16)}');
  
  // Calcula n0 = -n^-1 mod 2^64
  final n0 = _computeN0Inv64(n[0]);
  print('  n0 = 0x${n0.toUnsigned(64).toRadixString(16).toUpperCase()}');
  
  // R = 2^(numLimbs * 64)
  final R = BigInt.one << (numLimbs * 64);
  
  // Resultado esperado: a * b * R^-1 mod n
  // Montgomery multiplication retorna: (a * b) / R mod n
  // onde / é divisão modular (multiplicação pelo inverso)
  final Rinv = R.modInverse(nBig);
  final expectedBig = (aBig * bBig * Rinv) % nBig;
  print('  Esperado (BigInt): 0x${expectedBig.toRadixString(16)}');
  
  // Converte expectedBig para limbs (tratando corretamente 64-bit unsigned)
  final expected = List<int>.filled(numLimbs, 0);
  final mask64 = BigInt.parse('FFFFFFFFFFFFFFFF', radix: 16);
  var temp = expectedBig;
  for (int i = 0; i < numLimbs; i++) {
    final limb64 = temp & mask64;
    // Se o limb é maior que 2^63-1, converte para signed representação
    if (limb64 >= BigInt.one << 63) {
      // Trata como signed: valor - 2^64
      expected[i] = (limb64 - (BigInt.one << 64)).toInt();
    } else {
      expected[i] = limb64.toInt();
    }
    temp >>= 64;
  }
  // Mostra os limbs como unsigned
  print('  Esperado (limbs): [${expected.map((x) => '0x${BigInt.from(x).toUnsigned(64).toRadixString(16).toUpperCase()}').join(', ')}]');
  
  // Resultado via Dart CIOS
  final expectedDart = _montMulDart(a, b, n, n0, numLimbs);
  print('  Dart CIOS: [${expectedDart.map((x) => '0x${x.toUnsigned(64).toRadixString(16).toUpperCase()}').join(', ')}]');
  
  // Resultado via ASM
  final resultAsm = _callAsmMontMul(a, b, n, n0, numLimbs);
  print('  Resultado (ASM): [${resultAsm.map((x) => '0x${x.toUnsigned(64).toRadixString(16).toUpperCase()}').join(', ')}]');
  
  // Verifica se Dart CIOS está correto
  bool dartCorrect = true;
  for (int i = 0; i < numLimbs; i++) {
    if (expectedDart[i] != expected[i]) {
      dartCorrect = false;
      break;
    }
  }
  print('  Dart CIOS: ${dartCorrect ? "✓ OK" : "✗ ERRO"}');
  
  // Verifica se ASM está correto
  bool asmCorrect = true;
  for (int i = 0; i < numLimbs; i++) {
    // Compara como unsigned (usando BigInt para evitar problemas de signed int)
    final asmVal = BigInt.from(resultAsm[i]).toUnsigned(64);
    final expVal = BigInt.from(expected[i]).toUnsigned(64);
    if (asmVal != expVal) {
      asmCorrect = false;
      print('  DIFF limb[$i]: ASM=0x${asmVal.toRadixString(16)} vs EXP=0x${expVal.toRadixString(16)}');
      break;
    }
  }
  print('  ASM: ${asmCorrect ? "✓ OK" : "✗ ERRO"}');
}

int _computeN0Inv64(int n0word) {
  // Newton-Raphson para calcular -n^-1 mod 2^64
  int x = n0word;
  for (int i = 0; i < 6; i++) {
    x = x * (2 - n0word * x);
  }
  return -x;
}

/// Montgomery multiplication em Dart puro para comparação
List<int> _montMulDart(List<int> a, List<int> b, List<int> n, int n0, int numLimbs) {
  // Implementação CIOS com BigInt para evitar overflow
  final t = List<BigInt>.filled(2 * numLimbs + 1, BigInt.zero);
  final mask64 = BigInt.from(0xFFFFFFFFFFFFFFFF);
  final n0Big = BigInt.from(n0).toUnsigned(64);
  
  for (int i = 0; i < numLimbs; i++) {
    // Fase 1: t += a[i] * b
    BigInt carry = BigInt.zero;
    final aiBig = BigInt.from(a[i]).toUnsigned(64);
    
    for (int j = 0; j < numLimbs; j++) {
      final bjBig = BigInt.from(b[j]).toUnsigned(64);
      final prod = aiBig * bjBig + t[i + j] + carry;
      t[i + j] = prod & mask64;
      carry = prod >> 64;
    }
    t[i + numLimbs] += carry;
    
    // Fase 2: m = t[i] * n0 mod 2^64, t += m * n
    final m = (t[i] * n0Big) & mask64;
    
    carry = BigInt.zero;
    for (int j = 0; j < numLimbs; j++) {
      final njBig = BigInt.from(n[j]).toUnsigned(64);
      final prod = m * njBig + t[i + j] + carry;
      t[i + j] = prod & mask64;
      carry = prod >> 64;
    }
    t[i + numLimbs] += carry;
  }
  
  // Copia resultado da parte alta
  final result = List<int>.filled(numLimbs, 0);
  for (int i = 0; i < numLimbs; i++) {
    result[i] = t[numLimbs + i].toInt();
  }
  
  // Subtração condicional se result >= n
  if (_cmpBigList(result, n) >= 0) {
    _subInPlace(result, n);
  }
  
  return result;
}

int _cmpBigList(List<int> a, List<int> b) {
  for (int i = a.length - 1; i >= 0; i--) {
    final ai = BigInt.from(a[i]).toUnsigned(64);
    final bi = BigInt.from(b[i]).toUnsigned(64);
    if (ai > bi) return 1;
    if (ai < bi) return -1;
  }
  return 0;
}

void _subInPlace(List<int> a, List<int> b) {
  BigInt borrow = BigInt.zero;
  final mask64 = BigInt.from(0xFFFFFFFFFFFFFFFF);
  
  for (int i = 0; i < a.length; i++) {
    final ai = BigInt.from(a[i]).toUnsigned(64);
    final bi = BigInt.from(b[i]).toUnsigned(64);
    final diff = ai - bi - borrow;
    if (diff < BigInt.zero) {
      a[i] = (diff + (BigInt.one << 64)).toInt();
      borrow = BigInt.one;
    } else {
      a[i] = (diff & mask64).toInt();
      borrow = BigInt.zero;
    }
  }
}

/// Chama o shellcode ASM
List<int> _callAsmMontMul(List<int> a, List<int> b, List<int> n, int n0, int numLimbs) {
  // Aloca memória executável (carrega sob demanda)
  final execMem = ExecutableMemory.allocate(_getShellCode());
  
  // Aloca buffers
  final pRes = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
  final pA = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
  final pB = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
  final pN = pkg_ffi.calloc<ffi.Uint64>(numLimbs);
  
  try {
    // Copia dados
    final aList = pA.asTypedList(numLimbs);
    final bList = pB.asTypedList(numLimbs);
    final nList = pN.asTypedList(numLimbs);
    
    for (int i = 0; i < numLimbs; i++) {
      aList[i] = a[i];
      bList[i] = b[i];
      nList[i] = n[i];
    }
    
    // Chama função
    final funcPtr = execMem.pointer.cast<ffi.NativeFunction<_MontMulNative>>();
    final func = funcPtr.asFunction<_MontMulDart>();
    
    func(pRes, pA, pB, pN, n0, numLimbs);
    
    // Lê resultado
    final resList = pRes.asTypedList(numLimbs);
    return List<int>.from(resList);
  } finally {
    pkg_ffi.calloc.free(pRes);
    pkg_ffi.calloc.free(pA);
    pkg_ffi.calloc.free(pB);
    pkg_ffi.calloc.free(pN);
    execMem.free();
  }
}
