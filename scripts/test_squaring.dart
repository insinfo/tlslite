/// Teste específico do squaring ASM
/// Compara squaring otimizado vs multiplicação genérica

import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart' as pkg_ffi;
import 'dart:io';

typedef _MontMulNative = ffi.Void Function(
  ffi.Pointer<ffi.Uint64> result,
  ffi.Pointer<ffi.Uint64> a,
  ffi.Pointer<ffi.Uint64> b,
  ffi.Pointer<ffi.Uint64> n,
  ffi.Int64 n0,
  ffi.Int64 numLimbs,
);

typedef _MontMulDart = void Function(
  ffi.Pointer<ffi.Uint64> result,
  ffi.Pointer<ffi.Uint64> a,
  ffi.Pointer<ffi.Uint64> b,
  ffi.Pointer<ffi.Uint64> n,
  int n0,
  int numLimbs,
);

typedef _MontSqrNative = ffi.Void Function(
  ffi.Pointer<ffi.Uint64> result,
  ffi.Pointer<ffi.Uint64> a,
  ffi.Pointer<ffi.Uint64> n,
  ffi.Int64 n0,
);

typedef _MontSqrDart = void Function(
  ffi.Pointer<ffi.Uint64> result,
  ffi.Pointer<ffi.Uint64> a,
  ffi.Pointer<ffi.Uint64> n,
  int n0,
);

void main() {
  print('Teste de Squaring ASM');
  print('=' * 50);

  // Carrega shellcodes
  final mulBin = File('native_tools/mont_mul_4limbs.bin').readAsBytesSync();
  final sqrBin = File('native_tools/mont_sqr_4limbs.bin').readAsBytesSync();
  
  print('mult shellcode: ${mulBin.length} bytes');
  print('sqr shellcode: ${sqrBin.length} bytes');

  // Aloca memória executável
  final kernel32 = ffi.DynamicLibrary.open('kernel32.dll');
  
  final VirtualAlloc = kernel32.lookupFunction<
      ffi.Pointer<ffi.Void> Function(
          ffi.Pointer<ffi.Void>, ffi.IntPtr, ffi.Uint32, ffi.Uint32),
      ffi.Pointer<ffi.Void> Function(ffi.Pointer<ffi.Void>, int, int, int)>(
      'VirtualAlloc');
  
  const MEM_COMMIT = 0x1000;
  const MEM_RESERVE = 0x2000;
  const PAGE_EXECUTE_READWRITE = 0x40;

  // Aloca para multiply
  final execMemMul = VirtualAlloc(
    ffi.nullptr,
    mulBin.length,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
  );
  
  // Aloca para squaring
  final execMemSqr = VirtualAlloc(
    ffi.nullptr,
    sqrBin.length,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE,
  );
  
  // Copia shellcodes
  final mulBytes = execMemMul.cast<ffi.Uint8>();
  for (int i = 0; i < mulBin.length; i++) {
    mulBytes[i] = mulBin[i];
  }
  
  final sqrBytes = execMemSqr.cast<ffi.Uint8>();
  for (int i = 0; i < sqrBin.length; i++) {
    sqrBytes[i] = sqrBin[i];
  }

  // Cria funções
  final mulFunc = execMemMul
      .cast<ffi.NativeFunction<_MontMulNative>>()
      .asFunction<_MontMulDart>();
      
  final sqrFunc = execMemSqr
      .cast<ffi.NativeFunction<_MontSqrNative>>()
      .asFunction<_MontSqrDart>();

  // Aloca buffers
  final bufResult = pkg_ffi.calloc<ffi.Uint64>(4);
  final bufResultSqr = pkg_ffi.calloc<ffi.Uint64>(4);
  final bufA = pkg_ffi.calloc<ffi.Uint64>(4);
  final bufB = pkg_ffi.calloc<ffi.Uint64>(4);
  final bufN = pkg_ffi.calloc<ffi.Uint64>(4);

  // Módulo: secp256k1 prime
  final nList = bufN.asTypedList(4);
  nList[0] = 0xFFFFFFFEFFFFFC2F;
  nList[1] = 0xFFFFFFFFFFFFFFFF;
  nList[2] = 0xFFFFFFFFFFFFFFFF;
  nList[3] = 0xFFFFFFFFFFFFFFFF;
  
  // n0 = -n^-1 mod 2^64
  final n0 = _computeN0(nList[0]);
  print('n0 = 0x${n0.toUnsigned(64).toRadixString(16)}');

  // Teste com vários valores
  final testCases = [
    [1, 0, 0, 0], // Pequeno
    [7, 0, 0, 0], // Pequeno
    [0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0], // Grande
    [0xFFFFFFFF, 0xFFFFFFFF, 0, 0], // Médio
  ];

  for (final testVal in testCases) {
    print('\n--- Testando a = ${testVal.map((v) => '0x${v.toUnsigned(64).toRadixString(16)}').toList()} ---');
    
    // Configura a
    final aList = bufA.asTypedList(4);
    final bList = bufB.asTypedList(4);
    for (int i = 0; i < 4; i++) {
      aList[i] = testVal[i];
      bList[i] = testVal[i]; // b = a para squaring
    }

    // Multiplica via função genérica (a * a)
    mulFunc(bufResult, bufA, bufB, bufN, n0, 4);
    
    // Squaring otimizado
    sqrFunc(bufResultSqr, bufA, bufN, n0);

    // Compara resultados
    final resMul = bufResult.asTypedList(4);
    final resSqr = bufResultSqr.asTypedList(4);

    print('mul(a,a) = ${resMul.map((v) => '0x${v.toUnsigned(64).toRadixString(16)}').toList()}');
    print('sqr(a)   = ${resSqr.map((v) => '0x${v.toUnsigned(64).toRadixString(16)}').toList()}');

    bool match = true;
    for (int i = 0; i < 4; i++) {
      if (resMul[i] != resSqr[i]) {
        match = false;
        break;
      }
    }

    if (match) {
      print('✓ OK');
    } else {
      print('✗ ERRO! Resultados diferentes!');
    }
  }

  // Cleanup
  pkg_ffi.calloc.free(bufResult);
  pkg_ffi.calloc.free(bufResultSqr);
  pkg_ffi.calloc.free(bufA);
  pkg_ffi.calloc.free(bufB);
  pkg_ffi.calloc.free(bufN);
}

int _computeN0(int n0_limb) {
  // Calcula -n^-1 mod 2^64 usando método iterativo
  int x = 1;
  for (int i = 0; i < 64; i++) {
    x = x * x * n0_limb;
  }
  return (-x) & 0xFFFFFFFFFFFFFFFF;
}
