/// Debug test para verificar passagem de parâmetros FFI
import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart' as pkg_ffi;
import 'package:tlslite/src/utils/rijndael_fast_asm_x86_64.dart' show ExecutableMemory;

// Função que apenas retorna os argumentos para verificação
// Windows: rcx, rdx, r8, r9, [rsp+40], [rsp+48]
typedef TestNative = ffi.Uint64 Function(
  ffi.Uint64 a,
  ffi.Uint64 b,
  ffi.Uint64 c,
  ffi.Uint64 d,
  ffi.Uint64 e, // 5º arg - stack
  ffi.Uint64 f, // 6º arg - stack  
);
typedef TestDart = int Function(int a, int b, int c, int d, int e, int f);

void main() {
  // Shellcode que retorna o 5º argumento (deveria retornar 0xDEADBEEF)
  // Windows x64: 5º arg está em [rsp + 40] (após return address + shadow space)
  final code = Uint8List.fromList([
    // mov rax, [rsp+40]  (5º argumento)
    0x48, 0x8B, 0x44, 0x24, 0x28,  // rsp+40 = 0x28
    0xC3,  // ret
  ]);
  
  final execMem = ExecutableMemory.allocate(code);
  final funcPtr = execMem.pointer.cast<ffi.NativeFunction<TestNative>>();
  final func = funcPtr.asFunction<TestDart>();
  
  // Chama com valores conhecidos
  final result = func(
    0x1111111111111111, // rcx
    0x2222222222222222, // rdx
    0x3333333333333333, // r8
    0x4444444444444444, // r9
    0xDEADBEEFCAFEBABE, // [rsp+40] - devemos receber este!
    0x6666666666666666, // [rsp+48]
  );
  
  print('Resultado: 0x${result.toRadixString(16).toUpperCase()}');
  print('Esperado:  0xDEADBEEFCAFEBABE');
  print('Match: ${result == 0xDEADBEEFCAFEBABE}');
  
  // Testa 6º argumento
  final code2 = Uint8List.fromList([
    // mov rax, [rsp+48]  (6º argumento)
    0x48, 0x8B, 0x44, 0x24, 0x30,  // rsp+48 = 0x30
    0xC3,
  ]);
  
  final execMem2 = ExecutableMemory.allocate(code2);
  final funcPtr2 = execMem2.pointer.cast<ffi.NativeFunction<TestNative>>();
  final func2 = funcPtr2.asFunction<TestDart>();
  
  final result2 = func2(
    0x1111111111111111,
    0x2222222222222222,
    0x3333333333333333,
    0x4444444444444444,
    0x5555555555555555,
    0x6666666666666666, // devemos receber este!
  );
  
  print('');
  print('Resultado 6º arg: 0x${result2.toRadixString(16).toUpperCase()}');
  print('Esperado:         0x6666666666666666');
  print('Match: ${result2 == 0x6666666666666666}');
  
  execMem.free();
  execMem2.free();
}
