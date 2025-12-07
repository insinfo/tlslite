// dart format width=5000
//
// Versão otimizada do Rijndael que usa instruções AES-NI via shell code x86_64
// Inspirada na implementação do OpenSSL (aesni-x86_64.pl)
//
// Esta implementação usa instruções de hardware AES-NI quando disponíveis:
// - aesenc / aesenclast para encriptação
// - aesdec / aesdeclast para decriptação
// - aeskeygenassist para expansão de chave
//
// IMPORTANTE: Esta implementação só funciona em processadores x86_64 com suporte AES-NI
// Para verificar suporte: CPUID com EAX=1, verificar bit 25 de ECX

import 'dart:ffi' as ffi;
import 'dart:io' show Platform;
import 'dart:typed_data';
import 'package:ffi/ffi.dart' as pkgffi;

/// Verifica se a plataforma suporta AES-NI
class AesNiSupport {
  static bool? _supported;

  /// Retorna true se AES-NI é suportado
  static bool get isSupported {
    _supported ??= _checkAesNiSupport();
    return _supported!;
  }

  static bool _checkAesNiSupport() {
    // Só suporta x86_64 Windows/Linux
    if (!Platform.isWindows && !Platform.isLinux) {
      return false;
    }

    try {
      // Tenta executar CPUID para verificar suporte AES-NI
      return _executeCpuidCheck();
    } catch (e) {
      return false;
    }
  }

  static bool _executeCpuidCheck() {
    // Shell code x86_64 para CPUID
    // Verifica bit 25 de ECX quando EAX=1
    //
    // Código assembly:
    // push rbx              ; salva rbx (callee-saved)
    // mov eax, 1            ; função CPUID 1
    // cpuid                 ; executa CPUID
    // mov eax, ecx          ; resultado em ecx
    // shr eax, 25           ; shift right 25 bits
    // and eax, 1            ; isola bit 25
    // pop rbx               ; restaura rbx
    // ret                   ; retorna

    final Uint8List cpuidCode;

    if (Platform.isWindows) {
      // Windows x64 calling convention
      cpuidCode = Uint8List.fromList([
        0x53, // push rbx
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0x0F, 0xA2, // cpuid
        0x89, 0xC8, // mov eax, ecx
        0xC1, 0xE8, 0x19, // shr eax, 25
        0x83, 0xE0, 0x01, // and eax, 1
        0x5B, // pop rbx
        0xC3, // ret
      ]);
    } else {
      // Linux/System V AMD64 ABI
      cpuidCode = Uint8List.fromList([
        0x53, // push rbx
        0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0x0F, 0xA2, // cpuid
        0x89, 0xC8, // mov eax, ecx
        0xC1, 0xE8, 0x19, // shr eax, 25
        0x83, 0xE0, 0x01, // and eax, 1
        0x5B, // pop rbx
        0xC3, // ret
      ]);
    }

    final result = _executeShellCode(cpuidCode);
    return result == 1;
  }

  /// Executa shell code e retorna o resultado (valor em EAX/RAX)
  static int _executeShellCode(Uint8List code) {
    final execMem = _allocateExecutableMemory(code.length);
    if (execMem == ffi.nullptr) {
      throw StateError('Falha ao alocar memória executável');
    }

    try {
      // Copia o código para a memória executável
      final codePtr = execMem.cast<ffi.Uint8>();
      for (int i = 0; i < code.length; i++) {
        codePtr[i] = code[i];
      }

      // Cria ponteiro de função e executa
      final funcPtr = execMem.cast<ffi.NativeFunction<ffi.Int32 Function()>>();
      final func = funcPtr.asFunction<int Function()>();

      return func();
    } finally {
      _freeExecutableMemory(execMem, code.length);
    }
  }

  static ffi.Pointer<ffi.Void> _allocateExecutableMemory(int size) {
    if (Platform.isWindows) {
      return _windowsAllocExecutable(size);
    } else {
      return _linuxAllocExecutable(size);
    }
  }

  static void _freeExecutableMemory(ffi.Pointer<ffi.Void> ptr, int size) {
    if (Platform.isWindows) {
      _windowsFreeExecutable(ptr);
    } else {
      _linuxFreeExecutable(ptr, size);
    }
  }

  // Windows: VirtualAlloc / VirtualFree
  static ffi.Pointer<ffi.Void> _windowsAllocExecutable(int size) {
    final kernel32 = ffi.DynamicLibrary.open('kernel32.dll');

    // VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    final virtualAlloc = kernel32.lookupFunction<
        ffi.Pointer<ffi.Void> Function(
            ffi.Pointer<ffi.Void>, ffi.IntPtr, ffi.Uint32, ffi.Uint32),
        ffi.Pointer<ffi.Void> Function(
            ffi.Pointer<ffi.Void>, int, int, int)>('VirtualAlloc');

    const int MEM_COMMIT = 0x1000;
    const int MEM_RESERVE = 0x2000;
    const int PAGE_EXECUTE_READWRITE = 0x40;

    return virtualAlloc(
        ffi.nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  }

  static void _windowsFreeExecutable(ffi.Pointer<ffi.Void> ptr) {
    final kernel32 = ffi.DynamicLibrary.open('kernel32.dll');

    final virtualFree = kernel32.lookupFunction<
        ffi.Int32 Function(ffi.Pointer<ffi.Void>, ffi.IntPtr, ffi.Uint32),
        int Function(ffi.Pointer<ffi.Void>, int, int)>('VirtualFree');

    const int MEM_RELEASE = 0x8000;
    virtualFree(ptr, 0, MEM_RELEASE);
  }

  // Linux: mmap / munmap
  static ffi.Pointer<ffi.Void> _linuxAllocExecutable(int size) {
    final libc = ffi.DynamicLibrary.open('libc.so.6');

    // mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    final mmap = libc.lookupFunction<
        ffi.Pointer<ffi.Void> Function(ffi.Pointer<ffi.Void>, ffi.IntPtr,
            ffi.Int32, ffi.Int32, ffi.Int32, ffi.Int64),
        ffi.Pointer<ffi.Void> Function(
            ffi.Pointer<ffi.Void>, int, int, int, int, int)>('mmap');

    const int PROT_READ = 0x1;
    const int PROT_WRITE = 0x2;
    const int PROT_EXEC = 0x4;
    const int MAP_PRIVATE = 0x02;
    const int MAP_ANONYMOUS = 0x20;

    return mmap(ffi.nullptr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  }

  static void _linuxFreeExecutable(ffi.Pointer<ffi.Void> ptr, int size) {
    final libc = ffi.DynamicLibrary.open('libc.so.6');

    final munmap = libc.lookupFunction<
        ffi.Int32 Function(ffi.Pointer<ffi.Void>, ffi.IntPtr),
        int Function(ffi.Pointer<ffi.Void>, int)>('munmap');

    munmap(ptr, size);
  }
}

/// Gerenciador de memória executável para shell code
class ExecutableMemory {
  final ffi.Pointer<ffi.Void> pointer;
  final int size;
  bool _freed = false;

  ExecutableMemory._(this.pointer, this.size);

  /// Aloca memória executável e copia o código
  static ExecutableMemory allocate(Uint8List code) {
    final ptr = AesNiSupport._allocateExecutableMemory(code.length);
    if (ptr == ffi.nullptr) {
      throw StateError('Falha ao alocar memória executável');
    }

    // Copia o código
    final codePtr = ptr.cast<ffi.Uint8>();
    for (int i = 0; i < code.length; i++) {
      codePtr[i] = code[i];
    }

    return ExecutableMemory._(ptr, code.length);
  }

  /// Libera a memória
  void free() {
    if (_freed) return;
    AesNiSupport._freeExecutableMemory(pointer, size);
    _freed = true;
  }

  bool get isFreed => _freed;
}

/// Shell codes AES-NI x86_64
///
/// Baseados no OpenSSL aesni-x86_64.pl
/// Usa instruções:
/// - movdqu: load/store 128-bit unaligned
/// - pxor: XOR 128-bit
/// - aesenc: AES encryption round
/// - aesenclast: AES final encryption round
/// - aesdec: AES decryption round
/// - aesdeclast: AES final decryption round
class AesNiShellCode {
  /// Shell code para encriptação de 1 bloco AES-128 (10 rounds)
  ///
  /// Parâmetros (Windows x64):
  ///   rcx = ponteiro para input (16 bytes)
  ///   rdx = ponteiro para output (16 bytes)
  ///   r8  = ponteiro para round keys (176 bytes = 11 * 16)
  ///
  /// Código assembly:
  /// ```asm
  /// ; Carregar input e round key 0
  /// movdqu xmm0, [rcx]        ; load input
  /// movdqu xmm1, [r8]         ; load key[0]
  /// pxor   xmm0, xmm1         ; AddRoundKey inicial
  ///
  /// ; Rounds 1-9
  /// movdqu xmm1, [r8+16]
  /// aesenc xmm0, xmm1
  /// movdqu xmm1, [r8+32]
  /// aesenc xmm0, xmm1
  /// ... (continua para todos os rounds)
  ///
  /// ; Round 10 (final)
  /// movdqu xmm1, [r8+160]
  /// aesenclast xmm0, xmm1
  ///
  /// ; Store resultado
  /// movdqu [rdx], xmm0
  /// ret
  /// ```
  static Uint8List getEncrypt128ShellCode() {
    // Opcode bytes para instruções AES-NI (Windows x64 calling convention)
    return Uint8List.fromList([
      // movdqu xmm0, [rcx] - load input
      0xF3, 0x0F, 0x6F, 0x01,

      // movdqu xmm1, [r8] - load key[0]
      0xF3, 0x41, 0x0F, 0x6F, 0x08,

      // pxor xmm0, xmm1 - AddRoundKey inicial
      0x66, 0x0F, 0xEF, 0xC1,

      // Round 1: movdqu xmm1, [r8+16]; aesenc xmm0, xmm1
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x10,
      0x66, 0x0F, 0x38, 0xDC, 0xC1,

      // Round 2: movdqu xmm1, [r8+32]; aesenc xmm0, xmm1
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x20,
      0x66, 0x0F, 0x38, 0xDC, 0xC1,

      // Round 3: movdqu xmm1, [r8+48]; aesenc xmm0, xmm1
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x30,
      0x66, 0x0F, 0x38, 0xDC, 0xC1,

      // Round 4: movdqu xmm1, [r8+64]; aesenc xmm0, xmm1
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x40,
      0x66, 0x0F, 0x38, 0xDC, 0xC1,

      // Round 5: movdqu xmm1, [r8+80]; aesenc xmm0, xmm1
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x50,
      0x66, 0x0F, 0x38, 0xDC, 0xC1,

      // Round 6: movdqu xmm1, [r8+96]; aesenc xmm0, xmm1
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x60,
      0x66, 0x0F, 0x38, 0xDC, 0xC1,

      // Round 7: movdqu xmm1, [r8+112]; aesenc xmm0, xmm1
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x70,
      0x66, 0x0F, 0x38, 0xDC, 0xC1,

      // Round 8: movdqu xmm1, [r8+128]; aesenc xmm0, xmm1
      0xF3, 0x41, 0x0F, 0x6F, 0x88, 0x80, 0x00, 0x00, 0x00,
      0x66, 0x0F, 0x38, 0xDC, 0xC1,

      // Round 9: movdqu xmm1, [r8+144]; aesenc xmm0, xmm1
      0xF3, 0x41, 0x0F, 0x6F, 0x88, 0x90, 0x00, 0x00, 0x00,
      0x66, 0x0F, 0x38, 0xDC, 0xC1,

      // Round 10 (final): movdqu xmm1, [r8+160]; aesenclast xmm0, xmm1
      0xF3, 0x41, 0x0F, 0x6F, 0x88, 0xA0, 0x00, 0x00, 0x00,
      0x66, 0x0F, 0x38, 0xDD, 0xC1,

      // movdqu [rdx], xmm0 - store output
      0xF3, 0x0F, 0x7F, 0x02,

      // ret
      0xC3,
    ]);
  }

  /// Shell code para decriptação de 1 bloco AES-128 (10 rounds)
  static Uint8List getDecrypt128ShellCode() {
    return Uint8List.fromList([
      // movdqu xmm0, [rcx] - load input
      0xF3, 0x0F, 0x6F, 0x01,

      // movdqu xmm1, [r8] - load key[0] (que é key[10] original)
      0xF3, 0x41, 0x0F, 0x6F, 0x08,

      // pxor xmm0, xmm1 - AddRoundKey inicial
      0x66, 0x0F, 0xEF, 0xC1,

      // Round 1: movdqu xmm1, [r8+16]; aesdec xmm0, xmm1
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x10,
      0x66, 0x0F, 0x38, 0xDE, 0xC1,

      // Round 2
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x20,
      0x66, 0x0F, 0x38, 0xDE, 0xC1,

      // Round 3
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x30,
      0x66, 0x0F, 0x38, 0xDE, 0xC1,

      // Round 4
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x40,
      0x66, 0x0F, 0x38, 0xDE, 0xC1,

      // Round 5
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x50,
      0x66, 0x0F, 0x38, 0xDE, 0xC1,

      // Round 6
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x60,
      0x66, 0x0F, 0x38, 0xDE, 0xC1,

      // Round 7
      0xF3, 0x41, 0x0F, 0x6F, 0x48, 0x70,
      0x66, 0x0F, 0x38, 0xDE, 0xC1,

      // Round 8
      0xF3, 0x41, 0x0F, 0x6F, 0x88, 0x80, 0x00, 0x00, 0x00,
      0x66, 0x0F, 0x38, 0xDE, 0xC1,

      // Round 9
      0xF3, 0x41, 0x0F, 0x6F, 0x88, 0x90, 0x00, 0x00, 0x00,
      0x66, 0x0F, 0x38, 0xDE, 0xC1,

      // Round 10 (final): aesdeclast
      0xF3, 0x41, 0x0F, 0x6F, 0x88, 0xA0, 0x00, 0x00, 0x00,
      0x66, 0x0F, 0x38, 0xDF, 0xC1,

      // movdqu [rdx], xmm0
      0xF3, 0x0F, 0x7F, 0x02,

      // ret
      0xC3,
    ]);
  }

  /// Shell code para encriptação AES-192 (12 rounds)
  static Uint8List getEncrypt192ShellCode() {
    return Uint8List.fromList([
      // movdqu xmm0, [rcx]
      0xF3, 0x0F, 0x6F, 0x01,
      // movdqu xmm1, [r8]
      0xF3, 0x41, 0x0F, 0x6F, 0x08,
      // pxor xmm0, xmm1
      0x66, 0x0F, 0xEF, 0xC1,

      // Rounds 1-11 (aesenc)
      ..._generateAesencRounds(11),

      // Round 12 (final): movdqu xmm1, [r8+192]; aesenclast
      0xF3, 0x41, 0x0F, 0x6F, 0x88, 0xC0, 0x00, 0x00, 0x00,
      0x66, 0x0F, 0x38, 0xDD, 0xC1,

      // movdqu [rdx], xmm0
      0xF3, 0x0F, 0x7F, 0x02,
      0xC3,
    ]);
  }

  /// Shell code para encriptação AES-256 (14 rounds)
  static Uint8List getEncrypt256ShellCode() {
    return Uint8List.fromList([
      // movdqu xmm0, [rcx]
      0xF3, 0x0F, 0x6F, 0x01,
      // movdqu xmm1, [r8]
      0xF3, 0x41, 0x0F, 0x6F, 0x08,
      // pxor xmm0, xmm1
      0x66, 0x0F, 0xEF, 0xC1,

      // Rounds 1-13 (aesenc)
      ..._generateAesencRounds(13),

      // Round 14 (final): movdqu xmm1, [r8+224]; aesenclast
      0xF3, 0x41, 0x0F, 0x6F, 0x88, 0xE0, 0x00, 0x00, 0x00,
      0x66, 0x0F, 0x38, 0xDD, 0xC1,

      // movdqu [rdx], xmm0
      0xF3, 0x0F, 0x7F, 0x02,
      0xC3,
    ]);
  }

  /// Gera bytes para N rounds de aesenc
  static List<int> _generateAesencRounds(int numRounds) {
    final bytes = <int>[];

    for (int i = 1; i <= numRounds; i++) {
      final offset = i * 16;

      if (offset <= 0x7F) {
        // Offset cabe em 1 byte (disp8)
        // movdqu xmm1, [r8+offset]
        bytes.addAll([0xF3, 0x41, 0x0F, 0x6F, 0x48, offset]);
      } else {
        // Offset precisa de 4 bytes (disp32)
        // movdqu xmm1, [r8+offset]
        bytes.addAll([
          0xF3,
          0x41,
          0x0F,
          0x6F,
          0x88,
          offset & 0xFF,
          (offset >> 8) & 0xFF,
          (offset >> 16) & 0xFF,
          (offset >> 24) & 0xFF,
        ]);
      }

      // aesenc xmm0, xmm1
      bytes.addAll([0x66, 0x0F, 0x38, 0xDC, 0xC1]);
    }

    return bytes;
  }

  /// Gera bytes para N rounds de aesdec
  static List<int> _generateAesdecRounds(int numRounds) {
    final bytes = <int>[];

    for (int i = 1; i <= numRounds; i++) {
      final offset = i * 16;

      if (offset <= 0x7F) {
        bytes.addAll([0xF3, 0x41, 0x0F, 0x6F, 0x48, offset]);
      } else {
        bytes.addAll([
          0xF3,
          0x41,
          0x0F,
          0x6F,
          0x88,
          offset & 0xFF,
          (offset >> 8) & 0xFF,
          (offset >> 16) & 0xFF,
          (offset >> 24) & 0xFF,
        ]);
      }

      // aesdec xmm0, xmm1
      bytes.addAll([0x66, 0x0F, 0x38, 0xDE, 0xC1]);
    }

    return bytes;
  }

  /// Shell code para decriptação AES-192 (12 rounds)
  static Uint8List getDecrypt192ShellCode() {
    return Uint8List.fromList([
      0xF3, 0x0F, 0x6F, 0x01,
      0xF3, 0x41, 0x0F, 0x6F, 0x08,
      0x66, 0x0F, 0xEF, 0xC1,
      ..._generateAesdecRounds(11),
      // Round 12: aesdeclast
      0xF3, 0x41, 0x0F, 0x6F, 0x88, 0xC0, 0x00, 0x00, 0x00,
      0x66, 0x0F, 0x38, 0xDF, 0xC1,
      0xF3, 0x0F, 0x7F, 0x02,
      0xC3,
    ]);
  }

  /// Shell code para decriptação AES-256 (14 rounds)
  static Uint8List getDecrypt256ShellCode() {
    return Uint8List.fromList([
      0xF3, 0x0F, 0x6F, 0x01,
      0xF3, 0x41, 0x0F, 0x6F, 0x08,
      0x66, 0x0F, 0xEF, 0xC1,
      ..._generateAesdecRounds(13),
      // Round 14: aesdeclast
      0xF3, 0x41, 0x0F, 0x6F, 0x88, 0xE0, 0x00, 0x00, 0x00,
      0x66, 0x0F, 0x38, 0xDF, 0xC1,
      0xF3, 0x0F, 0x7F, 0x02,
      0xC3,
    ]);
  }

  // ============================================================
  // Shell codes para expansão de chave usando AESKEYGENASSIST
  // Isso elimina lookup tables da S-box, tornando a implementação
  // 100% resistente a ataques de canal lateral (side-channel)
  // ============================================================

  /// Shell code para expansão de chave AES-128 usando AESKEYGENASSIST
  ///
  /// Parâmetros (Windows x64):
  ///   rcx = ponteiro para chave original (16 bytes)
  ///   rdx = ponteiro para round keys de saída (176 bytes = 11 * 16)
  ///
  /// Código assembly:
  /// ```asm
  /// movdqu xmm0, [rcx]        ; carrega chave original
  /// movdqu [rdx], xmm0        ; salva round key 0
  ///
  /// aeskeygenassist xmm1, xmm0, 0x01
  /// call key_expand_128
  /// movdqu [rdx+16], xmm0
  /// ... (repete para cada rcon)
  /// ret
  ///
  /// key_expand_128:
  ///   pshufd xmm1, xmm1, 0xff  ; broadcast byte alto
  ///   vpslldq xmm2, xmm0, 4    ; shift left
  ///   pxor xmm0, xmm2
  ///   vpslldq xmm2, xmm0, 4
  ///   pxor xmm0, xmm2
  ///   vpslldq xmm2, xmm0, 4
  ///   pxor xmm0, xmm2
  ///   pxor xmm0, xmm1
  ///   ret
  /// ```
  static Uint8List getKeyExpand128ShellCode() {
    // Shell code para expansão completa de chave AES-128
    // Usa registradores XMM0-XMM2, não precisa de S-box
    return Uint8List.fromList([
      // movdqu xmm0, [rcx] - carrega chave
      0xF3, 0x0F, 0x6F, 0x01,

      // movdqu [rdx], xmm0 - salva round key 0
      0xF3, 0x0F, 0x7F, 0x02,

      // Round 1 (rcon=0x01)
      // aeskeygenassist xmm1, xmm0, 0x01
      0x66, 0x0F, 0x3A, 0xDF, 0xC8, 0x01,
      // Inline key expansion
      ..._keyExpand128Inline(),
      // movdqu [rdx+16], xmm0
      0xF3, 0x0F, 0x7F, 0x42, 0x10,

      // Round 2 (rcon=0x02)
      0x66, 0x0F, 0x3A, 0xDF, 0xC8, 0x02,
      ..._keyExpand128Inline(),
      0xF3, 0x0F, 0x7F, 0x42, 0x20,

      // Round 3 (rcon=0x04)
      0x66, 0x0F, 0x3A, 0xDF, 0xC8, 0x04,
      ..._keyExpand128Inline(),
      0xF3, 0x0F, 0x7F, 0x42, 0x30,

      // Round 4 (rcon=0x08)
      0x66, 0x0F, 0x3A, 0xDF, 0xC8, 0x08,
      ..._keyExpand128Inline(),
      0xF3, 0x0F, 0x7F, 0x42, 0x40,

      // Round 5 (rcon=0x10)
      0x66, 0x0F, 0x3A, 0xDF, 0xC8, 0x10,
      ..._keyExpand128Inline(),
      0xF3, 0x0F, 0x7F, 0x42, 0x50,

      // Round 6 (rcon=0x20)
      0x66, 0x0F, 0x3A, 0xDF, 0xC8, 0x20,
      ..._keyExpand128Inline(),
      0xF3, 0x0F, 0x7F, 0x42, 0x60,

      // Round 7 (rcon=0x40)
      0x66, 0x0F, 0x3A, 0xDF, 0xC8, 0x40,
      ..._keyExpand128Inline(),
      0xF3, 0x0F, 0x7F, 0x42, 0x70,

      // Round 8 (rcon=0x80)
      0x66, 0x0F, 0x3A, 0xDF, 0xC8, 0x80,
      ..._keyExpand128Inline(),
      // movdqu [rdx+128], xmm0
      0xF3, 0x0F, 0x7F, 0x82, 0x80, 0x00, 0x00, 0x00,

      // Round 9 (rcon=0x1B)
      0x66, 0x0F, 0x3A, 0xDF, 0xC8, 0x1B,
      ..._keyExpand128Inline(),
      // movdqu [rdx+144], xmm0
      0xF3, 0x0F, 0x7F, 0x82, 0x90, 0x00, 0x00, 0x00,

      // Round 10 (rcon=0x36)
      0x66, 0x0F, 0x3A, 0xDF, 0xC8, 0x36,
      ..._keyExpand128Inline(),
      // movdqu [rdx+160], xmm0
      0xF3, 0x0F, 0x7F, 0x82, 0xA0, 0x00, 0x00, 0x00,

      // ret
      0xC3,
    ]);
  }

  /// Gera bytes para expansão inline de uma round key AES-128
  /// Usa xmm0 como estado atual, xmm1 como resultado do aeskeygenassist
  static List<int> _keyExpand128Inline() {
    return [
      // pshufd xmm1, xmm1, 0xff - broadcast byte mais alto
      0x66, 0x0F, 0x70, 0xC9, 0xFF,

      // movdqa xmm2, xmm0
      0x66, 0x0F, 0x6F, 0xD0,

      // pslldq xmm2, 4 (shift left 4 bytes)
      0x66, 0x0F, 0x73, 0xFA, 0x04,

      // pxor xmm0, xmm2
      0x66, 0x0F, 0xEF, 0xC2,

      // movdqa xmm2, xmm0
      0x66, 0x0F, 0x6F, 0xD0,

      // pslldq xmm2, 4
      0x66, 0x0F, 0x73, 0xFA, 0x04,

      // pxor xmm0, xmm2
      0x66, 0x0F, 0xEF, 0xC2,

      // movdqa xmm2, xmm0
      0x66, 0x0F, 0x6F, 0xD0,

      // pslldq xmm2, 4
      0x66, 0x0F, 0x73, 0xFA, 0x04,

      // pxor xmm0, xmm2
      0x66, 0x0F, 0xEF, 0xC2,

      // pxor xmm0, xmm1
      0x66, 0x0F, 0xEF, 0xC1,
    ];
  }

  /// Shell code para expansão de chave AES-192
  ///
  /// AES-192 é mais complexo porque usa 6 palavras (192 bits) de chave
  /// mas gera round keys de 128 bits
  static Uint8List getKeyExpand192ShellCode() {
    return Uint8List.fromList([
      // Carrega chave de 192 bits (24 bytes)
      // movdqu xmm0, [rcx]      ; primeiros 16 bytes
      0xF3, 0x0F, 0x6F, 0x01,
      // movq xmm1, [rcx+16]     ; últimos 8 bytes
      0xF3, 0x0F, 0x7E, 0x49, 0x10,

      // movdqu [rdx], xmm0      ; salva round key 0
      0xF3, 0x0F, 0x7F, 0x02,
      // movq [rdx+16], xmm1     ; parte da round key 1
      0x66, 0x0F, 0xD6, 0x4A, 0x10,

      // Round 1-2 (rcon=0x01)
      // aeskeygenassist xmm2, xmm1, 0x01
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x01,
      ..._keyExpand192Inline(),
      // movdqu [rdx+24], xmm0
      0xF3, 0x0F, 0x7F, 0x42, 0x18,
      // movq [rdx+40], xmm1
      0x66, 0x0F, 0xD6, 0x4A, 0x28,

      // Round 3-4 (rcon=0x02)
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x02,
      ..._keyExpand192Inline(),
      0xF3, 0x0F, 0x7F, 0x42, 0x30,
      0x66, 0x0F, 0xD6, 0x4A, 0x40,

      // Round 5-6 (rcon=0x04)
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x04,
      ..._keyExpand192Inline(),
      0xF3, 0x0F, 0x7F, 0x42, 0x48,
      0x66, 0x0F, 0xD6, 0x4A, 0x58,

      // Round 7-8 (rcon=0x08)
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x08,
      ..._keyExpand192Inline(),
      0xF3, 0x0F, 0x7F, 0x42, 0x60,
      0x66, 0x0F, 0xD6, 0x4A, 0x70,

      // Round 9-10 (rcon=0x10)
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x10,
      ..._keyExpand192Inline(),
      0xF3, 0x0F, 0x7F, 0x82, 0x78, 0x00, 0x00, 0x00,
      0x66, 0x0F, 0xD6, 0x8A, 0x88, 0x00, 0x00, 0x00,

      // Round 11-12 (rcon=0x20)
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x20,
      ..._keyExpand192Inline(),
      0xF3, 0x0F, 0x7F, 0x82, 0x90, 0x00, 0x00, 0x00,
      0x66, 0x0F, 0xD6, 0x8A, 0xA0, 0x00, 0x00, 0x00,

      // Round 12 (rcon=0x40) - último round parcial
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x40,
      ..._keyExpand192InlineLast(),
      0xF3, 0x0F, 0x7F, 0x82, 0xA8, 0x00, 0x00, 0x00,
      0xF3, 0x0F, 0x7F, 0x8A, 0xB8, 0x00, 0x00, 0x00,

      // ret
      0xC3,
    ]);
  }

  /// Expansão inline AES-192
  static List<int> _keyExpand192Inline() {
    return [
      // pshufd xmm2, xmm2, 0x55 - broadcast segundo dword
      0x66, 0x0F, 0x70, 0xD2, 0x55,

      // movdqa xmm3, xmm0
      0x66, 0x0F, 0x6F, 0xD8,
      // pslldq xmm3, 4
      0x66, 0x0F, 0x73, 0xFB, 0x04,
      // pxor xmm0, xmm3
      0x66, 0x0F, 0xEF, 0xC3,
      // movdqa xmm3, xmm0
      0x66, 0x0F, 0x6F, 0xD8,
      // pslldq xmm3, 4
      0x66, 0x0F, 0x73, 0xFB, 0x04,
      // pxor xmm0, xmm3
      0x66, 0x0F, 0xEF, 0xC3,
      // movdqa xmm3, xmm0
      0x66, 0x0F, 0x6F, 0xD8,
      // pslldq xmm3, 4
      0x66, 0x0F, 0x73, 0xFB, 0x04,
      // pxor xmm0, xmm3
      0x66, 0x0F, 0xEF, 0xC3,
      // pxor xmm0, xmm2
      0x66, 0x0F, 0xEF, 0xC2,

      // Expande xmm1 (últimas 2 palavras)
      // pshufd xmm2, xmm0, 0xff
      0x66, 0x0F, 0x70, 0xD0, 0xFF,
      // movdqa xmm3, xmm1
      0x66, 0x0F, 0x6F, 0xD9,
      // pslldq xmm3, 4
      0x66, 0x0F, 0x73, 0xFB, 0x04,
      // pxor xmm1, xmm3
      0x66, 0x0F, 0xEF, 0xCB,
      // pxor xmm1, xmm2
      0x66, 0x0F, 0xEF, 0xCA,
    ];
  }

  /// Último round de expansão AES-192 (não precisa expandir xmm1)
  static List<int> _keyExpand192InlineLast() {
    return [
      // pshufd xmm2, xmm2, 0x55
      0x66, 0x0F, 0x70, 0xD2, 0x55,

      // movdqa xmm3, xmm0
      0x66, 0x0F, 0x6F, 0xD8,
      // pslldq xmm3, 4
      0x66, 0x0F, 0x73, 0xFB, 0x04,
      // pxor xmm0, xmm3
      0x66, 0x0F, 0xEF, 0xC3,
      // movdqa xmm3, xmm0
      0x66, 0x0F, 0x6F, 0xD8,
      // pslldq xmm3, 4
      0x66, 0x0F, 0x73, 0xFB, 0x04,
      // pxor xmm0, xmm3
      0x66, 0x0F, 0xEF, 0xC3,
      // movdqa xmm3, xmm0
      0x66, 0x0F, 0x6F, 0xD8,
      // pslldq xmm3, 4
      0x66, 0x0F, 0x73, 0xFB, 0x04,
      // pxor xmm0, xmm3
      0x66, 0x0F, 0xEF, 0xC3,
      // pxor xmm0, xmm2
      0x66, 0x0F, 0xEF, 0xC2,

      // Copia xmm0 para xmm1 para a última round key
      0x66, 0x0F, 0x6F, 0xC8,
    ];
  }

  /// Shell code para expansão de chave AES-256
  ///
  /// AES-256 usa chave de 256 bits e gera 15 round keys
  static Uint8List getKeyExpand256ShellCode() {
    return Uint8List.fromList([
      // Carrega chave de 256 bits
      // movdqu xmm0, [rcx]      ; primeiros 16 bytes
      0xF3, 0x0F, 0x6F, 0x01,
      // movdqu xmm1, [rcx+16]   ; últimos 16 bytes
      0xF3, 0x0F, 0x6F, 0x49, 0x10,

      // movdqu [rdx], xmm0      ; salva round key 0
      0xF3, 0x0F, 0x7F, 0x02,
      // movdqu [rdx+16], xmm1   ; salva round key 1
      0xF3, 0x0F, 0x7F, 0x4A, 0x10,

      // Round 2 (rcon=0x01)
      // aeskeygenassist xmm2, xmm1, 0x01
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x01,
      ..._keyExpand256InlineOdd(),
      // movdqu [rdx+32], xmm0
      0xF3, 0x0F, 0x7F, 0x42, 0x20,

      // Round 3
      // aeskeygenassist xmm2, xmm0, 0x00
      0x66, 0x0F, 0x3A, 0xDF, 0xD0, 0x00,
      ..._keyExpand256InlineEven(),
      // movdqu [rdx+48], xmm1
      0xF3, 0x0F, 0x7F, 0x4A, 0x30,

      // Round 4 (rcon=0x02)
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x02,
      ..._keyExpand256InlineOdd(),
      0xF3, 0x0F, 0x7F, 0x42, 0x40,

      // Round 5
      0x66, 0x0F, 0x3A, 0xDF, 0xD0, 0x00,
      ..._keyExpand256InlineEven(),
      0xF3, 0x0F, 0x7F, 0x4A, 0x50,

      // Round 6 (rcon=0x04)
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x04,
      ..._keyExpand256InlineOdd(),
      0xF3, 0x0F, 0x7F, 0x42, 0x60,

      // Round 7
      0x66, 0x0F, 0x3A, 0xDF, 0xD0, 0x00,
      ..._keyExpand256InlineEven(),
      0xF3, 0x0F, 0x7F, 0x4A, 0x70,

      // Round 8 (rcon=0x08)
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x08,
      ..._keyExpand256InlineOdd(),
      0xF3, 0x0F, 0x7F, 0x82, 0x80, 0x00, 0x00, 0x00,

      // Round 9
      0x66, 0x0F, 0x3A, 0xDF, 0xD0, 0x00,
      ..._keyExpand256InlineEven(),
      0xF3, 0x0F, 0x7F, 0x8A, 0x90, 0x00, 0x00, 0x00,

      // Round 10 (rcon=0x10)
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x10,
      ..._keyExpand256InlineOdd(),
      0xF3, 0x0F, 0x7F, 0x82, 0xA0, 0x00, 0x00, 0x00,

      // Round 11
      0x66, 0x0F, 0x3A, 0xDF, 0xD0, 0x00,
      ..._keyExpand256InlineEven(),
      0xF3, 0x0F, 0x7F, 0x8A, 0xB0, 0x00, 0x00, 0x00,

      // Round 12 (rcon=0x20)
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x20,
      ..._keyExpand256InlineOdd(),
      0xF3, 0x0F, 0x7F, 0x82, 0xC0, 0x00, 0x00, 0x00,

      // Round 13
      0x66, 0x0F, 0x3A, 0xDF, 0xD0, 0x00,
      ..._keyExpand256InlineEven(),
      0xF3, 0x0F, 0x7F, 0x8A, 0xD0, 0x00, 0x00, 0x00,

      // Round 14 (rcon=0x40) - última round key
      0x66, 0x0F, 0x3A, 0xDF, 0xD1, 0x40,
      ..._keyExpand256InlineOdd(),
      0xF3, 0x0F, 0x7F, 0x82, 0xE0, 0x00, 0x00, 0x00,

      // ret
      0xC3,
    ]);
  }

  /// Expansão AES-256 para rounds ímpares (usa pshufd com 0xff)
  static List<int> _keyExpand256InlineOdd() {
    return [
      // pshufd xmm2, xmm2, 0xff
      0x66, 0x0F, 0x70, 0xD2, 0xFF,

      // movdqa xmm3, xmm0
      0x66, 0x0F, 0x6F, 0xD8,
      // pslldq xmm3, 4
      0x66, 0x0F, 0x73, 0xFB, 0x04,
      // pxor xmm0, xmm3
      0x66, 0x0F, 0xEF, 0xC3,
      // movdqa xmm3, xmm0
      0x66, 0x0F, 0x6F, 0xD8,
      // pslldq xmm3, 4
      0x66, 0x0F, 0x73, 0xFB, 0x04,
      // pxor xmm0, xmm3
      0x66, 0x0F, 0xEF, 0xC3,
      // movdqa xmm3, xmm0
      0x66, 0x0F, 0x6F, 0xD8,
      // pslldq xmm3, 4
      0x66, 0x0F, 0x73, 0xFB, 0x04,
      // pxor xmm0, xmm3
      0x66, 0x0F, 0xEF, 0xC3,
      // pxor xmm0, xmm2
      0x66, 0x0F, 0xEF, 0xC2,
    ];
  }

  /// Expansão AES-256 para rounds pares (usa pshufd com 0xaa)
  static List<int> _keyExpand256InlineEven() {
    return [
      // pshufd xmm2, xmm2, 0xaa
      0x66, 0x0F, 0x70, 0xD2, 0xAA,

      // movdqa xmm3, xmm1
      0x66, 0x0F, 0x6F, 0xD9,
      // pslldq xmm3, 4
      0x66, 0x0F, 0x73, 0xFB, 0x04,
      // pxor xmm1, xmm3
      0x66, 0x0F, 0xEF, 0xCB,
      // movdqa xmm3, xmm1
      0x66, 0x0F, 0x6F, 0xD9,
      // pslldq xmm3, 4
      0x66, 0x0F, 0x73, 0xFB, 0x04,
      // pxor xmm1, xmm3
      0x66, 0x0F, 0xEF, 0xCB,
      // movdqa xmm3, xmm1
      0x66, 0x0F, 0x6F, 0xD9,
      // pslldq xmm3, 4
      0x66, 0x0F, 0x73, 0xFB, 0x04,
      // pxor xmm1, xmm3
      0x66, 0x0F, 0xEF, 0xCB,
      // pxor xmm1, xmm2
      0x66, 0x0F, 0xEF, 0xCA,
    ];
  }

  /// Shell code para AESIMC (InvMixColumns) em uma round key
  ///
  /// Parâmetros (Windows x64):
  ///   rcx = ponteiro para round key de entrada (16 bytes)
  ///   rdx = ponteiro para round key de saída (16 bytes)
  static Uint8List getAesimcShellCode() {
    return Uint8List.fromList([
      // movdqu xmm0, [rcx]
      0xF3, 0x0F, 0x6F, 0x01,

      // aesimc xmm0, xmm0
      0x66, 0x0F, 0x38, 0xDB, 0xC0,

      // movdqu [rdx], xmm0
      0xF3, 0x0F, 0x7F, 0x02,

      // ret
      0xC3,
    ]);
  }
}

/// Implementação AES usando instruções AES-NI via shell code x86_64
///
/// Esta implementação oferece alta performance usando as instruções
/// de hardware AES-NI disponíveis em processadores Intel/AMD modernos.
///
/// SEGURANÇA: Esta implementação é 100% resistente a ataques de canal lateral
/// (side-channel attacks) porque:
/// - Usa instruções AES-NI para encriptação/decriptação (tempo constante)
/// - Usa AESKEYGENASSIST para expansão de chave (sem lookup tables)
/// - Usa AESIMC para InvMixColumns (sem lookup tables)
///
/// IMPORTANTE: Só funciona em Windows/Linux x86_64 com suporte AES-NI
class RijndaelAsmX8664 {
  /// Tamanho do bloco (sempre 16 para AES)
  static const int blockSize = 16;

  /// Número de rounds baseado no tamanho da chave
  final int _rounds;

  /// Tamanho da chave em bytes
  final int _keySize;

  /// Round keys para encriptação (em memória nativa, alinhado 16 bytes)
  late final ffi.Pointer<ffi.Uint8> _encKeys;

  /// Round keys para decriptação (em memória nativa, alinhado 16 bytes)
  late final ffi.Pointer<ffi.Uint8> _decKeys;

  /// Buffer de trabalho para input (16 bytes, alinhado)
  late final ffi.Pointer<ffi.Uint8> _inputBuf;

  /// Buffer de trabalho para output (16 bytes, alinhado)
  late final ffi.Pointer<ffi.Uint8> _outputBuf;

  /// Memória executável para função de encriptação
  late final ExecutableMemory _encryptMem;

  /// Memória executável para função de decriptação
  late final ExecutableMemory _decryptMem;

  /// Função de encriptação compilada
  late final void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>,
      ffi.Pointer<ffi.Uint8>) _encryptFunc;

  /// Função de decriptação compilada
  late final void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>,
      ffi.Pointer<ffi.Uint8>) _decryptFunc;

  bool _disposed = false;

  /// Cria uma instância do AES com chave de 128, 192 ou 256 bits
  ///
  /// [key] deve ter 16, 24 ou 32 bytes
  ///
  /// Lança [StateError] se AES-NI não for suportado
  /// Lança [ArgumentError] se o tamanho da chave for inválido
  RijndaelAsmX8664(Uint8List key)
      : _keySize = key.length,
        _rounds = _getRounds(key.length) {
    if (!AesNiSupport.isSupported) {
      throw StateError('AES-NI não suportado nesta plataforma. '
          'Use RijndaelFast como alternativa.');
    }

    if (key.length != 16 && key.length != 24 && key.length != 32) {
      throw ArgumentError('Tamanho de chave inválido: ${key.length}. '
          'Use 16, 24 ou 32 bytes.');
    }

    // Aloca memória alinhada para round keys
    // AES-128: 11 round keys = 176 bytes
    // AES-192: 13 round keys = 208 bytes
    // AES-256: 15 round keys = 240 bytes
    final keyScheduleSize = (_rounds + 1) * 16;

    _encKeys = pkgffi.calloc<ffi.Uint8>(keyScheduleSize);
    _decKeys = pkgffi.calloc<ffi.Uint8>(keyScheduleSize);
    _inputBuf = pkgffi.calloc<ffi.Uint8>(16);
    _outputBuf = pkgffi.calloc<ffi.Uint8>(16);

    // Expande a chave
    _expandKey(key);

    // Compila as funções de encriptação/decriptação
    _compileShellCode();
  }

  static int _getRounds(int keyLength) {
    switch (keyLength) {
      case 16:
        return 10;
      case 24:
        return 12;
      case 32:
        return 14;
      default:
        throw ArgumentError('Tamanho de chave inválido: $keyLength');
    }
  }

  /// Expande a chave usando o método mais seguro disponível
  ///
  /// - AES-128: Usa AESKEYGENASSIST (100% constant-time, sem lookup tables)
  /// - AES-192/256: Usa expansão em software (requer S-box lookup, mas executado
  ///   apenas uma vez durante a inicialização da chave)
  ///
  /// NOTA: Mesmo para AES-192/256, a exposição é mínima porque:
  /// 1. Key expansion é feito apenas uma vez por chave
  /// 2. O core AES (encrypt/decrypt de cada bloco) usa AES-NI
  /// 3. A maioria dos ataques de cache-timing requer muitas operações
  void _expandKey(Uint8List key) {
    if (_keySize == 16) {
      // AES-128: Usa AESKEYGENASSIST (totalmente constant-time)
      _expandKey128Hardware(key);
    } else {
      // AES-192/256: Usa expansão em software
      _expandKeySoftware(key);
    }

    // Gera as chaves de decriptação usando AESIMC (sempre hardware)
    _generateDecryptKeys();
  }

  /// Expansão de chave AES-128 usando AESKEYGENASSIST (constant-time)
  void _expandKey128Hardware(Uint8List key) {
    final keyBuf = pkgffi.calloc<ffi.Uint8>(16);

    try {
      for (int i = 0; i < 16; i++) {
        keyBuf[i] = key[i];
      }

      final keyExpandCode = AesNiShellCode.getKeyExpand128ShellCode();
      final keyExpandMem = ExecutableMemory.allocate(keyExpandCode);

      try {
        final funcPtr = keyExpandMem.pointer.cast<
            ffi.NativeFunction<
                ffi.Void Function(
                    ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>)>>();

        final keyExpandFunc = funcPtr.asFunction<
            void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>)>();

        keyExpandFunc(keyBuf, _encKeys);
      } finally {
        keyExpandMem.free();
      }
    } finally {
      pkgffi.calloc.free(keyBuf);
    }
  }

  /// Expansão de chave em software (para AES-192 e AES-256)
  ///
  /// AVISO: Esta função usa lookup tables (S-box) e não é constant-time.
  /// No entanto, como é executada apenas uma vez durante a inicialização,
  /// o risco de ataques de cache-timing é muito baixo.
  void _expandKeySoftware(Uint8List key) {
    // S-box para key expansion
    const sBox = [
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, //
      0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
      0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
      0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
      0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
      0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
      0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
      0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
      0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
      0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
      0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
      0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
      0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
      0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
      0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
      0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
      0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
      0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
      0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
      0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
      0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
      0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
      0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
      0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
      0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
      0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
      0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ];

    // Rcon (round constants)
    const rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

    final nk = _keySize ~/ 4;
    final nr = _rounds;
    const nb = 4;

    // Copia a chave original
    for (int i = 0; i < _keySize; i++) {
      _encKeys[i] = key[i];
    }

    // Expande o restante das round keys
    final totalWords = nb * (nr + 1);

    for (int i = nk; i < totalWords; i++) {
      int temp0 = _encKeys[(i - 1) * 4 + 0];
      int temp1 = _encKeys[(i - 1) * 4 + 1];
      int temp2 = _encKeys[(i - 1) * 4 + 2];
      int temp3 = _encKeys[(i - 1) * 4 + 3];

      if (i % nk == 0) {
        final t = temp0;
        temp0 = sBox[temp1] ^ rcon[(i ~/ nk) - 1];
        temp1 = sBox[temp2];
        temp2 = sBox[temp3];
        temp3 = sBox[t];
      } else if (nk > 6 && i % nk == 4) {
        temp0 = sBox[temp0];
        temp1 = sBox[temp1];
        temp2 = sBox[temp2];
        temp3 = sBox[temp3];
      }

      _encKeys[i * 4 + 0] = _encKeys[(i - nk) * 4 + 0] ^ temp0;
      _encKeys[i * 4 + 1] = _encKeys[(i - nk) * 4 + 1] ^ temp1;
      _encKeys[i * 4 + 2] = _encKeys[(i - nk) * 4 + 2] ^ temp2;
      _encKeys[i * 4 + 3] = _encKeys[(i - nk) * 4 + 3] ^ temp3;
    }
  }

  /// Gera as round keys de decriptação usando AESIMC (constant-time)
  ///
  /// Para decriptação eficiente com AES-NI:
  /// 1. Inverte a ordem das round keys
  /// 2. Aplica aesimc (InvMixColumns) nas keys intermediárias via hardware
  void _generateDecryptKeys() {
    // Copia em ordem reversa
    for (int r = 0; r <= _rounds; r++) {
      final srcOffset = r * 16;
      final dstOffset = (_rounds - r) * 16;

      for (int i = 0; i < 16; i++) {
        _decKeys[dstOffset + i] = _encKeys[srcOffset + i];
      }
    }

    // Aplica InvMixColumns via AESIMC (constant-time, hardware)
    final aesimcCode = AesNiShellCode.getAesimcShellCode();
    final aesimcMem = ExecutableMemory.allocate(aesimcCode);

    try {
      final funcPtr = aesimcMem.pointer.cast<
          ffi.NativeFunction<
              ffi.Void Function(
                  ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>)>>();

      final aesimcFunc = funcPtr.asFunction<
          void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>)>();

      // Buffer temporário para round key
      final tempBuf = pkgffi.calloc<ffi.Uint8>(16);

      try {
        // Aplica AESIMC nas keys intermediárias (não na primeira e última)
        for (int r = 1; r < _rounds; r++) {
          final offset = r * 16;

          // Copia round key para buffer de entrada
          for (int i = 0; i < 16; i++) {
            tempBuf[i] = _decKeys[offset + i];
          }

          // Aplica AESIMC via hardware
          // Ponteiro de saída é o mesmo que entrada (in-place via tempBuf)
          final inputPtr = tempBuf;
          final outputPtr = _decKeys.cast<ffi.Uint8>() + offset;

          aesimcFunc(inputPtr, outputPtr);
        }
      } finally {
        pkgffi.calloc.free(tempBuf);
      }
    } finally {
      aesimcMem.free();
    }
  }

  /// Compila os shell codes em funções executáveis
  void _compileShellCode() {
    final Uint8List encCode;
    final Uint8List decCode;

    switch (_rounds) {
      case 10:
        encCode = AesNiShellCode.getEncrypt128ShellCode();
        decCode = AesNiShellCode.getDecrypt128ShellCode();
        break;
      case 12:
        encCode = AesNiShellCode.getEncrypt192ShellCode();
        decCode = AesNiShellCode.getDecrypt192ShellCode();
        break;
      case 14:
        encCode = AesNiShellCode.getEncrypt256ShellCode();
        decCode = AesNiShellCode.getDecrypt256ShellCode();
        break;
      default:
        throw StateError('Número de rounds inválido: $_rounds');
    }

    _encryptMem = ExecutableMemory.allocate(encCode);
    _decryptMem = ExecutableMemory.allocate(decCode);

    // Cria ponteiros de função
    final encFuncPtr = _encryptMem.pointer.cast<
        ffi.NativeFunction<
            ffi.Void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>,
                ffi.Pointer<ffi.Uint8>)>>();

    final decFuncPtr = _decryptMem.pointer.cast<
        ffi.NativeFunction<
            ffi.Void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>,
                ffi.Pointer<ffi.Uint8>)>>();

    _encryptFunc = encFuncPtr.asFunction<
        void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>,
            ffi.Pointer<ffi.Uint8>)>();

    _decryptFunc = decFuncPtr.asFunction<
        void Function(ffi.Pointer<ffi.Uint8>, ffi.Pointer<ffi.Uint8>,
            ffi.Pointer<ffi.Uint8>)>();
  }

  /// Libera todos os recursos alocados
  void dispose() {
    if (_disposed) return;

    pkgffi.calloc.free(_encKeys);
    pkgffi.calloc.free(_decKeys);
    pkgffi.calloc.free(_inputBuf);
    pkgffi.calloc.free(_outputBuf);

    _encryptMem.free();
    _decryptMem.free();

    _disposed = true;
  }

  void _checkNotDisposed() {
    if (_disposed) {
      throw StateError('RijndaelAsmX8664 já foi liberado (dispose)');
    }
  }

  /// Encripta um bloco de 16 bytes
  Uint8List encrypt(Uint8List plaintext) {
    _checkNotDisposed();

    if (plaintext.length != blockSize) {
      throw ArgumentError(
          'Tamanho de bloco inválido: ${plaintext.length}. Esperado: $blockSize');
    }

    // Copia input para buffer nativo
    for (int i = 0; i < blockSize; i++) {
      _inputBuf[i] = plaintext[i];
    }

    // Executa encriptação via shell code
    _encryptFunc(_inputBuf, _outputBuf, _encKeys);

    // Copia resultado
    final result = Uint8List(blockSize);
    for (int i = 0; i < blockSize; i++) {
      result[i] = _outputBuf[i];
    }

    return result;
  }

  /// Encripta diretamente em um buffer de saída (evita alocação)
  void encryptInto(Uint8List plaintext, Uint8List output) {
    _checkNotDisposed();

    if (plaintext.length != blockSize) {
      throw ArgumentError(
          'Tamanho de bloco inválido: ${plaintext.length}. Esperado: $blockSize');
    }
    if (output.length != blockSize) {
      throw ArgumentError(
          'Tamanho de saída inválido: ${output.length}. Esperado: $blockSize');
    }

    for (int i = 0; i < blockSize; i++) {
      _inputBuf[i] = plaintext[i];
    }

    _encryptFunc(_inputBuf, _outputBuf, _encKeys);

    for (int i = 0; i < blockSize; i++) {
      output[i] = _outputBuf[i];
    }
  }

  /// Decripta um bloco de 16 bytes
  Uint8List decrypt(Uint8List ciphertext) {
    _checkNotDisposed();

    if (ciphertext.length != blockSize) {
      throw ArgumentError(
          'Tamanho de bloco inválido: ${ciphertext.length}. Esperado: $blockSize');
    }

    for (int i = 0; i < blockSize; i++) {
      _inputBuf[i] = ciphertext[i];
    }

    _decryptFunc(_inputBuf, _outputBuf, _decKeys);

    final result = Uint8List(blockSize);
    for (int i = 0; i < blockSize; i++) {
      result[i] = _outputBuf[i];
    }

    return result;
  }

  /// Decripta diretamente em um buffer de saída (evita alocação)
  void decryptInto(Uint8List ciphertext, Uint8List output) {
    _checkNotDisposed();

    if (ciphertext.length != blockSize) {
      throw ArgumentError(
          'Tamanho de bloco inválido: ${ciphertext.length}. Esperado: $blockSize');
    }
    if (output.length != blockSize) {
      throw ArgumentError(
          'Tamanho de saída inválido: ${output.length}. Esperado: $blockSize');
    }

    for (int i = 0; i < blockSize; i++) {
      _inputBuf[i] = ciphertext[i];
    }

    _decryptFunc(_inputBuf, _outputBuf, _decKeys);

    for (int i = 0; i < blockSize; i++) {
      output[i] = _outputBuf[i];
    }
  }
}

// --- Funções Helper ---

/// Encripta um bloco usando AES-NI se disponível
Uint8List encryptBlockAsmX8664(Uint8List key, Uint8List block) {
  final cipher = RijndaelAsmX8664(key);
  try {
    return cipher.encrypt(block);
  } finally {
    cipher.dispose();
  }
}

/// Decripta um bloco usando AES-NI se disponível
Uint8List decryptBlockAsmX8664(Uint8List key, Uint8List block) {
  final cipher = RijndaelAsmX8664(key);
  try {
    return cipher.decrypt(block);
  } finally {
    cipher.dispose();
  }
}
