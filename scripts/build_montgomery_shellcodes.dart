/// Script para compilar os arquivos C de Montgomery e gerar shellcodes Dart
/// 
/// Uso: dart run scripts/build_montgomery_shellcodes.dart
/// 
/// Requer: GCC (MinGW64) e objcopy instalados e no PATH

import 'dart:io';

const gccPath = r'c:\gcc\bin\gcc.exe';
const objcopyPath = r'c:\gcc\bin\objcopy.exe';

void main() async {
  final asmDir = Directory('asm');
  
  if (!asmDir.existsSync()) {
    print('Erro: Diretorio asm/ nao encontrado');
    exit(1);
  }
  
  print('=== Compilando shellcodes Montgomery ===\n');
  
  // Compila mont_modpow_4limbs.c (256-bit)
  await compileShellcode(
    sourceFile: 'asm/mont_modpow_4limbs.c',
    outputDart: 'lib/src/utils/montgomery_modpow_256_bit_shellcode.dart',
    constName: 'kMontgomeryModPow256BitShellcode',
    functionName: 'mont_modpow_256',
  );
  
  // Compila mont_modpow_generic.c (generico ate 1024-bit)
  await compileShellcode(
    sourceFile: 'asm/mont_modpow_generic.c',
    outputDart: 'lib/src/utils/montgomery_modpow_generic_shellcode.dart',
    constName: 'kMontgomeryModPowGenericShellcode',
    functionName: 'mont_modpow_generic',
  );
  
  print('\n=== Concluido! ===');
}

Future<void> compileShellcode({
  required String sourceFile,
  required String outputDart,
  required String constName,
  required String functionName,
}) async {
  final source = File(sourceFile);
  if (!source.existsSync()) {
    print('ERRO: $sourceFile nao encontrado');
    return;
  }
  
  final baseName = sourceFile.replaceAll('.c', '').replaceAll('asm/', '').replaceAll(r'asm\', '');
  final objFile = 'asm/$baseName.o';
  final binFile = 'asm/$baseName.bin';
  
  print('Compilando $sourceFile...');
  
  // 1. Compilar para objeto
  var result = await Process.run(gccPath, [
    '-O3',
    '-fno-stack-protector',
    '-fno-asynchronous-unwind-tables', 
    '-nostdlib',
    '-fPIC',
    '-c',
    sourceFile,
    '-o', objFile,
  ]);
  
  if (result.exitCode != 0) {
    print('ERRO ao compilar:');
    print(result.stderr);
    return;
  }
  print('  Objeto criado: $objFile');
  
  // 2. Extrair secao .text para binario
  result = await Process.run(objcopyPath, [
    '-O', 'binary',
    '-j', '.text',
    objFile,
    binFile,
  ]);
  
  if (result.exitCode != 0) {
    print('ERRO ao extrair shellcode:');
    print(result.stderr);
    return;
  }
  print('  Binario criado: $binFile');
  
  // 3. Ler bytes do binario
  final binBytes = File(binFile).readAsBytesSync();
  print('  Tamanho: ${binBytes.length} bytes');
  
  if (binBytes.isEmpty) {
    print('ERRO: Shellcode vazio!');
    return;
  }
  
  // 4. Verificar primeiros bytes
  final firstBytes = binBytes.take(16).map((b) => '0x' + b.toRadixString(16).padLeft(2, '0').toUpperCase()).join(', ');
  print('  Primeiros 16 bytes: $firstBytes');
  
  // 5. Gerar arquivo Dart
  final dartContent = generateDartFile(constName, functionName, binBytes);
  File(outputDart).writeAsStringSync(dartContent);
  print('  Dart gerado: $outputDart');
  
  // Limpar arquivos temporarios
  try {
    File(objFile).deleteSync();
    File(binFile).deleteSync();
  } catch (_) {}
  
  print('  OK!\n');
}

String generateDartFile(String constName, String functionName, List<int> bytes) {
  final sb = StringBuffer();
  
  sb.writeln('// dart format width=5000');
  sb.writeln('// AUTO-GENERATED - DO NOT EDIT');
  sb.writeln('// Shellcode compilado de $functionName');
  sb.writeln('// Tamanho: ${bytes.length} bytes');
  sb.writeln('// Gerado em: ${DateTime.now().toIso8601String()}');
  sb.writeln('');
  sb.writeln('/// Shellcode x86_64 para $functionName');
  sb.writeln('const List<int> $constName = [');
  
  // Escreve bytes em linhas de 16
  for (int i = 0; i < bytes.length; i += 16) {
    final end = (i + 16 > bytes.length) ? bytes.length : i + 16;
    final line = bytes.sublist(i, end);
    final hexBytes = line.map((b) => '0x' + b.toRadixString(16).padLeft(2, '0').toUpperCase()).join(', ');
    sb.writeln('  $hexBytes,');
  }
  
  sb.writeln('];');
  
  return sb.toString();
}

