/// Compiles the Montgomery C sources and generates Dart shellcode files.
/// 
/// Usage: dart run tool/build_montgomery_shellcodes.dart
/// 
/// Requires GCC (MinGW64) and objcopy installed and on the PATH.

import 'dart:io';

const gccPath = r'c:\gcc\bin\gcc.exe';
const objcopyPath = r'c:\gcc\bin\objcopy.exe';

void main() async {
  final asmDir = Directory('asm');
  
  if (!asmDir.existsSync()) {
    print('Error: asm/ directory not found');
    exit(1);
  }
  
  print('=== Building Montgomery shellcodes ===\n');
  
  // Build mont_modpow_4limbs.c (256-bit)
  await compileShellcode(
    sourceFile: 'asm/mont_modpow_4limbs.c',
    outputDart: 'lib/src/utils/montgomery_modpow_256_bit_shellcode.dart',
    constName: 'kMontgomeryModPow256BitShellcode',
    functionName: 'mont_modpow_256',
  );
  
  // Build mont_modpow_generic.c (generic, up to 1024-bit)
  await compileShellcode(
    sourceFile: 'asm/mont_modpow_generic.c',
    outputDart: 'lib/src/utils/montgomery_modpow_generic_shellcode.dart',
    constName: 'kMontgomeryModPowGenericShellcode',
    functionName: 'mont_modpow_generic',
  );
  
  print('\n=== Done! ===');
}

Future<void> compileShellcode({
  required String sourceFile,
  required String outputDart,
  required String constName,
  required String functionName,
}) async {
  final source = File(sourceFile);
  if (!source.existsSync()) {
    print('ERROR: $sourceFile not found');
    return;
  }
  
  final baseName = sourceFile.replaceAll('.c', '').replaceAll('asm/', '').replaceAll(r'asm\', '');
  final objFile = 'asm/$baseName.o';
  final binFile = 'asm/$baseName.bin';
  
  print('Compiling $sourceFile...');
  
  // 1. Compile to an object file
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
    print('ERROR while compiling:');
    print(result.stderr);
    return;
  }
  print('  Object file created: $objFile');
  
  // 2. Extract the .text section to a raw binary
  result = await Process.run(objcopyPath, [
    '-O', 'binary',
    '-j', '.text',
    objFile,
    binFile,
  ]);
  
  if (result.exitCode != 0) {
    print('ERROR while extracting shellcode:');
    print(result.stderr);
    return;
  }
  print('  Binary created: $binFile');
  
  // 3. Read the binary's bytes
  final binBytes = File(binFile).readAsBytesSync();
  print('  Size: ${binBytes.length} bytes');
  
  if (binBytes.isEmpty) {
    print('ERROR: empty shellcode!');
    return;
  }
  
  // 4. Show the first bytes
  final firstBytes = binBytes.take(16).map((b) => '0x' + b.toRadixString(16).padLeft(2, '0').toUpperCase()).join(', ');
  print('  First 16 bytes: $firstBytes');
  
  // 5. Generate the Dart file
  final dartContent = generateDartFile(constName, functionName, binBytes);
  File(outputDart).writeAsStringSync(dartContent);
  print('  Dart file generated: $outputDart');
  
  // Remove temporary files
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
  sb.writeln('// Shellcode compiled from $functionName');
  sb.writeln('// Size: ${bytes.length} bytes');
  sb.writeln('// Generated at: ${DateTime.now().toIso8601String()}');
  sb.writeln('');
  sb.writeln('/// x86_64 shellcode for $functionName.');
  sb.writeln('const List<int> $constName = [');
  
  // Write the bytes in rows of 16
  for (int i = 0; i < bytes.length; i += 16) {
    final end = (i + 16 > bytes.length) ? bytes.length : i + 16;
    final line = bytes.sublist(i, end);
    final hexBytes = line.map((b) => '0x' + b.toRadixString(16).padLeft(2, '0').toUpperCase()).join(', ');
    sb.writeln('  $hexBytes,');
  }
  
  sb.writeln('];');
  
  return sb.toString();
}

