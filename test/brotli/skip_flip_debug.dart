import 'dart:typed_data';

const SKIP_FLIP = "\u06F7%\u018C'T%e%1%c';%\u0D04\u0B3B\u000F%'%C%\u0092))%S%%3%)%\u00A5%Q%\u0139%\u008D-%%\u00BB%O%%\u0099%\u009B%A%K%%\u009B%3%%)%\u00B7%\u00EF\u0B48%U%%\u0093\u066E;%w%Y%S%\u011F%\u00B3%\u0099%\u00F3%\u00A9%\u012B%\u00BF%\u0135%\u007F%\u00A5%\u00E7%\u00A3%\u00A9%\u00A3%\u00DD%\u00CF%\u00C1%";

void main() {
  print('SKIP_FLIP analysis:');
  print('Length: ${SKIP_FLIP.length}');
  
  // First few pairs
  print('\nFirst 10 pairs (skip, flip):');
  for (int i = 0; i < 20 && i < SKIP_FLIP.length; i += 2) {
    final skip = SKIP_FLIP.codeUnitAt(i) - 36;
    final flip = i + 1 < SKIP_FLIP.length ? SKIP_FLIP.codeUnitAt(i + 1) - 36 : 0;
    print('Pair ${i ~/ 2}: skip=$skip, flip=$flip');
  }
  
  // Calculate total bytes processed
  int totalSkip = 0;
  int totalFlip = 0;
  int totalBytes = 0;
  final n = SKIP_FLIP.length >> 1;
  for (int i = 0; i < n; i++) {
    final skip = SKIP_FLIP.codeUnitAt(2 * i) - 36;
    final flip = SKIP_FLIP.codeUnitAt(2 * i + 1) - 36;
    totalSkip += skip;
    totalFlip += flip;
    totalBytes += skip + flip;
  }
  
  print('\n--- Summary ---');
  print('Number of pairs: $n');
  print('Total skip bytes: $totalSkip');
  print('Total flip bytes: $totalFlip');
  print('Total bytes processed: $totalBytes');
  print('Expected dictionary size: 122784');
  
  // Simulate the algorithm
  const DATA0_PREFIX = 'wjnfgltmojefofewab`h`lgfgbwbpkltlmozpjwf';
  
  print('\n--- Simulating XOR algorithm ---');
  final dict = Uint8List.fromList(DATA0_PREFIX.codeUnits.map((c) => c & 0x7F).toList());
  
  print('Initial dict (first 16 bytes after masking): ${dict.sublist(0, 16)}');
  print('As string: ${String.fromCharCodes(dict.sublist(0, 16))}');
  
  // Apply the first few skip/flip pairs
  int offset = 0;
  for (int i = 0; i < 3 && i < n; i++) {
    final skip = SKIP_FLIP.codeUnitAt(2 * i) - 36;
    final flip = SKIP_FLIP.codeUnitAt(2 * i + 1) - 36;
    print('\nPair $i: skip=$skip, flip=$flip, offset before=$offset');
    
    for (int j = 0; j < skip && offset < dict.length; j++) {
      dict[offset] = dict[offset] ^ 3;
      offset++;
    }
    print('After skip XOR 3: offset=$offset, dict[0:16]=${dict.sublist(0, 16).map((b) => b).toList()}');
    
    for (int j = 0; j < flip && offset < dict.length; j++) {
      dict[offset] = dict[offset] ^ 236;
      offset++;
    }
    print('After flip XOR 236: offset=$offset');
  }
  
  print('\n--- Final result (first 16 bytes) ---');
  print('Bytes: ${dict.sublist(0, 16)}');
  print('As string: ${String.fromCharCodes(dict.sublist(0, 16))}');
  
  // Expected from Go
  print('\nExpected (from Go dictionary): [116, 105, 109, 101, 100, 111, 119, 110, 108, 105, 102, 101, 108, 101, 102, 116]');
  print('Expected as string: timedownlifeleft');
}
