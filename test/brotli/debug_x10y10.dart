import 'dart:typed_data';
import 'package:tlslite/src/utils/brotlidecpy/decode.dart';
import 'package:tlslite/src/utils/brotlidecpy/prefix.dart';

void main() {
  // Test what distanceContext would be for various cmdCodes
  print('=== distanceContext calculation test ===');
  for (int cmdCode in [0, 64, 127, 128, 192, 255]) {
    int rangeIdx = cmdCode >> 6;
    int distanceContextOffset = -4;
    if (rangeIdx >= 2) {
      rangeIdx -= 2;
      distanceContextOffset = 0;
    }
    final copyLenCode = (((0x26244 >> (rangeIdx * 2)) & 0x3) << 3) | (cmdCode & 7);
    final copyLengthOffset = kCopyLengthPrefixCode[copyLenCode].offset;
    final distanceContext = distanceContextOffset + (copyLengthOffset < 5 ? copyLengthOffset : 5) - 2;
    print('cmdCode=$cmdCode rangeIdx=$rangeIdx copyLenCode=$copyLenCode copyLengthOffset=$copyLengthOffset distCtx=$distanceContext');
  }
  
  print('\n=== X10Y10 decompress test ===');
  // Test X10Y10
  final compressed = Uint8List.fromList([0x1B, 0x13, 0x00, 0x00, 0xA4, 0xB0, 0xB2, 0xEA, 0x81, 0x47, 0x02, 0x8A]);
  final expected = "XXXXXXXXXXYYYYYYYYYY";
  
  print('Expected: "$expected" (${expected.length} chars)');
  
  try {
    final result = brotliDecompressBuffer(compressed);
    final actual = String.fromCharCodes(result);
    print('Actual:   "$actual" (${result.length} chars)');
    print('Match: ${expected == actual}');
    
    if (expected != actual) {
      for (int i = 0; i < expected.length && i < actual.length; i++) {
        if (expected[i] != actual[i]) {
          print('First diff at $i: expected "${expected[i]}" got "${actual[i]}"');
          break;
        }
      }
    }
  } catch (e, st) {
    print('Error: $e');
    print(st);
  }
}
