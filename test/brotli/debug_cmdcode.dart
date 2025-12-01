import 'dart:typed_data';
import 'package:tlslite/src/utils/brotlidecpy/prefix.dart';

void main() {
  // Analyze what happens for cmdCode values
  print('=== Copy Length Offset analysis ===');
  for (int copyLenCode = 0; copyLenCode < 8; copyLenCode++) {
    int offset = kCopyLengthPrefixCode[copyLenCode].offset;
    print('copyLenCode=$copyLenCode -> offset=$offset');
    
    // For cmdCode < 128, distanceContextOffset = -4
    int ctx = -4 + (offset < 5 ? offset : 5) - 2;
    print('  -> implicitDistanceContext with offset=-4: $ctx');
  }
  
  print('\n=== cmdCode analysis ===');
  for (int cmdCode in [0, 1, 2, 8, 16, 64, 127, 128, 129, 200]) {
    int rangeIdx = cmdCode >> 6;
    int distanceContextOffset = -4;
    if (rangeIdx >= 2) {
      rangeIdx -= 2;
      distanceContextOffset = 0;
    }
    int copyLenCode = (((0x26244 >> (rangeIdx * 2)) & 0x3) << 3) | (cmdCode & 7);
    int offset = kCopyLengthPrefixCode[copyLenCode].offset;
    int ctx = distanceContextOffset + (offset < 5 ? offset : 5) - 2;
    print('cmdCode=$cmdCode rangeIdx=${cmdCode>>6} copyLenCode=$copyLenCode offset=$offset ctx=$ctx implicit=${ctx < 0}');
  }
}
