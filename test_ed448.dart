import 'dart:typed_data';
import 'package:tlslite/src/crypto/shake256.dart' as shake;

void main() {
  // Test 1: Verify SHAKE256 test vector
  // Empty input, 64 bytes output should produce a known value
  final shakeResult = shake.shake256([], 64);
  print('SHAKE256("", 64) first 8 bytes: ${shakeResult.sublist(0, 8)}');
  // Known test vector: SHAKE256("") first bytes should be 
  // 46b9dd2b0ba88d13...
  // Let's see what we get
  
  // Test 2: Test with a simple known input
  final input = Uint8List.fromList([0x61, 0x62, 0x63]); // "abc"
  final result = shake.shake256(input, 64);
  print('SHAKE256("abc", 64) first 8 bytes: ${result.sublist(0, 8).map((b) => b.toRadixString(16).padLeft(2, '0')).join(' ')}');
  
  // Expected SHAKE256("abc") first bytes: 
  // 48 33 65 32 15 23 32 14 5a ab 14 31 e1 5e e7 fa...
  // Reference: https://emn178.github.io/online-tools/shake_256.html
}
