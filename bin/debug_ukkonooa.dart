import 'dart:typed_data';
import 'package:tlslite/src/utils/brotlidecpy/decode.dart';

void main() {
  final compressed = Uint8List.fromList([
    0x1B, 0x76, 0x00, 0x00, 0x14, 0x4A, 0xAC, 0x9B, 0x7A, 0xBD, 0xE1, 0x97,
    0x9D, 0x7F, 0x8E, 0xC2, 0x82, 0x36, 0x0E, 0x9C, 0xE0, 0x90, 0x03, 0xF7,
    0x8B, 0x9E, 0x38, 0xE6, 0xB6, 0x00, 0xAB, 0xC3, 0xCA, 0xA0, 0xC2, 0xDA,
    0x66, 0x36, 0xDC, 0xCD, 0x80, 0x8D, 0x2E, 0x21, 0xD7, 0x6E, 0xE3, 0xEA,
    0x4C, 0xB8, 0xF0, 0xD2, 0xB8, 0xC7, 0xC2, 0x70, 0x4D, 0x3A, 0xF0, 0x69,
    0x7E, 0xA1, 0xB8, 0x45, 0x73, 0xAB, 0xC4, 0x57, 0x1E
  ]);
  final result = brotliDecompressBuffer(compressed);
  final expected = 'ukko nooa, ukko nooa oli kunnon mies, kun han meni saunaan, pisti laukun naulaan, ukko nooa, ukko nooa oli kunnon mies.';
  final actual = String.fromCharCodes(result);
  print('Expected: $expected');
  print('Actual  : $actual');
  print('Match: ${expected == actual}');
  print('Expected len: ${expected.length}, Actual len: ${actual.length}');
  
  // Find first difference
  for (int i = 0; i < expected.length && i < actual.length; i++) {
    if (expected[i] != actual[i]) {
      print('First diff at $i: expected "${expected[i]}" (${expected.codeUnitAt(i)}), got "${actual[i]}" (${actual.codeUnitAt(i)})');
      int start = i > 10 ? i - 10 : 0;
      int end = i + 10 < expected.length ? i + 10 : expected.length;
      print('Context expected: "${expected.substring(start, end)}"');
      print('Context actual  : "${actual.substring(start, end < actual.length ? end : actual.length)}"');
      break;
    }
  }
}
