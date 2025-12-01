void main() {
  // From brotli-go/dictionary.go, the raw dictionary starts with:
  // [116, 105, 109, 101, 100, 111, 119, 110, 108, 105, 102, 101, 108, 101, 102, 116, ...]
  // = "timedownlifeleft..."
  
  var expected = [116, 105, 109, 101, 100, 111, 119, 110, 108, 105, 102, 101, 108, 101, 102, 116];
  print('Expected dictionary start (from Go): ${String.fromCharCodes(expected)}');
  print('Bytes: $expected');
  
  // DATA0 starts with "wjnfgltmojefofewab`h..."
  const DATA0 = 'wjnfgltmojefofewab`h`lgfgbwbpkltlmozpjwf';
  
  print('\nDATA0 start: ${DATA0.substring(0, 16)}');
  print('DATA0 bytes:');
  var data0Bytes = <int>[];
  for (int i = 0; i < 16; i++) {
    data0Bytes.add(DATA0.codeUnitAt(i));
  }
  print(data0Bytes);
  
  // XOR with 3 should give us the expected dictionary
  print('\nDATA0 bytes XOR 3:');
  var xored = <int>[];
  for (int i = 0; i < 16; i++) {
    xored.add(DATA0.codeUnitAt(i) ^ 3);
  }
  print(xored);
  print('As string: ${String.fromCharCodes(xored)}');
  
  // Check if they match
  print('\nMatch with expected: ${xored.toString() == expected.toString()}');
  
  // What XOR value would make DATA0 -> expected?
  print('\nRequired XOR values:');
  for (int i = 0; i < 16; i++) {
    var needed = DATA0.codeUnitAt(i) ^ expected[i];
    print('$i: ${DATA0[i]} (${DATA0.codeUnitAt(i)}) ^ $needed = ${expected[i]} (${String.fromCharCode(expected[i])})');
  }
}
