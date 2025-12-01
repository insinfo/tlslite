void main() {
  final expected = 'ukko nooa, ukko nooa oli mies, kun han meni saunaan, pansen lansenansenansen'.codeUnits;
  print('expected[37]=${expected[37]} (${String.fromCharCode(expected[37])})');
  print('Position 30-40: "${String.fromCharCodes(expected.sublist(30,45))}"');
  print('Expected bytes 30-40: ${expected.sublist(30,45)}');
}
