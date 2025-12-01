void main() {
  const value = 3964;
  const bits = 14;
  final buffer = StringBuffer();
  for (var i = 0; i < bits; i++) {
    buffer.write(((value >> i) & 1));
  }
  print(buffer.toString());
}
