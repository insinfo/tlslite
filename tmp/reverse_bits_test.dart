void main() {
  const value = 1982;
  const bits = 14;
  int reversed = 0;
  for (var i = 0; i < bits; i++) {
    final bit = (value >> (bits - 1 - i)) & 1; // msb-first bit order
    reversed |= bit << i; // lsb-first reader would see this order
  }
  print('value=$value reversed=$reversed');
}
