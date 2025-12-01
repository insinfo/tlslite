void main(List<String> args) {
  final value = int.parse(args[0]);
  final bits = int.parse(args[1]);
  var reversed = 0;
  for (var i = 0; i < bits; i++) {
    reversed <<= 1;
    reversed |= (value >> i) & 1;
  }
  print('value=$value bits=$bits reversed=$reversed');
}
