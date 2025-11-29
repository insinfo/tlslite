import 'package:tlslite/src/adaptive_number/adaptive_number.dart';

void main() {
  final number = Number(42);
  print('type=${number.runtimeType} hash=${number.hashCode} value=${number.intValue}');
}
