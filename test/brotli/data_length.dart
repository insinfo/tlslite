import 'package:tlslite/src/utils/brotlidecpy/dec/DictionaryData.dart';

void main() {
  print('DATA0 length: ${DictionaryData.DATA0.length}');
  print('DATA1 length: ${DictionaryData.DATA1.length}');
  print('SKIP_FLIP length: ${DictionaryData.SKIP_FLIP.length}');
  print('Total DATA0+DATA1: ${DictionaryData.DATA0.length + DictionaryData.DATA1.length}');
  print('Expected dictionary size: 122784');
}
