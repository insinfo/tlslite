import 'dart:typed_data';
import 'package:tlslite/src/utils/brotlidecpy/dictionary.dart';

void main() {
  final dict = BrotliDictionary.dictionary;
  print('Dictionary length: ${dict.length}');
  
  // Verificar o endereço 44059
  int addr = 44059;
  if (addr + 9 <= dict.length) {
    String word = String.fromCharCodes(dict.sublist(addr, addr + 9));
    print('Address $addr: "$word"');
  }
  
  // Verificar o cálculo para length=9, wordId=3
  int pos = BrotliDictionary.findPos(9, 3);
  print('findPos(9, 3) = $pos');
  
  // Ver offsets e sizeBits
  print('offsetsByLength[9] = ${BrotliDictionary.offsetsByLength[9]}');
  print('sizeBitsByLength[9] = ${BrotliDictionary.sizeBitsByLength[9]}');
  
  // Calcular manualmente
  int bits = BrotliDictionary.sizeBitsByLength[9];
  int offset = BrotliDictionary.offsetsByLength[9];
  int mask = (1 << bits) - 1;
  int index = 3 & mask;
  print('bits=$bits offset=$offset mask=$mask index=$index');
  print('calculated pos = ${offset + (index * 9)}');
  
  // Ver as primeiras palavras de tamanho 9
  for (int i = 0; i < 10; i++) {
    int p = BrotliDictionary.findPos(9, i);
    if (p >= 0 && p + 9 <= dict.length) {
      String w = String.fromCharCodes(dict.sublist(p, p + 9));
      print('wordId=$i: pos=$p word="$w"');
    }
  }
}
