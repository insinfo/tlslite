import 'package:tlslite/src/utils/brotlidecpy/dec/DictionaryData.dart';
import 'package:tlslite/src/utils/brotlidecpy/dec/Utils.dart';

void main() {
  // Get SKIP_FLIP runes
  final skipFlipRunes = Utils.toUtf8Runes(DictionaryData.SKIP_FLIP);
  
  print('SKIP_FLIP string length: ' + DictionaryData.SKIP_FLIP.length.toString());
  print('SKIP_FLIP runes length: ' + skipFlipRunes.length.toString());
  print('Number of pairs: ' + (skipFlipRunes.length >> 1).toString());
  
  // Calculate total
  int totalSkip = 0;
  int totalFlip = 0;
  final n = skipFlipRunes.length >> 1;
  
  for (int i = 0; i < n; i++) {
    final skip = skipFlipRunes[2 * i] - 36;
    final flip = skipFlipRunes[2 * i + 1] - 36;
    totalSkip += skip;
    totalFlip += flip;
  }
  
  print('Total skip bytes: ' + totalSkip.toString());
  print('Total flip bytes: ' + totalFlip.toString());
  print('Total processed: ' + (totalSkip + totalFlip).toString());
  print('Expected: 122784');
  
  // Show first 10 skip values
  print('');
  print('First 10 skip values:');
  for (int i = 0; i < 10 && i < n; i++) {
    final skip = skipFlipRunes[2 * i] - 36;
    final flip = skipFlipRunes[2 * i + 1] - 36;
    print('  Pair ' + i.toString() + ': skip=' + skip.toString() + ', flip=' + flip.toString());
  }
  
  // Check if there are large values we might be missing
  print('');
  print('Looking for large skip values:');
  for (int i = 0; i < n; i++) {
    final skip = skipFlipRunes[2 * i] - 36;
    if (skip > 5000) {
      print('  Pair ' + i.toString() + ': skip=' + skip.toString());
    }
  }
}
