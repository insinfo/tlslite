import '../../lib/src/utils/brotlidecpy/dictionary.dart';
import '../../lib/src/utils/brotlidecpy/dictionary_data.dart';

void main() {
  // Initialize dictionary
  DictionaryData.init();
  
  // Get dictionary data
  final dictData = Dictionary.getData();
  
  print('Dictionary initialized!');
  print('Dictionary size: ' + dictData.length.toString());
  
  // Check first 100 bytes
  print('');
  print('First 100 bytes:');
  final first100 = dictData.sublist(0, 100);
  print(first100.toList());
  
  // Convert to string
  print('');
  print('First 50 bytes as string: ' + String.fromCharCodes(first100.sublist(0, 50)));
  
  // Expected: "timedownlifeleft..."
  final expected = <int>[116, 105, 109, 101, 100, 111, 119, 110, 108, 105, 102, 101, 108, 101, 102, 116];
  print('');
  print('Expected first 16: ' + expected.toString());
  print('Got first 16:      ' + first100.sublist(0, 16).toList().toString());
  
  var match = true;
  for (var i = 0; i < expected.length; i++) {
    if (first100[i] != expected[i]) {
      match = false;
      break;
    }
  }
  print('');
  print('Match: ' + match.toString());
}
