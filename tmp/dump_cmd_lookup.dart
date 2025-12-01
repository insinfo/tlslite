import 'package:tlslite/src/utils/brotlidecpy/dec/Decode.dart';

void main() {
  const commandSymbol = 496;
  final index = commandSymbol << 2;
  final insertCopyBits = Decode.CMD_LOOKUP[index];
  final insertBits = insertCopyBits & 0xFF;
  final copyBits = (insertCopyBits >> 8) & 0xFF;
  final insertOffset = Decode.CMD_LOOKUP[index + 1];
  final copyOffset = Decode.CMD_LOOKUP[index + 2];
  final distContext = Decode.CMD_LOOKUP[index + 3];
  print('cmd=$commandSymbol insertBits=$insertBits copyBits=$copyBits');
  print('insertOffset=$insertOffset copyOffset=$copyOffset distCtx=$distContext');
}
