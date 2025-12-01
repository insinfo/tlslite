import 'dart:typed_data';

import 'package:tlslite/src/utils/brotlidecpy/brotli_encoder.dart';
import 'package:tlslite/src/utils/brotlidecpy/dec/BrotliError.dart';
import 'package:tlslite/src/utils/brotlidecpy/dec/Decode.dart';
import 'package:tlslite/src/utils/brotlidecpy/dec/State.dart';
import 'package:tlslite/src/utils/brotlidecpy/dec/Utils.dart';

void main() {
  final payload = Uint8List.fromList(List<int>.generate(64, (i) => (i * 7) & 0xFF));
  final encoded = brotliCompressLiteral(payload);
  final state = State()
    ..input = ByteArrayInputStream(encoded)
    ..output = Uint8List(1 << 16)
    ..outputOffset = 0
    ..outputLength = 1 << 16
    ..outputUsed = 0;

  var result = Decode.initState(state);
  if (result != BrotliError.BROTLI_OK) {
    throw StateError('initState failed: $result');
  }
  result = Decode.enableLargeWindow(state);
  if (result != BrotliError.BROTLI_OK) {
    throw StateError('enableLargeWindow failed: $result');
  }

  while (true) {
    int status;
    try {
      status = Decode.decompress(state);
    } catch (error, stackTrace) {
      print('caught $error meta=${state.metaBlockLength} insert=${state.insertLength} copy=${state.copyLength} running=${state.runningState}');
      print(stackTrace);
      rethrow;
    }
    print('status=$status state.running=${state.runningState} meta=${state.metaBlockLength} insert=${state.insertLength} copy=${state.copyLength} pos=${state.pos}');
    if (status == BrotliError.BROTLI_OK_DONE) {
      break;
    }
    if (status == BrotliError.BROTLI_OK_NEED_MORE_OUTPUT) {
      state.outputUsed = 0;
      continue;
    }
    if (status < 0) {
      break;
    }
  }

  Decode.close(state);
  Utils.closeInput(state);
}
