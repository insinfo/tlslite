
import 'dart:typed_data';
import 'dart:math' as math;
import 'state.dart';
import 'decode.dart';
import 'utils.dart';
import 'brotli_error.dart';
import 'brotli_runtime_exception.dart';

class BrotliInputStream implements InputStream {
  static const int defaultInternalBufferSize = 256;
  static const int endOfStreamMarker = -1;

  Uint8List buffer;
  int remainingBufferBytes;
  int bufferOffset;
  final State state = State();

  BrotliInputStream(InputStream source, [int byteReadBufferSize = defaultInternalBufferSize])
      : buffer = Uint8List(byteReadBufferSize),
        remainingBufferBytes = 0,
        bufferOffset = 0 {
    if (byteReadBufferSize <= 0) {
      throw ArgumentError("Bad buffer size: $byteReadBufferSize");
    }
    state.input = source;
    int result = Decode.initState(state);
    if (result != BrotliError.brotliOk) {
        throw BrotliRuntimeException("Brotli decoder initialization failed");
    }
  }

  void attachDictionaryChunk(Uint8List data) {
    Decode.attachDictionaryChunk(state, data);
  }

  void enableEagerOutput() {
    Decode.enableEagerOutput(state);
  }

  void enableLargeWindow() {
    Decode.enableLargeWindow(state);
  }

  @override
  void close() {
    Decode.close(state);
    Utils.closeInput(state);
  }

  int readByte() {
    if (bufferOffset >= remainingBufferBytes) {
      remainingBufferBytes = read(buffer, 0, buffer.length);
      bufferOffset = 0;
      if (remainingBufferBytes == endOfStreamMarker) {
        return -1;
      }
    }
    return buffer[bufferOffset++] & 0xFF;
  }

  @override
  int read(Uint8List destBuffer, int destOffset, int destLen) {
    if (destOffset < 0) {
      throw ArgumentError("Bad offset: $destOffset");
    } else if (destLen < 0) {
      throw ArgumentError("Bad length: $destLen");
    } else if (destOffset + destLen > destBuffer.length) {
      throw ArgumentError(
          "Buffer overflow: ${destOffset + destLen} > ${destBuffer.length}");
    } else if (destLen == 0) {
      return 0;
    }
    int copyLen = math.max(remainingBufferBytes - bufferOffset, 0);
    if (copyLen != 0) {
      copyLen = math.min(copyLen, destLen);
      Utils.copyBytes(destBuffer, destOffset, buffer, bufferOffset, bufferOffset + copyLen);
      bufferOffset += copyLen;
      destOffset += copyLen;
      destLen -= copyLen;
      if (destLen == 0) {
        return copyLen;
      }
    }
    try {
      state.output = destBuffer;
      state.outputOffset = destOffset;
      state.outputLength = destLen;
      state.outputUsed = 0;
      int result = Decode.decompress(state);
      if (result != BrotliError.brotliOk && result != BrotliError.brotliOkDone && result != BrotliError.brotliOkNeedMoreOutput) {
          throw BrotliRuntimeException("Brotli stream decoding failed");
      }
      copyLen += state.outputUsed;
      copyLen = (copyLen > 0) ? copyLen : endOfStreamMarker;
      return copyLen;
    } catch (e) {
      throw BrotliRuntimeException("Brotli stream decoding failed: $e");
    }
  }
}
