import 'dart:typed_data';
import 'dart:math' as math;
import 'State.dart';
import 'BrotliError.dart';
import 'BrotliRuntimeException.dart';

class Utils {
  static final Uint8List _byteZeroes = Uint8List(1024);
  static final Int32List _intZeroes = Int32List(1024);

  static void fillBytesWithZeroes(Uint8List dest, int start, int end) {
    int cursor = start;
    while (cursor < end) {
      int step = math.min(cursor + 1024, end) - cursor;
      dest.setRange(cursor, cursor + step, _byteZeroes);
      cursor += step;
    }
  }

  static void fillIntsWithZeroes(Int32List dest, int start, int end) {
    int cursor = start;
    while (cursor < end) {
      int step = math.min(cursor + 1024, end) - cursor;
      dest.setRange(cursor, cursor + step, _intZeroes);
      cursor += step;
    }
  }

  static void copyBytes(Uint8List dst, int target, Uint8List src, int start, int end) {
    dst.setRange(target, target + (end - start), src.sublist(start, end));
  }

  static void copyBytesWithin(Uint8List bytes, int target, int start, int end) {
    bytes.setRange(target, target + (end - start), bytes, start);
  }

  static int readInput(State s, Uint8List dst, int offset, int length) {
    try {
      return s.input.read(dst, offset, length);
    } catch (e) {
      return makeError(s, BrotliError.BROTLI_ERROR_READ_FAILED);
    }
  }

  static void closeInput(State s) {
    s.input.close();
  }

  /// Converts string to US-ASCII bytes (7-bit), matching Java's String.getBytes("US-ASCII")
  static Uint8List toUsAsciiBytes(String src) {
    // Java's getBytes("US-ASCII") masks each char to 7-bit (& 0x7F)
    final Uint8List result = Uint8List(src.length);
    for (int i = 0; i < src.length; i++) {
      result[i] = src.codeUnitAt(i) & 0x7F;
    }
    return result;
  }

  /// Converts string to int array, matching Java's String.charAt() behavior
  static Int32List toUtf8Runes(String src) {
    // Java's charAt returns the char value directly (16-bit)
    final Int32List result = Int32List(src.length);
    for (int i = 0; i < src.length; i++) {
      result[i] = src.codeUnitAt(i);
    }
    return result;
  }

  static int isDebugMode() {
    return 0;
  }

  static int getLogBintness() {
    return 6;
  }

  static int shr32(int x, int y) {
    return x >>> y;
  }

  static int shr64(int x, int y) {
    return x >>> y;
  }

  static int min(int a, int b) {
    return math.min(a, b);
  }

  static int makeError(State s, int code) {
    if (code >= BrotliError.BROTLI_OK) {
      return code;
    }
    if (s.runningState >= 0) {
      s.runningState = code;
    }
    if (code <= BrotliError.BROTLI_PANIC) {
      throw StateError("Brotli error code: $code");
    }
    throw BrotliRuntimeException("Error code: $code");
  }
}
