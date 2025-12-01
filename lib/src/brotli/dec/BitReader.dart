import 'dart:typed_data';
import 'State.dart';
import 'Utils.dart';
import 'BrotliError.dart';

class BitReader {
  static const int BITNESS = 64;
  static const int BYTENESS = BITNESS ~/ 8;
  static const int CAPACITY = 4096;
  static const int SLACK = 64;
  static const int BUFFER_SIZE = CAPACITY + SLACK;
  static const int SAFEGUARD = 36;
  static const int WATERLINE = CAPACITY - SAFEGUARD;
  static const int HALF_BITNESS = BITNESS ~/ 2;
  static const int HALF_SIZE = BYTENESS ~/ 2;
  static const int HALVES_CAPACITY = CAPACITY ~/ HALF_SIZE;
  static const int HALF_BUFFER_SIZE = BUFFER_SIZE ~/ HALF_SIZE;
  static const int LOG_HALF_SIZE = 2;
  static const int HALF_WATERLINE = WATERLINE ~/ HALF_SIZE;

  static int readMoreInput(State s) {
    if (s.endOfStreamReached != 0) {
      if (halfAvailable(s) >= -2) {
        return BrotliError.BROTLI_OK;
      }
      return Utils.makeError(s, BrotliError.BROTLI_ERROR_TRUNCATED_INPUT);
    }
    final int readOffset = s.halfOffset << 2;
    int bytesInBuffer = CAPACITY - readOffset;
    Utils.copyBytesWithin(s.byteBuffer, 0, readOffset, CAPACITY);
    s.halfOffset = 0;
    while (bytesInBuffer < CAPACITY) {
      final int spaceLeft = CAPACITY - bytesInBuffer;
      final int len = Utils.readInput(s, s.byteBuffer, bytesInBuffer, spaceLeft);
      if (len < BrotliError.BROTLI_ERROR) {
        return len;
      }
      if (len <= 0) {
        s.endOfStreamReached = 1;
        s.tailBytes = bytesInBuffer;
        bytesInBuffer += HALF_SIZE - 1;
        break;
      }
      bytesInBuffer += len;
    }
    bytesToNibbles(s, bytesInBuffer);
    return BrotliError.BROTLI_OK;
  }

  static int checkHealth(State s, int endOfStream) {
    if (s.endOfStreamReached == 0) {
      return BrotliError.BROTLI_OK;
    }
    final int byteOffset = (s.halfOffset << 2) + ((s.bitOffset + 7) >> 3) - BYTENESS;
    if (byteOffset > s.tailBytes) {
      return Utils.makeError(s, BrotliError.BROTLI_ERROR_READ_AFTER_END);
    }
    if ((endOfStream != 0) && (byteOffset != s.tailBytes)) {
      return Utils.makeError(s, BrotliError.BROTLI_ERROR_UNUSED_BYTES_AFTER_END);
    }
    return BrotliError.BROTLI_OK;
  }

  static void assertAccumulatorHealthy(State s) {
    if (s.bitOffset > BITNESS) {
      throw StateError('Accumulator underloaded: ${s.bitOffset}');
    }
  }

  static void fillBitWindow(State s) {
    if (s.bitOffset >= HALF_BITNESS) {
      int nextVal = s.intBuffer[s.halfOffset++];
      s.accumulator64 = ((nextVal & 0xFFFFFFFF) << HALF_BITNESS) | (s.accumulator64 >>> HALF_BITNESS);
      s.bitOffset -= HALF_BITNESS;
    }
  }

  static void doFillBitWindow(State s) {
    fillBitWindow(s);
  }

  static int peekBits(State s) {
    return s.accumulator64 >>> s.bitOffset;
  }

  static int readFewBits(State s, int n) {
    final int v = peekBits(s) & ((1 << n) - 1);
    s.bitOffset += n;
    return v;
  }

  static int readBits(State s, int n) {
    if (HALF_BITNESS >= 24) {
      return readFewBits(s, n);
    } else {
      return (n <= 16) ? readFewBits(s, n) : readManyBits(s, n);
    }
  }

  static int readManyBits(State s, int n) {
    final int low = readFewBits(s, 16);
    doFillBitWindow(s);
    return low | (readFewBits(s, n - 16) << 16);
  }

  static int initBitReader(State s) {
    s.byteBuffer = Uint8List(BUFFER_SIZE);
    s.accumulator64 = 0;
    s.intBuffer = Int32List(HALF_BUFFER_SIZE);
    s.bitOffset = BITNESS;
    s.halfOffset = HALVES_CAPACITY;
    s.endOfStreamReached = 0;
    return prepare(s);
  }

  static int prepare(State s) {
    if (s.halfOffset > HALF_WATERLINE) {
      final int result = readMoreInput(s);
      if (result != BrotliError.BROTLI_OK) {
        return result;
      }
    }
    int health = checkHealth(s, 0);
    if (health != BrotliError.BROTLI_OK) {
      return health;
    }
    doFillBitWindow(s);
    doFillBitWindow(s);
    return BrotliError.BROTLI_OK;
  }

  static int reload(State s) {
    if (s.bitOffset == BITNESS) {
      return prepare(s);
    }
    return BrotliError.BROTLI_OK;
  }

  static int jumpToByteBoundary(State s) {
    final int padding = (BITNESS - s.bitOffset) & 7;
    if (padding != 0) {
      final int paddingBits = readFewBits(s, padding);
      if (paddingBits != 0) {
        return Utils.makeError(s, BrotliError.BROTLI_ERROR_CORRUPTED_PADDING_BITS);
      }
    }
    return BrotliError.BROTLI_OK;
  }

  static int halfAvailable(State s) {
    int limit = HALVES_CAPACITY;
    if (s.endOfStreamReached != 0) {
      limit = (s.tailBytes + (HALF_SIZE - 1)) >> 2;
    }
    return limit - s.halfOffset;
  }

  static int copyRawBytes(State s, Uint8List data, int offset, int length) {
    int pos = offset;
    int len = length;
    if ((s.bitOffset & 7) != 0) {
      return Utils.makeError(s, BrotliError.BROTLI_PANIC_UNALIGNED_COPY_BYTES);
    }

    while ((s.bitOffset != BITNESS) && (len != 0)) {
      data[pos++] = peekBits(s) & 0xFF;
      s.bitOffset += 8;
      len--;
    }
    if (len == 0) {
      return BrotliError.BROTLI_OK;
    }

    final int copyNibbles = Utils.min(halfAvailable(s), len >> 2);
    if (copyNibbles > 0) {
      final int readOffset = s.halfOffset << 2;
      final int delta = copyNibbles << 2;
      Utils.copyBytes(data, pos, s.byteBuffer, readOffset, readOffset + delta);
      pos += delta;
      len -= delta;
      s.halfOffset += copyNibbles;
    }
    if (len == 0) {
      return BrotliError.BROTLI_OK;
    }

    if (halfAvailable(s) > 0) {
      fillBitWindow(s);
      while (len != 0) {
        data[pos++] = peekBits(s) & 0xFF;
        s.bitOffset += 8;
        len--;
      }
      return checkHealth(s, 0);
    }

    while (len > 0) {
      final int chunkLen = Utils.readInput(s, data, pos, len);
      if (chunkLen < BrotliError.BROTLI_ERROR) {
        return chunkLen;
      }
      if (chunkLen <= 0) {
        return Utils.makeError(s, BrotliError.BROTLI_ERROR_TRUNCATED_INPUT);
      }
      pos += chunkLen;
      len -= chunkLen;
    }
    return BrotliError.BROTLI_OK;
  }

  static void bytesToNibbles(State s, int byteLen) {
    final Uint8List byteBuffer = s.byteBuffer;
    final int halfLen = byteLen >> 2;
    final Int32List intBuffer = s.intBuffer;
    for (int i = 0; i < halfLen; ++i) {
      intBuffer[i] = (byteBuffer[i * 4] & 0xFF) |
          ((byteBuffer[(i * 4) + 1] & 0xFF) << 8) |
          ((byteBuffer[(i * 4) + 2] & 0xFF) << 16) |
          ((byteBuffer[(i * 4) + 3] & 0xFF) << 24);
    }
  }
}
