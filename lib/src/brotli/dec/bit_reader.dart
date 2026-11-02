import 'dart:typed_data';
import 'state.dart';
import 'utils.dart';
import 'brotli_error.dart';

class BitReader {
  static const int bitness = 64;
  static const int byteness = bitness ~/ 8;
  static const int capacity = 4096;
  static const int slack = 64;
  static const int bufferSize = capacity + slack;
  static const int safeguard = 36;
  static const int waterline = capacity - safeguard;
  static const int halfBitness = bitness ~/ 2;
  static const int halfSize = byteness ~/ 2;
  static const int halvesCapacity = capacity ~/ halfSize;
  static const int halfBufferSize = bufferSize ~/ halfSize;
  static const int logHalfSize = 2;
  static const int halfWaterline = waterline ~/ halfSize;

  static int readMoreInput(State s) {
    if (s.endOfStreamReached != 0) {
      if (halfAvailable(s) >= -2) {
        return BrotliError.brotliOk;
      }
      return Utils.makeError(s, BrotliError.brotliErrorTruncatedInput);
    }
    final int readOffset = s.halfOffset << 2;
    int bytesInBuffer = capacity - readOffset;
    Utils.copyBytesWithin(s.byteBuffer, 0, readOffset, capacity);
    s.halfOffset = 0;
    while (bytesInBuffer < capacity) {
      final int spaceLeft = capacity - bytesInBuffer;
      final int len =
          Utils.readInput(s, s.byteBuffer, bytesInBuffer, spaceLeft);
      if (len < BrotliError.brotliError) {
        return len;
      }
      if (len <= 0) {
        s.endOfStreamReached = 1;
        s.tailBytes = bytesInBuffer;
        bytesInBuffer += halfSize - 1;
        break;
      }
      bytesInBuffer += len;
    }
    bytesToNibbles(s, bytesInBuffer);
    return BrotliError.brotliOk;
  }

  static int checkHealth(State s, int endOfStream) {
    if (s.endOfStreamReached == 0) {
      return BrotliError.brotliOk;
    }
    final int byteOffset =
        (s.halfOffset << 2) + ((s.bitOffset + 7) >> 3) - byteness;
    if (byteOffset > s.tailBytes) {
      return Utils.makeError(s, BrotliError.brotliErrorReadAfterEnd);
    }
    if ((endOfStream != 0) && (byteOffset != s.tailBytes)) {
      return Utils.makeError(s, BrotliError.brotliErrorUnusedBytesAfterEnd);
    }
    return BrotliError.brotliOk;
  }

  static void assertAccumulatorHealthy(State s) {
    if (s.bitOffset > bitness) {
      throw StateError('Accumulator underloaded: ${s.bitOffset}');
    }
  }

  static void fillBitWindow(State s) {
    if (s.bitOffset >= halfBitness) {
      int nextVal = s.intBuffer[s.halfOffset++];
      s.accumulator64 = ((nextVal & 0xFFFFFFFF) << halfBitness) |
          (s.accumulator64 >>> halfBitness);
      s.bitOffset -= halfBitness;
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
    if (halfBitness >= 24) {
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
    s.byteBuffer = Uint8List(bufferSize);
    s.accumulator64 = 0;
    s.intBuffer = Int32List(halfBufferSize);
    s.bitOffset = bitness;
    s.halfOffset = halvesCapacity;
    s.endOfStreamReached = 0;
    return prepare(s);
  }

  static int prepare(State s) {
    if (s.halfOffset > halfWaterline) {
      final int result = readMoreInput(s);
      if (result != BrotliError.brotliOk) {
        return result;
      }
    }
    int health = checkHealth(s, 0);
    if (health != BrotliError.brotliOk) {
      return health;
    }
    doFillBitWindow(s);
    doFillBitWindow(s);
    return BrotliError.brotliOk;
  }

  static int reload(State s) {
    if (s.bitOffset == bitness) {
      return prepare(s);
    }
    return BrotliError.brotliOk;
  }

  static int jumpToByteBoundary(State s) {
    final int padding = (bitness - s.bitOffset) & 7;
    if (padding != 0) {
      final int paddingBits = readFewBits(s, padding);
      if (paddingBits != 0) {
        return Utils.makeError(s, BrotliError.brotliErrorCorruptedPaddingBits);
      }
    }
    return BrotliError.brotliOk;
  }

  static int halfAvailable(State s) {
    int limit = halvesCapacity;
    if (s.endOfStreamReached != 0) {
      limit = (s.tailBytes + (halfSize - 1)) >> 2;
    }
    return limit - s.halfOffset;
  }

  static int copyRawBytes(State s, Uint8List data, int offset, int length) {
    int pos = offset;
    int len = length;
    if ((s.bitOffset & 7) != 0) {
      return Utils.makeError(s, BrotliError.brotliPanicUnalignedCopyBytes);
    }

    while ((s.bitOffset != bitness) && (len != 0)) {
      data[pos++] = peekBits(s) & 0xFF;
      s.bitOffset += 8;
      len--;
    }
    if (len == 0) {
      return BrotliError.brotliOk;
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
      return BrotliError.brotliOk;
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
      if (chunkLen < BrotliError.brotliError) {
        return chunkLen;
      }
      if (chunkLen <= 0) {
        return Utils.makeError(s, BrotliError.brotliErrorTruncatedInput);
      }
      pos += chunkLen;
      len -= chunkLen;
    }
    return BrotliError.brotliOk;
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
