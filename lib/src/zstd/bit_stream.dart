import 'dart:typed_data';

import 'frame_header.dart';

const int bitContainerSize = 8;
const int bitContainerBits = bitContainerSize * 8;
const int bitContainerMask = 0xFFFFFFFFFFFFFFFF;

class BitStreamInitializer {
  BitStreamInitializer(this.buffer, this.start, this.end);

  final Uint8List buffer;
  final int start;
  final int end;

  late int bits;
  late int current;
  late int bitsConsumed;

  void initialize() {
    if (end - start < 1) {
      throw ZstdFrameFormatException('Bitstream is empty');
    }
    final lastByte = buffer[end - 1];
    if (lastByte == 0) {
      throw ZstdFrameFormatException('Bitstream end mark not present');
    }

    bitsConsumed = bitContainerSize - highestBit(lastByte);

    final inputSize = end - start;
    if (inputSize >= bitContainerSize) {
      current = end - bitContainerSize;
      bits = readUint64LE(buffer, current);
    } else {
      current = start;
      bits = readTail(buffer, start, inputSize);
      bitsConsumed += (bitContainerSize - inputSize) * 8;
    }
  }
}

class BitStreamLoader {
  BitStreamLoader({
    required this.buffer,
    required this.start,
    required this.current,
    required this.bits,
    required this.bitsConsumed,
  });

  final Uint8List buffer;
  final int start;
  int current;
  int bits;
  int bitsConsumed;
  bool overflow = false;

  bool load() {
    if (bitsConsumed > bitContainerBits) {
      overflow = true;
      return true;
    } else if (current == start) {
      return true;
    }

    int bytes = bitsConsumed >> 3;
    if (current >= start + bitContainerSize) {
      if (bytes > 0) {
        current -= bytes;
        bits = readUint64LE(buffer, current);
      }
      bitsConsumed &= 0x7;
    } else if (current - bytes < start) {
      final consumedBytes = current - start;
      current = start;
      bitsConsumed -= consumedBytes * bitContainerSize;
      bits = readUint64LE(buffer, current);
      return true;
    } else {
      current -= bytes;
      bitsConsumed -= bytes * bitContainerSize;
      bits = readUint64LE(buffer, current);
    }

    return false;
  }
}

int peekBitsFast(int bitsConsumed, int bitContainer, int numberOfBits) {
  final shifted = ((bitContainer & bitContainerMask) << bitsConsumed) & bitContainerMask;
  final result = shifted >> (bitContainerBits - numberOfBits);
  return result & ((1 << numberOfBits) - 1);
}

int peekBits(int bitsConsumed, int bitContainer, int numberOfBits) {
  final shifted = ((bitContainer & bitContainerMask) << bitsConsumed) & bitContainerMask;
  final trimmed = (shifted >> 1) & bitContainerMask;
  final result = trimmed >> ((bitContainerBits - 1) - numberOfBits);
  return result & ((1 << numberOfBits) - 1);
}

bool isBitStreamFullyConsumed(int start, int current, int bitsConsumed) {
  return start == current && bitsConsumed == bitContainerBits;
}

int readUint64LE(Uint8List buffer, int offset) {
  int value = 0;
  for (int i = 0; i < bitContainerSize; i++) {
    value |= (buffer[offset + i] & 0xFF) << (8 * i);
  }
  return value & bitContainerMask;
}

int readTail(Uint8List buffer, int offset, int length) {
  if (length <= 0) {
    return 0;
  }
  int bits = buffer[offset] & 0xFF;
  if (length >= 2) {
    bits |= (buffer[offset + 1] & 0xFF) << 8;
  }
  if (length >= 3) {
    bits |= (buffer[offset + 2] & 0xFF) << 16;
  }
  if (length >= 4) {
    bits |= (buffer[offset + 3] & 0xFF) << 24;
  }
  if (length >= 5) {
    bits |= (buffer[offset + 4] & 0xFF) << 32;
  }
  if (length >= 6) {
    bits |= (buffer[offset + 5] & 0xFF) << 40;
  }
  if (length >= 7) {
    bits |= (buffer[offset + 6] & 0xFF) << 48;
  }
  return bits & bitContainerMask;
}

int highestBit(int value) {
  if (value <= 0) {
    return -1;
  }
  return value.bitLength - 1;
}

bool isPowerOfTwo(int value) => value > 0 && (value & (value - 1)) == 0;
