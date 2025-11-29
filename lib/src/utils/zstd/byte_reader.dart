import 'dart:typed_data';

class ZstdByteReader {
  ZstdByteReader(this.buffer) : length = buffer.length;

  final Uint8List buffer;
  final int length;
  int offset = 0;

  bool get isEOF => offset >= length;
  int get remaining => length - offset;

  int readUint8() {
    _ensureAvailable(1);
    return buffer[offset++];
  }

  int readUint16LE() {
    _ensureAvailable(2);
    final value = buffer[offset] | (buffer[offset + 1] << 8);
    offset += 2;
    return value;
  }

  int readUint24LE() {
    _ensureAvailable(3);
    final value = buffer[offset] |
        (buffer[offset + 1] << 8) |
        (buffer[offset + 2] << 16);
    offset += 3;
    return value;
  }

  int readUint32LE() {
    _ensureAvailable(4);
    final value = buffer[offset] |
        (buffer[offset + 1] << 8) |
        (buffer[offset + 2] << 16) |
        (buffer[offset + 3] << 24);
    offset += 4;
    return value & 0xFFFFFFFF;
  }

  int readUint64LE() {
    _ensureAvailable(8);
    int result = 0;
    for (int i = 0; i < 8; i++) {
      result |= buffer[offset + i] << (8 * i);
    }
    offset += 8;
    return result;
  }

  Uint8List readBytes(int length) {
    _ensureAvailable(length);
    final slice = buffer.sublist(offset, offset + length);
    offset += length;
    return Uint8List.fromList(slice);
  }

  void skip(int length) {
    _ensureAvailable(length);
    offset += length;
  }

  void _ensureAvailable(int size) {
    if (offset + size > length) {
      throw StateError('Unexpected end of buffer while reading Zstd stream');
    }
  }
}
