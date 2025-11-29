import 'dart:typed_data';

import 'frame_header.dart';

/// Sliding window that stores the most recent decompressed bytes so that
/// sequence matches can reference prior output even after it wraps.
class ZstdWindow {
  ZstdWindow(int windowSize)
      : _capacity = windowSize > 0 ? windowSize : 0,
        _buffer = Uint8List(windowSize > 0 ? windowSize : 0);

  final int _capacity;
  final Uint8List _buffer;
  int _size = 0;
  int _writeIndex = 0;
  int _totalProduced = 0;

  int get availableHistory => _size;
  int get totalProduced => _totalProduced;

  void appendBytes(Uint8List data, List<int> output) {
    appendSlice(data, 0, data.length, output);
  }

  void appendSlice(Uint8List data, int start, int length, List<int> output) {
    if (length == 0) {
      return;
    }
    if (start < 0 || length < 0 || start + length > data.length) {
      throw RangeError.range(start + length, 0, data.length,
          'length', 'Invalid literal slice for window append');
    }
    for (int i = 0; i < length; i++) {
      final value = data[start + i];
      output.add(value);
      _storeByte(value);
    }
  }

  void repeatByte(int value, int count, List<int> output) {
    if (count <= 0) {
      return;
    }
    final byte = value & 0xFF;
    for (int i = 0; i < count; i++) {
      output.add(byte);
      _storeByte(byte);
    }
  }

  void copyMatch(int offset, int length, List<int> output) {
    if (length <= 0) {
      return;
    }
    if (offset <= 0 || offset > _size) {
      throw ZstdFrameFormatException(
        'Match offset $offset exceeds available history $_size',
      );
    }
    if (_capacity == 0) {
      throw ZstdFrameFormatException(
        'Match requested with zero-sized window',
      );
    }
    var readIndex = _startIndexForOffset(offset);
    for (int i = 0; i < length; i++) {
      final value = _buffer[readIndex];
      output.add(value);
      _storeByte(value);
      readIndex++;
      if (readIndex == _capacity) {
        readIndex = 0;
      }
    }
  }

  void _storeByte(int value) {
    _totalProduced++;
    if (_capacity == 0) {
      return;
    }
    _buffer[_writeIndex] = value & 0xFF;
    _writeIndex++;
    if (_writeIndex == _capacity) {
      _writeIndex = 0;
    }
    if (_size < _capacity) {
      _size++;
    }
  }

  int _startIndexForOffset(int offset) {
    var index = _writeIndex - offset;
    if (index < 0) {
      index += _capacity;
    }
    return index;
  }
}
