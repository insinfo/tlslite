//codec.dart
import 'dart:typed_data';

// --- Custom Exception Classes ---

/// Exception raised in case of decoding errors during parsing.
/// Similar to Python's DecodeError.
class DecodeError implements Exception {
  final String message;
  DecodeError(this.message);

  @override
  String toString() => 'DecodeError: $message';
}

/// Exception raised in case of bad certificate data during parsing.
/// Similar to Python's BadCertificateError.
class BadCertificateError implements Exception {
  final String message;
  BadCertificateError(this.message);

  @override
  String toString() => 'BadCertificateError: $message';
}

// --- Writer Class (Equivalent to Python's Writer) ---

/// Serialisation helper for complex byte-based structures.
/// Builds a Uint8List incrementally using big-endian format for multi-byte integers.
class Writer {
  final BytesBuilder _builder;

  /// Initialise the serializer with an empty buffer.
  Writer() : _builder = BytesBuilder();

  /// Returns the accumulated bytes as a Uint8List.
  /// Note: This consumes the internal buffer in BytesBuilder in some implementations,
  /// but toBytes() here returns a copy without clearing the builder.
  Uint8List get bytes => _builder.toBytes();

  /// Returns the current length of the accumulated bytes.
  int get length => _builder.length;

  /// Adds a single byte (0-255) to the buffer.
  /// Equivalent to Python's addOne.
  void addOne(int value) {
    if (value < 0 || value > 0xFF) {
      throw ArgumentError("Value $value out of range for uint8 (0-255)");
    }
    _builder.addByte(value);
  }

  /// Adds a two-byte unsigned integer (0-65535) in big-endian format.
  /// Equivalent to Python's addTwo.
  void addTwo(int value) {
    if (value < 0 || value > 0xFFFF) {
      throw ArgumentError("Value $value out of range for uint16 (0-65535)");
    }
    var byteData = ByteData(2);
    byteData.setUint16(0, value, Endian.big);
    _builder.add(byteData.buffer.asUint8List());
  }

  /// Adds a three-byte unsigned integer (0-16777215) in big-endian format.
  /// Equivalent to Python's addThree.
  void addThree(int value) {
    if (value < 0 || value > 0xFFFFFF) {
      throw ArgumentError("Value $value out of range for uint24 (0-16777215)");
    }
    // Write as 3 separate bytes in big-endian order
    _builder.addByte((value >> 16) & 0xFF);
    _builder.addByte((value >> 8) & 0xFF);
    _builder.addByte(value & 0xFF);
  }

  /// Adds a four-byte unsigned integer (0-4294967295) in big-endian format.
  /// Equivalent to Python's addFour.
  void addFour(int value) {
    if (value < 0 || value > 0xFFFFFFFF) {
      throw ArgumentError(
          "Value $value out of range for uint32 (0-4294967295)");
    }
    var byteData = ByteData(4);
    byteData.setUint32(0, value, Endian.big);
    _builder.add(byteData.buffer.asUint8List());
  }

  /// Adds a single non-negative integer value `x`, encoded in `length` bytes
  /// in big-endian format.
  ///
  /// Throws [ArgumentError] if the value is negative, out of range for the
  /// given length, or if the length is not supported (currently 1, 2, 3, 4).
  void add(int x, int length) {
    if (x < 0) {
      throw ArgumentError("Value must be non-negative");
    }
    switch (length) {
      case 1:
        addOne(x); // Use addOne for consistency with Python naming if preferred
        break;
      case 2:
        addTwo(x); // Use addTwo
        break;
      case 3:
        addThree(x); // Use addThree
        break;
      case 4:
        addFour(x); // Use addFour
        break;
      // Add cases for 5, 6, 7, 8 (Uint64) if needed, using ByteData or manual shifts
      default:
        // Manual implementation for other lengths if necessary, or throw error
        // Dart's int can go up to 64 bits.
        if (length <= 0 || length > 8) {
          throw ArgumentError(
              "Unsupported length for add: $length (must be 1-8)");
        }
        // Check if value fits in length bytes (unsigned)
        // Note: 1 << (length * 8) might overflow Dart's 64-bit int if length is 8 or more.
        // Use BigInt for reliable large comparisons if supporting > 7 bytes.
        // For lengths up to 7:
        if (length < 8 && x >= (1 << (length * 8))) {
          throw ArgumentError(
              "Value $x cannot be represented unsigned in $length bytes");
        }
        // For length 8 (uint64): Check against max uint64
        // Dart int is signed 64-bit, so direct comparison works for positive values up to 2^63-1
        // For values >= 2^63, they appear negative in Dart's int. We need to handle this carefully
        // if we are strictly encoding unsigned 64-bit values that might use the highest bit.
        // Assuming positive integers within the signed 64-bit range for simplicity here.
        // If true unsigned 64-bit support is needed, consider using BigInt internally or careful bitwise ops.

        // Manual big-endian encoding for lengths 5-8
        final bytes = Uint8List(length);
        var tempVal = x;
        for (int i = length - 1; i >= 0; i--) {
          bytes[i] = tempVal & 0xFF;
          tempVal >>= 8;
        }
        // Final check if any bits remained after shifting (means value was too large)
        if (tempVal != 0) {
          throw ArgumentError(
              "Value $x cannot be represented unsigned in $length bytes (overflow check)");
        }
        _builder.add(bytes);
    }
  }

  /// Adds a list of integers, encoding every item in `length` bytes (big-endian).
  ///
  /// - `seq`: Iterable of non-negative integers to encode.
  /// - `length`: Number of bytes to use for encoding each element.
  void addFixSeq(Iterable<int> seq, int length) {
    for (final e in seq) {
      add(e, length);
    }
  }

  /// Adds a length-prefixed list of same-sized integer values (big-endian).
  ///
  /// Encodes the total *byte length* of the sequence data first (using
  /// `lengthLength` bytes), followed by the sequence elements themselves,
  /// each encoded using `length` bytes.
  ///
  /// - `seq`: List of non-negative integers to encode.
  /// - `length`: Amount of bytes in which to encode every item.
  /// - `lengthLength`: Amount of bytes in which to encode the overall
  ///   *byte length* of the array data.
  void addVarSeq(List<int> seq, int length, int lengthLength) {
    final dataLength = seq.length * length;
    add(dataLength, lengthLength); // Add the total byte length prefix

    // Optimisation: if length is 1, add all bytes directly if they are valid bytes
    if (length == 1) {
      // Check range before adding
      for (final val in seq) {
        if (val < 0 || val > 0xFF) {
          throw ArgumentError("Value $val out of range for uint8 in sequence");
        }
      }
      _builder.add(Uint8List.fromList(seq)); // Now safe to convert
    } else {
      // Otherwise, add each element individually using the specified length
      addFixSeq(seq, length);
    }
  }

  /// Adds a variable length list of same-sized element tuples (represented as Lists).
  /// Note that all inner lists (tuples) must have the same size.
  ///
  /// Encodes the total *byte length* of the sequence data first (using
  /// `lengthLength` bytes), followed by the sequence elements themselves.
  /// Elements within tuples are encoded in big-endian.
  ///
  /// - `seq`: List of Lists of non-negative integers to encode.
  /// - `length`: Length in bytes of a single element within a tuple/list.
  /// - `lengthLength`: Length in bytes of the overall *byte length* field prefix.
  void addVarTupleSeq(List<List<int>> seq, int length, int lengthLength) {
    if (seq.isEmpty) {
      add(0, lengthLength);
      return;
    }

    final tupleSize = seq.first.length;
    // Validate that all tuples have the same size
    for (final elemTuple in seq) {
      if (elemTuple.length != tupleSize) {
        throw ArgumentError("Tuples of different lengths found in sequence");
      }
    }

    final dataLength = seq.length * tupleSize * length;
    add(dataLength, lengthLength); // Add total byte length prefix

    // Add the actual tuple data
    for (final elemTuple in seq) {
      addFixSeq(elemTuple, length); // Add each element of the tuple
    }
  }

  /// Adds a variable length array of bytes, prefixed by its length.
  /// Equivalent to Python's `add_var_bytes`.
  ///
  /// - `data`: The bytes to add.
  /// - `lengthLength`: Size in bytes of the field used to represent the length
  ///   of the `data`.
  void addVarBytes(Uint8List data, int lengthLength) {
    add(data.length, lengthLength); // Add length prefix
    _builder.add(data); // Add the data itself
  }

  /// Adds an arbitrary list of bytes to the buffer.
  void addBytes(List<int> bytes) {
    _builder.add(bytes);
  }
}

// --- Parser Class (Equivalent to Python's Parser) ---

/// Parser for TLV and LV byte-based encodings.
/// Reads data sequentially from a Uint8List using big-endian format for multi-byte integers.
class Parser {
  final Uint8List _bytes;
  final ByteData _byteData; // View for efficient multi-byte reads
  int _index;

  // For length checking
  int _checkIndex = 0;
  int _checkLength = 0;

  /// Bind raw bytes with parser.
  ///
  /// - `bytes`: The Uint8List containing the data to be parsed.
  Parser(Uint8List bytes)
      : _bytes = bytes,
        // Ensure the view covers the relevant part of the buffer
        _byteData = ByteData.view(
            bytes.buffer, bytes.offsetInBytes, bytes.lengthInBytes),
        _index = 0;

  /// Current position (index) in the buffer.
  int get index => _index;

  /// Total length of the buffer being parsed.
  int get length => _bytes.length;

  /// Check if the parser has consumed all bytes in the buffer.
  bool get isDone => _index >= _bytes.length;

  /// Ensures there are at least `count` bytes remaining to be read from the current index.
  /// Throws [DecodeError] if not enough bytes are available.
  void _ensureRemaining(int count) {
    if (_index + count > _bytes.length) {
      throw DecodeError(
          "Read past end of buffer: need $count bytes, only ${getRemainingLength()} available at index $_index");
    }
  }

  /// Reads a single byte (uint8).
  int getUint8() {
    _ensureRemaining(1);
    final value = _byteData.getUint8(_index);
    _index++;
    return value;
  }

  /// Reads a two-byte unsigned integer in big-endian format (uint16).
  int getUint16() {
    _ensureRemaining(2);
    final value = _byteData.getUint16(_index, Endian.big);
    _index += 2;
    return value;
  }

  /// Reads a three-byte unsigned integer in big-endian format (uint24).
  int getUint24() {
    _ensureRemaining(3);
    // Read 3 bytes manually in big-endian order
    final b1 = _byteData.getUint8(_index);
    final b2 = _byteData.getUint8(_index + 1);
    final b3 = _byteData.getUint8(_index + 2);
    _index += 3;
    return (b1 << 16) | (b2 << 8) | b3;
  }

  /// Reads a four-byte unsigned integer in big-endian format (uint32).
  int getUint32() {
    _ensureRemaining(4);
    final value = _byteData.getUint32(_index, Endian.big);
    _index += 4;
    return value;
  }

  /// Reads a single big-endian integer value encoded in `length` bytes.
  /// Supports lengths 1, 2, 3, 4, and up to 8 via manual reconstruction.
  ///
  /// - `length`: Number of bytes in which the value is encoded.
  int get(int length) {
    if (length <= 0) {
      throw ArgumentError("Length must be positive for get()");
    }
    switch (length) {
      case 1:
        return getUint8();
      case 2:
        return getUint16();
      case 3:
        return getUint24();
      case 4:
        return getUint32();
      // Add cases for 5, 6, 7, 8 (getUint64) if needed, using manual reconstruction
      default:
        _ensureRemaining(length);
        if (length > 8) {
          // Dart int is 64-bit max
          throw ArgumentError("Unsupported length for get: $length (max 8)");
        }
        // Manual big-endian reconstruction for lengths 5-8
        int value = 0;
        for (int i = 0; i < length; i++) {
          value = (value << 8) | _byteData.getUint8(_index + i);
        }
        _index += length;
        return value;
    }
  }

  /// Reads a fixed number of bytes from the current position.
  /// Returns a *copy* of the bytes.
  /// Equivalent to Python's `getFixBytes`.
  ///
  /// - `lengthBytes`: Number of bytes to return.
  Uint8List getFixBytes(int lengthBytes) {
    if (lengthBytes < 0) throw ArgumentError("lengthBytes cannot be negative");
    _ensureRemaining(lengthBytes);
    // Create a copy using sublist
    final result = _bytes.sublist(_index, _index + lengthBytes);
    _index += lengthBytes;
    return result;
  }

  /// Moves the internal pointer ahead `length` bytes without reading data.
  /// Equivalent to Python's `skip_bytes`.
  void skipBytes(int length) {
    if (length < 0) throw ArgumentError("Length to skip cannot be negative");
    _ensureRemaining(length); // Checks if skipping is possible
    _index += length;
  }

  /// Reads a variable length byte array, where the length is prefixed.
  /// Inverse of `Writer.addVarBytes()`.
  ///
  /// - `lengthLength`: Number of bytes used to encode the length prefix.
  Uint8List getVarBytes(int lengthLength) {
    final lengthBytes = get(lengthLength); // Read the length prefix
    if (lengthBytes < 0) {
      throw DecodeError(
          "Invalid negative length received for var bytes: $lengthBytes");
    }
    return getFixBytes(lengthBytes); // Read the actual bytes
  }

  /// Reads a list of static length (`lengthList`) containing same-sized integers (big-endian).
  ///
  /// - `length`: Size in bytes of a single element in the list.
  /// - `lengthList`: The fixed number of elements in the list.
  List<int> getFixList(int length, int lengthList) {
    if (lengthList < 0) throw ArgumentError("lengthList cannot be negative");
    // Calculate total bytes needed beforehand for a single check
    _ensureRemaining(length * lengthList);
    final list = List<int>.filled(lengthList, 0);
    for (int x = 0; x < lengthList; x++) {
      // We already ensured enough bytes, so internal gets won't throw range error here
      list[x] = get(length);
    }
    return list;
  }

  /// Reads a variable length list of same-sized integers (big-endian). The total *byte length*
  /// of the list data is prefixed.
  ///
  /// - `length`: Size in bytes of a single element.
  /// - `lengthLength`: Size in bytes of the encoded total byte length prefix.
  List<int> getVarList(int length, int lengthLength) {
    final totalBytes = get(lengthLength); // Read the total byte length prefix
    if (totalBytes < 0) {
      throw DecodeError(
          "Invalid negative total length received for var list: $totalBytes");
    }
    if (length <= 0) throw ArgumentError("Element length must be positive");
    if (totalBytes == 0) return []; // Handle empty list case
    if (totalBytes % length != 0) {
      throw DecodeError(
          "Encoded total length ($totalBytes) not a multiple of element length ($length)");
    }
    final numElements = totalBytes ~/ length;
    // Now call getFixList which will do the final _ensureRemaining check
    return getFixList(length, numElements);
  }

  /// Reads a variable length list of same-sized tuples (represented as Lists, big-endian elements).
  /// The total *byte length* of the list data is prefixed.
  ///
  /// - `elemLength`: Length in bytes of a single tuple element.
  /// - `elemNum`: Number of elements in each tuple.
  /// - `lengthLength`: Length in bytes of the total byte length prefix.
  List<List<int>> getVarTupleList(
      int elemLength, int elemNum, int lengthLength) {
    final totalBytes = get(lengthLength); // Read the total byte length prefix
    if (totalBytes < 0) {
      throw DecodeError(
          "Invalid negative total length received for var tuple list: $totalBytes");
    }
    if (elemLength <= 0 || elemNum <= 0) {
      throw ArgumentError("Element length and number must be positive");
    }
    if (totalBytes == 0) return []; // Handle empty list case

    final tupleByteLength = elemLength * elemNum;
    if (tupleByteLength == 0 && totalBytes > 0) {
      throw DecodeError(
          "Zero tuple byte length but non-zero total bytes ($totalBytes)");
    }
    if (tupleByteLength > 0 && totalBytes % tupleByteLength != 0) {
      throw DecodeError(
          "Encoded total length ($totalBytes) not a multiple of tuple byte length ($tupleByteLength)");
    }

    final tupleCount =
        (tupleByteLength == 0) ? 0 : totalBytes ~/ tupleByteLength;

    // Pre-calculate required bytes and check once
    _ensureRemaining(
        totalBytes - lengthLength); // We already read lengthLength bytes

    final tupleList = <List<int>>[];
    for (int i = 0; i < tupleCount; i++) {
      final currentTuple = List<int>.filled(elemNum, 0);
      for (int j = 0; j < elemNum; j++) {
        // Internal gets are safe due to pre-check
        currentTuple[j] = get(elemLength);
      }
      tupleList.add(currentTuple);
    }
    return tupleList;
  }

  /// --- Length Checking Methods ---

  /// Reads the length of a structure from the buffer and starts a length check.
  /// Records the expected length and the current index.
  ///
  /// - `lengthLength`: Number of bytes in which the structure's length is encoded.
  void startLengthCheck(int lengthLength) {
    _checkLength = get(lengthLength);
    if (_checkLength < 0) {
      throw DecodeError(
          "Invalid negative structure length received: $_checkLength");
    }
    _checkIndex = _index;
    // Ensure the declared length doesn't exceed remaining buffer size from *start* of check
    if (_checkIndex + _checkLength > _bytes.length) {
      throw DecodeError(
          "Declared structure length ($_checkLength from index $_checkIndex) exceeds buffer end (${_bytes.length})");
    }
  }

  /// Sets the expected length of a structure and starts a length check from the current position.
  /// Use when the length is known externally.
  ///
  /// - `length`: Expected size of the structure in bytes from the current index.
  void setLengthCheck(int length) {
    if (length < 0) {
      throw ArgumentError("Length check cannot be negative");
    }
    _checkLength = length;
    _checkIndex = _index;
    // Ensure the declared length doesn't exceed remaining buffer size
    if (_checkIndex + _checkLength > _bytes.length) {
      throw DecodeError(
          "Set structure length ($_checkLength from index $_checkIndex) exceeds buffer end (${_bytes.length})");
    }
  }

  /// Stops the current structure parsing length check. Verifies that the
  /// number of bytes read since the check started *exactly* matches the
  /// expected length.
  ///
  /// Throws [DecodeError] if the consumed length doesn't match the expected length.
  void stopLengthCheck() {
    final consumed = _index - _checkIndex;
    if (consumed != _checkLength) {
      throw DecodeError(
          "Length check failed: expected to consume $_checkLength bytes starting from index $_checkIndex, but consumed $consumed bytes (ended at index $_index)");
    }
    // Reset check values (optional, but good practice)
    // _checkIndex = 0;
    // _checkLength = 0;
  }

  /// Checks if the parser has consumed *exactly* the expected number of bytes
  /// for the current length check. Useful for loops that consume the structure.
  ///
  /// Returns `true` if the end of the checked structure is reached (`consumed == expected`).
  /// Returns `false` if there are still bytes remaining within the structure (`consumed < expected`).
  /// Throws [DecodeError] if more bytes than expected have been consumed (`consumed > expected`).
  bool atLengthCheck() {
    final consumed = _index - _checkIndex;
    if (consumed < _checkLength) {
      return false; // Still within the structure
    } else if (consumed == _checkLength) {
      return true; // Exactly at the end
    } else {
      // consumed > _checkLength
      throw DecodeError(
          "Length check overflow: expected $_checkLength bytes from index $_checkIndex, but already consumed $consumed bytes (at index $_index)");
    }
  }

  /// Returns the number of bytes remaining *within the current length check structure*.
  /// Calculates `expected_end - current_index`.
  /// Throws [DecodeError] if the current index has already moved beyond the expected end.
  int get remainingCheckLength {
    final consumed = _index - _checkIndex;
    if (consumed > _checkLength) {
      throw DecodeError(
          "Index ($_index) has moved beyond the expected end (${_checkIndex + _checkLength}) of the checked structure.");
    }
    return _checkLength - consumed;
  }

  /// Returns the total number of bytes remaining in the *entire* buffer
  /// from the current index position.
  /// Equivalent to Python's `getRemainingLength()`.
  int getRemainingLength() {
    // Ensure index is not out of bounds (should be caught by _ensureRemaining earlier, but safe check)
    if (_index > _bytes.length) {
      return 0;
    }
    return _bytes.length - _index;
  }
}
