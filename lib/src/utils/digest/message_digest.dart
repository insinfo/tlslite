import 'dart:typed_data';

/// Incremental cryptographic hash function.
///
/// All implementations are pure Dart and VM-only (they rely on 64-bit native
/// integers).
abstract class MessageDigest {
  /// Lowercase algorithm name (e.g. `sha256`).
  String get algorithm;

  /// Output size in bytes.
  int get digestSize;

  /// Internal block size in bytes (used by HMAC).
  int get blockSize;

  /// Absorbs `data[start..end)`.
  void update(List<int> data, [int start = 0, int? end]);

  /// Returns the digest of everything absorbed so far, leaving the state
  /// untouched so more data can still be added ("peek").
  Uint8List digest() => clone().finish();

  /// Finalizes and returns the digest. The object is reset afterwards and can
  /// be reused for a new message. Cheaper than [digest] (no state copy).
  Uint8List finish();

  /// Resets to the initial state.
  void reset();

  /// Returns an independent copy of the current state.
  MessageDigest clone();
}

/// Shared buffering for Merkle-Damgard hashes (MD5, SHA-1, SHA-2).
abstract class MdDigest extends MessageDigest {
  MdDigest(int blockSize, this._lengthFieldSize)
      : _buffer = Uint8List(blockSize);

  final Uint8List _buffer;
  final int _lengthFieldSize;
  int _bufferLength = 0;

  /// Total number of bytes absorbed.
  int _byteCount = 0;

  @override
  int get blockSize => _buffer.length;

  /// Compresses one block starting at `block[offset]`.
  void processBlock(Uint8List block, int offset);

  /// Writes the message length field (in bits) at `buffer[offset]`, given the
  /// total number of absorbed bytes.
  void writeLength(Uint8List buffer, int offset, int byteCount);

  /// Writes the final state into [out].
  void writeOutput(Uint8List out);

  /// Restores the initial chaining values.
  void resetState();

  /// Copies buffer and counters into [other] (state words are copied by the
  /// subclass).
  void copyBufferTo(MdDigest other) {
    other._buffer.setRange(0, _bufferLength, _buffer);
    other._bufferLength = _bufferLength;
    other._byteCount = _byteCount;
  }

  @override
  void update(List<int> data, [int start = 0, int? end]) {
    end = RangeError.checkValidRange(start, end, data.length);
    var length = end - start;
    if (length == 0) return;
    final Uint8List bytes;
    if (data is Uint8List) {
      bytes = data;
    } else {
      bytes = Uint8List.fromList(data.sublist(start, end));
      start = 0;
    }
    _byteCount += length;
    final buffer = _buffer;
    final bs = buffer.length;
    if (_bufferLength > 0) {
      final take = bs - _bufferLength < length ? bs - _bufferLength : length;
      buffer.setRange(_bufferLength, _bufferLength + take, bytes, start);
      _bufferLength += take;
      start += take;
      length -= take;
      if (_bufferLength < bs) return;
      processBlock(buffer, 0);
      _bufferLength = 0;
    }
    while (length >= bs) {
      processBlock(bytes, start);
      start += bs;
      length -= bs;
    }
    if (length > 0) {
      buffer.setRange(0, length, bytes, start);
      _bufferLength = length;
    }
  }

  @override
  Uint8List finish() {
    final buffer = _buffer;
    final bs = buffer.length;
    var pos = _bufferLength;
    buffer[pos++] = 0x80;
    if (pos > bs - _lengthFieldSize) {
      buffer.fillRange(pos, bs, 0);
      processBlock(buffer, 0);
      pos = 0;
    }
    buffer.fillRange(pos, bs - _lengthFieldSize, 0);
    writeLength(buffer, bs - _lengthFieldSize, _byteCount);
    processBlock(buffer, 0);
    final out = Uint8List(digestSize);
    writeOutput(out);
    reset();
    return out;
  }

  @override
  void reset() {
    _bufferLength = 0;
    _byteCount = 0;
    resetState();
  }
}
