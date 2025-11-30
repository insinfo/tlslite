import 'dart:typed_data';

/// Writes bits in little-endian order (least significant bit first) into an
/// in-memory buffer that can be materialized as a [Uint8List]. The writer keeps
/// track of partial bytes so callers may interleave bit-level writes with byte
/// alignment requests without copying intermediates.
class BitStreamWriter {
  BitStreamWriter();

  final List<int> _bytes = <int>[];
  int _bitContainer = 0;
  int _bitCount = 0;

  /// Total number of bits currently staged but not yet flushed to [_bytes].
  int get pendingBitCount => _bitCount;

  /// Reports whether the writer is currently aligned on an 8-bit boundary.
  bool get isByteAligned => (_bitCount & 7) == 0;

  /// Writes [bitCount] least significant bits from [value] into the stream.
  void writeBits(int value, int bitCount) {
    if (bitCount < 0) {
      throw ArgumentError.value(bitCount, 'bitCount', 'Cannot be negative');
    }
    if (bitCount == 0) {
      return;
    }
    var remaining = bitCount;
    var payload = value;
    while (remaining > 0) {
      final chunkWidth = remaining > 32 ? 32 : remaining;
      final mask = (chunkWidth == 32) ? 0xFFFFFFFF : ((1 << chunkWidth) - 1);
      final chunk = payload & mask;
      _bitContainer |= chunk << _bitCount;
      _bitCount += chunkWidth;
      payload = payload >> chunkWidth;
      _flushFullBytes();
      remaining -= chunkWidth;
    }
  }

  /// Writes a single bit reflecting [value].
  void writeBool(bool value) {
    writeBits(value ? 1 : 0, 1);
  }

  /// Pads with [padBit] (defaults to zero) until the stream reaches the next
  /// byte boundary.
  void alignToByte([int padBit = 0]) {
    final remainder = _bitCount & 7;
    if (remainder == 0) {
      return;
    }
    final fill = padBit & 1;
    final bitsNeeded = 8 - remainder;
    if (fill == 0) {
      // Fast path when padding with zeros.
      _bitCount += bitsNeeded;
    } else {
      final mask = (1 << bitsNeeded) - 1;
      _bitContainer |= mask << _bitCount;
      _bitCount += bitsNeeded;
    }
    _flushFullBytes();
  }

  /// Flushes any whole bytes accumulated so far into the output buffer.
  void flush() {
    _flushFullBytes();
  }

  /// Materializes the current buffer as a [Uint8List]. When
  /// [includePartialByte] is true (default) the remaining bits are emitted as a
  /// final byte padded with zeros.
  Uint8List takeBytes({bool includePartialByte = true}) {
    _flushFullBytes();
    if (includePartialByte && _bitCount > 0) {
      _bytes.add(_bitContainer & 0xFF);
      _bitContainer = 0;
      _bitCount = 0;
    }
    final bytes = Uint8List.fromList(_bytes);
    _bytes.clear();
    return bytes;
  }

  /// Finishes the stream by appending a mandatory terminator bit (value 1) used
  /// by the Zstd bitstreams and returns the resulting bytes.
  Uint8List closeWithTerminator() {
    writeBits(1, 1);
    final bytes = takeBytes();
    if (bytes.isEmpty || bytes.last == 0) {
      throw StateError('Bitstream terminator missing');
    }
    return bytes;
  }

  /// Clears the buffered data and resets the bit container.
  void reset() {
    _bytes.clear();
    _bitContainer = 0;
    _bitCount = 0;
  }

  void _flushFullBytes() {
    while (_bitCount >= 8) {
      _bytes.add(_bitContainer & 0xFF);
      _bitContainer >>= 8;
      _bitCount -= 8;
    }
  }
}
