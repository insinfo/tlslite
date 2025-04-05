//bit_reader.dart
import 'dart:typed_data';

/// Wraps a Uint8List buffer to enable reading 0 < n <= 24 bits at a time,
/// or transfer of arbitrary number of bytes.
class BrotliBitReader {
  /// Bitmasks for 0 to 24 bits.
  static const List<int> kBitMask = [
    // Preserve formatting
    0x000000, 0x000001, 0x000003, 0x000007, 0x00000f, 0x00001f, 0x00003f,
    0x00007f, 0x0000ff, 0x0001ff, 0x0003ff, 0x0007ff, 0x000fff, 0x001fff,
    0x003fff, 0x007fff, 0x00ffff, 0x01ffff, 0x03ffff, 0x07ffff, 0x0fffff,
    0x1fffff, 0x3fffff, 0x7fffff, 0xffffff
  ];

  /// The input data buffer.
  /// Note: This implementation keeps a reference to the original list.
  /// If the original list is modified externally, it will affect the reader.
  /// The Python version created a mutable copy (`bytearray`). If that exact
  /// behavior is needed, pass `Uint8List.fromList(originalList)` to the constructor.
  final Uint8List buf_;

  /// Length of the buffer.
  final int buf_len_;

  /// Current byte position in the buffer.
  int pos_;

  /// Current bit position within the current byte (0-7).
  /// Represents the number of bits already read from the byte at `pos_`.
  int bit_pos_;

  /// Creates a BitReader wrapping the [input_buffer].
  BrotliBitReader(Uint8List input_buffer)
      // Initialize fields using an initializer list
      : buf_ = input_buffer, // Stores the reference
        buf_len_ = input_buffer.length,
        pos_ = 0,
        bit_pos_ = 0;

  /// Resets the reader to the start of the input buffer.
  void reset() {
    pos_ = 0;
    bit_pos_ = 0;
  }

  /// Reads [n_bits] unsigned integer from the input buffer, treating it as a
  /// little-endian byte stream. Optionally advances the read position.
  ///
  /// - [n_bits]: Number of bits to read (1-24). If 0 or null, returns 0.
  /// - [bits_to_skip]: Number of bits to advance the read position after reading.
  ///   If null, defaults to [n_bits]. Pass 0 to peek at the bits
  ///   without advancing the position.
  ///
  /// Returns the next [n_bits] from the buffer as a little-endian integer,
  /// or 0 if [n_bits] is 0 or null.
  /// Throws [RangeError] if [n_bits] is negative or greater than 24.
  int read_bits(int n_bits, {int? bits_to_skip}) {
    // Input validation
    if (n_bits < 0 || n_bits > 24) {
      throw RangeError.range(
          n_bits, 0, 24, 'n_bits', 'Must be between 0 and 24');
    }

    // If bits_to_skip is not provided, default it to n_bits
    bits_to_skip ??= n_bits;

    if (n_bits == 0) {
      // If we only need to skip bits (n_bits is 0, but bits_to_skip > 0)
      if (bits_to_skip > 0) {
        int next_total_bits = bit_pos_ + bits_to_skip;
        bit_pos_ = next_total_bits & 7; // Update bit position (modulo 8)
        pos_ += next_total_bits >>
            3; // Update byte position (integer division by 8)
      }
      return 0; // Return 0 if n_bits is 0
    }

    // --- Reading logic ---
    int val = 0;
    int bytes_shift = 0;
    int buf_pos = pos_;
    // Calculate the total number of bits required from the start of the current byte.
    int bit_pos_when_done = n_bits + bit_pos_;

    // Read enough bytes to cover all the required bits.
    // We keep reading bytes as long as the number of bits provided by
    // the read bytes (bytes_shift) is less than the total bits needed.
    while (bytes_shift < bit_pos_when_done) {
      if (buf_pos >= buf_len_) {
        // Reached end of buffer. Further reads act as if reading zeros,
        // which is the correct behavior for padding.
        break;
      }
      // Read the byte at buf_pos and shift it left by bytes_shift bits,
      // then OR it into val. This accumulates bytes in little-endian order.
      val |= (buf_[buf_pos] << bytes_shift);
      bytes_shift += 8; // Move to the position for the next byte
      buf_pos++; // Advance to the next byte in the buffer
    }

    // Now 'val' contains the necessary bytes shifted into place.
    // 1. Shift right by `bit_pos_` to discard bits already consumed
    //    from the first byte involved.
    // 2. Apply the mask `kBitMask[n_bits]` to isolate exactly `n_bits`.
    val = (val >> bit_pos_) & kBitMask[n_bits];

    // --- Skipping logic ---
    if (bits_to_skip > 0) {
      // Calculate the new absolute bit position after skipping.
      int next_total_bits = bit_pos_ + bits_to_skip;
      // Update the bit position within the new byte (result of modulo 8).
      bit_pos_ = next_total_bits & 7;
      // Update the byte position (result of integer division by 8).
      pos_ += next_total_bits >> 3;
    }

    return val;
  }

  /// Copies [n_bytes] from the input buffer to [dest_buffer] starting at [dest_pos].
  ///
  /// This operation first aligns the reader to the next byte boundary if it's
  /// not already aligned (i.e., if `bit_pos_ != 0`).
  ///
  /// Call with `n_bytes == 0` to simply align the reader to the next byte boundary.
  ///
  /// - [dest_buffer]: The destination buffer to copy bytes into.
  /// - [dest_pos]: The starting position in the [dest_buffer].
  /// - [n_bytes]: The number of bytes to copy.
  ///
  /// Throws [ArgumentError] if the requested copy operation would read past
  /// the end of the source buffer or write past the end of the destination buffer.
  void copy_bytes(List<int> dest_buffer, int dest_pos, int n_bytes) { // Changed to List<int>
    // Align to the next byte boundary if the reader is currently mid-byte.
    if (bit_pos_ != 0) {
      bit_pos_ = 0;
      pos_++; // Move to the start of the next byte.
    }

    // If n_bytes is 0, the only effect is the alignment above.
    if (n_bytes > 0) {
      int source_end = pos_ + n_bytes;
      int dest_end = dest_pos + n_bytes;

      // --- Bounds Checking ---
      if (pos_ < 0 || source_end > buf_len_) {
        throw ArgumentError(
            'Source range ($pos_ to $source_end) is out of bounds for buffer length $buf_len_.');
      }
      // Check destination bounds carefully, List<int> might have been resized.
      if (dest_pos < 0 || dest_pos > dest_buffer.length || dest_end > dest_buffer.length) {
         // Allow writing exactly at the end if length matches needed size.
          if(dest_pos == dest_buffer.length && n_bytes == 0) {
             // Okay, writing 0 bytes at the end.
          } else if (dest_pos > dest_buffer.length || dest_end > dest_buffer.length) {
              throw ArgumentError(
                  'Destination range ($dest_pos to $dest_end) is out of bounds for buffer length ${dest_buffer.length}.');
          }
      }


      // --- Perform the copy ---
      // Cannot use setRange directly between Uint8List (buf_) and List<int> (dest_buffer).
      // Copy byte by byte.
      for (int i = 0; i < n_bytes; ++i) {
          // Direct assignment works because Uint8List elements are int.
          dest_buffer[dest_pos + i] = buf_[pos_ + i];
      }

      // Update the position in the source buffer.
      pos_ = source_end;
    }
  }

  // Keep other methods like copyBytesTo if needed, or remove if copy_bytes is the only one used.
   void copyBytesTo(List<int> dest_buffer, int dest_pos, int n_bytes) {
      copy_bytes(dest_buffer, dest_pos, n_bytes);
   }

   // Ensure jumpToByteBoundary also exists or uses the modified copy_bytes
   void jumpToByteBoundary() {
      copy_bytes([], 0, 0); // Align using the modified method
   }

    // Ensure dropBytes exists or uses the modified copy_bytes
   void dropBytes(int n_bytes) {
      // Align first
      if (bit_pos_ != 0) {
         bit_pos_ = 0;
         pos_++;
      }
      if (n_bytes > 0) {
         int next_pos = pos_ + n_bytes;
         // Don't read past end, just update position up to buffer length
         pos_ = (next_pos > buf_len_) ? buf_len_ : next_pos;
      }
   }
}
