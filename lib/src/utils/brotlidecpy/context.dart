//context.dart
import 'dart:typed_data';

/// Lookup table to map the previous two bytes to a context id.
///
/// There are four different context modeling modes defined here:
///   CONTEXT_LSB6: context id is the least significant 6 bits of the last byte,
///   CONTEXT_MSB6: context id is the most significant 6 bits of the last byte,
///   CONTEXT_UTF8: second-order context model tuned for UTF8-encoded text,
///   CONTEXT_SIGNED: second-order context model tuned for signed integers.
///
/// The context id for the UTF8 context model is calculated as follows. If p1
/// and p2 are the previous two bytes, we calculate the context as
///
///   context = Context.lookup[p1] | Context.lookup[p2 + 256].
///
/// If the previous two bytes are ASCII characters (i.e. < 128), this will be
/// equivalent to
///
///   context = 4 * context1(p1) + context2(p2),
///
/// where context1 is based on the previous byte in the following way:
///
///   0  : non-ASCII control
///   1  : \t, \n, \r
///   2  : space
///   3  : other punctuation
///   4  : " '
///   5  : %
///   6  : ( < [ {
///   7  : ) > ] }
///   8  : , ; :
///   9  : .
///   10 : =
///   11 : number
///   12 : upper-case vowel
///   13 : upper-case consonant
///   14 : lower-case vowel
///   15 : lower-case consonant
///
/// and context2 is based on the second last byte:
///
///   0 : control, space
///   1 : punctuation
///   2 : upper-case letter, number
///   3 : lower-case letter
///
/// If the last byte is ASCII, and the second last byte is not (in a valid UTF8
/// stream it will be a continuation byte, value between 128 and 191), the
/// context is the same as if the second last byte was an ASCII control or
/// space.
///
/// If the last byte is a UTF8 lead byte (value >= 192), then the next byte will
/// be a continuation byte and the context id is 2 or 3 depending on the LSB of
/// the last byte and to a lesser extent on the second last byte if it is ASCII.
///
/// If the last byte is a UTF8 continuation byte, the second last byte can be:
///   - continuation byte: the next byte is probably ASCII or lead byte (
///     assuming 4-byte UTF8 characters are rare) and the context id is 0 or 1.
///   - lead byte (192 - 207): next byte is ASCII or lead byte, context is 0
///     or 1
///   - lead byte (208 - 255): next byte is continuation byte, context is 2 or 3
///
/// The possible value combinations of the previous two bytes, the range of
/// context ids and the type of the next byte is summarized in the table below:
///
/// |--------|-----------------------------------------------------------------|
/// |        |                           Last byte                             |
/// | Second |---------------------------------------------------------------|
/// | last byte |    ASCII           |    cont. byte       |    lead byte     |
/// |         |    (0-127)         |    (128-191)        |    (192-)        |
/// |=============|===================|=====================|==================|
/// |  ASCII      | next: ASCII/lead  |  not valid          |  next: cont.     |
/// |  (0-127)    | context: 4 - 63   |                     |  context: 2 - 3  |
/// |-------------|-------------------|---------------------|------------------|
/// |  cont. byte | next: ASCII/lead  |  next: ASCII/lead   |  next: cont.     |
/// |  (128-191)  | context: 4 - 63   |  context: 0 - 1     |  context: 2 - 3  |
/// |-------------|-------------------|---------------------|------------------|
/// |  lead byte  | not valid         |  next: ASCII/lead   |  not valid       |
/// |  (192-207)  |                   |  context: 0 - 1     |                  |
/// |-------------|-------------------|---------------------|------------------|
/// |  lead byte  | not valid         |  next: cont.        |  not valid       |
/// |  (208-)     |                   |  context: 2 - 3     |                  |
/// |-------------|-------------------|---------------------|------------------|
///
/// The context id for the signed context mode is calculated as:
///
///   context = (Context.lookup[512 + p1] << 3) | Context.lookup[512 + p2].
///   (Note: The actual implementation uses offsets from [lookupOffsets], see below)
///
/// For any context modeling modes, the context ids can be calculated by |-ing
/// together two lookups from one table using context model dependent offsets:
///
///   offset1 = Context.lookupOffsets[mode * 2];
///   offset2 = Context.lookupOffsets[mode * 2 + 1];
///   context = Context.lookup[offset1 + p1] | Context.lookup[offset2 + p2];
///
/// where p1 is the previous byte and p2 is the second previous byte.
/// The specific calculation for CONTEXT_SIGNED using the general formula might differ
/// slightly from the specific one mentioned above depending on interpretation.
/// Using the offsets is the general method.
class Context {
  // Private constructor prevents instantiation. Use static members directly.
  Context._();

  static const int CONTEXT_LSB6 = 0;
  static const int CONTEXT_MSB6 = 1;
  static const int CONTEXT_UTF8 = 2;
  static const int CONTEXT_SIGNED = 3;

  /// Combined lookup table for all context modes.
  /// Use with [lookupOffsets] to determine the correct indices based on the
  /// context mode and the previous two bytes.
  /// Using `final` because Uint8List.fromList is not a compile-time constant.
  static final Uint8List lookup = Uint8List.fromList([
    // Preserve formatting
    // CONTEXT_UTF8, last byte (offset 0)
    // ASCII range (0-127)  // Preserve formatting
    // Preserve formatting
    0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 0, 0, 4, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    8, 12, 16, 12, 12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12,
    44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12,
    12, 48, 52, 52, 52, 48, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48,
    52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24, 12, 28, 12, 12,
    12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56,
    60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 24, 12, 28, 12, 0,
    // UTF8 continuation byte range (128-191)
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
    // UTF8 lead byte range (192-255)
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
    2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, // end index 255

    // CONTEXT_UTF8, second last byte (offset 256)
    // ASCII range (0-127)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
    1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0, // end index 383
    // UTF8 continuation byte range (128-191)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // end index 447
    // UTF8 lead byte range (192-255) - Part 1 (192-207)
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // end index 463
    // UTF8 lead byte range - Part 2 (208-255)
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // end index 511

    // CONTEXT_SIGNED, second last byte lookup part (offset 512)
    // (Used for p2 lookup in the general formula for CONTEXT_SIGNED)
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, // end index 767

    // CONTEXT_SIGNED, last byte lookup part (offset 768)
    // (Used for p1 lookup in the general formula for CONTEXT_SIGNED)
    // Note: These values are effectively (lookup[512 + i] << 3)
    0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
    40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
    40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40, 40,
    48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
    56, // end index 1023

    // CONTEXT_LSB6, last byte (offset 1024)
    // Value is simply (byte & 0x3F)
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    // Repeated 3 more times (total 256 bytes)
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
    63, // end index 1279

    // CONTEXT_MSB6, last byte (offset 1280)
    // Value is effectively (byte >> 2)
    0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,
    8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11,
    12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15,
    16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19,
    20, 20, 20, 20, 21, 21, 21, 21, 22, 22, 22, 22, 23, 23, 23, 23,
    24, 24, 24, 24, 25, 25, 25, 25, 26, 26, 26, 26, 27, 27, 27, 27,
    28, 28, 28, 28, 29, 29, 29, 29, 30, 30, 30, 30, 31, 31, 31, 31,
    32, 32, 32, 32, 33, 33, 33, 33, 34, 34, 34, 34, 35, 35, 35, 35,
    36, 36, 36, 36, 37, 37, 37, 37, 38, 38, 38, 38, 39, 39, 39, 39,
    40, 40, 40, 40, 41, 41, 41, 41, 42, 42, 42, 42, 43, 43, 43, 43,
    44, 44, 44, 44, 45, 45, 45, 45, 46, 46, 46, 46, 47, 47, 47, 47,
    48, 48, 48, 48, 49, 49, 49, 49, 50, 50, 50, 50, 51, 51, 51, 51,
    52, 52, 52, 52, 53, 53, 53, 53, 54, 54, 54, 54, 55, 55, 55, 55,
    56, 56, 56, 56, 57, 57, 57, 57, 58, 58, 58, 58, 59, 59, 59, 59,
    60, 60, 60, 60, 61, 61, 61, 61, 62, 62, 62, 62, 63, 63, 63,
    63, // end index 1535

    // CONTEXT_{M,L}SB6, second last byte (offset 1536)
    // Contribution is always 0 for these modes from the second last byte.
    // All zeros for 256 bytes
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // end index 1791
  ]);

  /// Offsets into the [lookup] table based on context mode.
  /// Each pair represents `[offset1, offset2]` for a mode, used as:
  /// `lookup[offset1 + p1] | lookup[offset2 + p2]` where `p1` is the last byte
  /// and `p2` is the second last byte.
  ///
  /// Use index `mode * 2` for `offset1` and `mode * 2 + 1` for `offset2`.
  /// - `CONTEXT_LSB6` uses indices 0, 1 => `lookup[1024 + p1] | lookup[1536 + p2]`
  /// - `CONTEXT_MSB6` uses indices 2, 3 => `lookup[1280 + p1] | lookup[1536 + p2]`
  /// - `CONTEXT_UTF8` uses indices 4, 5 => `lookup[0 + p1] | lookup[256 + p2]`
  /// - `CONTEXT_SIGNED` uses indices 6, 7 => `lookup[768 + p1] | lookup[512 + p2]`
  static const List<int> lookupOffsets = [
    // CONTEXT_LSB6 (mode 0)
    1024, // offset1 for p1 (last byte)
    1536, // offset2 for p2 (second last byte)
    // CONTEXT_MSB6 (mode 1)
    1280, // offset1 for p1
    1536, // offset2 for p2
    // CONTEXT_UTF8 (mode 2)
    0, // offset1 for p1
    256, // offset2 for p2
    // CONTEXT_SIGNED (mode 3)
    768, // offset1 for p1
    512, // offset2 for p2
  ];
}
