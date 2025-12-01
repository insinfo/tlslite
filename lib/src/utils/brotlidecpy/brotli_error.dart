
class BrotliError {
  static const int BROTLI_OK = 0;
  static const int BROTLI_OK_DONE = 1;
  static const int BROTLI_OK_NEED_MORE_OUTPUT = 2;

  static const int BROTLI_ERROR = -1;
  static const int BROTLI_ERROR_CORRUPTED_CODE_LENGTH_TABLE = -2;
  static const int BROTLI_ERROR_CORRUPTED_CONTEXT_MAP = -3;
  static const int BROTLI_ERROR_CORRUPTED_HUFFMAN_CODE_HISTOGRAM = -4;
  static const int BROTLI_ERROR_CORRUPTED_PADDING_BITS = -5;
  static const int BROTLI_ERROR_CORRUPTED_RESERVED_BIT = -6;
  static const int BROTLI_ERROR_DUPLICATE_SIMPLE_HUFFMAN_SYMBOL = -7;
  static const int BROTLI_ERROR_EXUBERANT_NIBBLE = -8;
  static const int BROTLI_ERROR_INVALID_BACKWARD_REFERENCE = -9;
  static const int BROTLI_ERROR_INVALID_METABLOCK_LENGTH = -10;
  static const int BROTLI_ERROR_INVALID_WINDOW_BITS = -11;
  static const int BROTLI_ERROR_NEGATIVE_DISTANCE = -12;
  static const int BROTLI_ERROR_READ_AFTER_END = -13;
  static const int BROTLI_ERROR_READ_FAILED = -14;
  static const int BROTLI_ERROR_SYMBOL_OUT_OF_RANGE = -15;
  static const int BROTLI_ERROR_TRUNCATED_INPUT = -16;
  static const int BROTLI_ERROR_UNUSED_BYTES_AFTER_END = -17;
  static const int BROTLI_ERROR_UNUSED_HUFFMAN_SPACE = -18;

  static const int BROTLI_PANIC = -21;
  static const int BROTLI_PANIC_ALREADY_CLOSED = -22;
  static const int BROTLI_PANIC_MAX_DISTANCE_TOO_SMALL = -23;
  static const int BROTLI_PANIC_STATE_NOT_FRESH = -24;
  static const int BROTLI_PANIC_STATE_NOT_INITIALIZED = -25;
  static const int BROTLI_PANIC_STATE_NOT_UNINITIALIZED = -26;
  static const int BROTLI_PANIC_TOO_MANY_DICTIONARY_CHUNKS = -27;
  static const int BROTLI_PANIC_UNEXPECTED_STATE = -28;
  static const int BROTLI_PANIC_UNREACHABLE = -29;
  static const int BROTLI_PANIC_UNALIGNED_COPY_BYTES = -30;
}
