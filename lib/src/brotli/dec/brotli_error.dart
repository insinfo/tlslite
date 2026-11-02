
class BrotliError {
  static const int brotliOk = 0;
  static const int brotliOkDone = 1;
  static const int brotliOkNeedMoreOutput = 2;

  static const int brotliError = -1;
  static const int brotliErrorCorruptedCodeLengthTable = -2;
  static const int brotliErrorCorruptedContextMap = -3;
  static const int brotliErrorCorruptedHuffmanCodeHistogram = -4;
  static const int brotliErrorCorruptedPaddingBits = -5;
  static const int brotliErrorCorruptedReservedBit = -6;
  static const int brotliErrorDuplicateSimpleHuffmanSymbol = -7;
  static const int brotliErrorExuberantNibble = -8;
  static const int brotliErrorInvalidBackwardReference = -9;
  static const int brotliErrorInvalidMetablockLength = -10;
  static const int brotliErrorInvalidWindowBits = -11;
  static const int brotliErrorNegativeDistance = -12;
  static const int brotliErrorReadAfterEnd = -13;
  static const int brotliErrorReadFailed = -14;
  static const int brotliErrorSymbolOutOfRange = -15;
  static const int brotliErrorTruncatedInput = -16;
  static const int brotliErrorUnusedBytesAfterEnd = -17;
  static const int brotliErrorUnusedHuffmanSpace = -18;

  static const int brotliPanic = -21;
  static const int brotliPanicAlreadyClosed = -22;
  static const int brotliPanicMaxDistanceTooSmall = -23;
  static const int brotliPanicStateNotFresh = -24;
  static const int brotliPanicStateNotInitialized = -25;
  static const int brotliPanicStateNotUninitialized = -26;
  static const int brotliPanicTooManyDictionaryChunks = -27;
  static const int brotliPanicUnexpectedState = -28;
  static const int brotliPanicUnreachable = -29;
  static const int brotliPanicUnalignedCopyBytes = -30;
}
