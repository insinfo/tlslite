import 'dart:typed_data';

import 'bit_stream_writer.dart';
import 'huffman_builder.dart';

const int _repeatPreviousCodeLength = 16;
const int _repeatZeroCodeLength = 17;
const int _initialRepeatedCodeLength = 8;
const int _codeLengthAlphabetSize = 18;
const List<int> _codeLengthCodeOrder = [
  1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15,
];
const List<int> _bitLengthHuffmanSymbols = [0, 7, 3, 2, 1, 15];
const List<int> _bitLengthHuffmanBitLengths = [2, 4, 3, 2, 2, 4];

/// Serializes Huffman code lengths into the canonical Brotli meta-data format.
class BrotliHuffmanTreeWriter {
  const BrotliHuffmanTreeWriter._();

  /// Writes [codeLengths] to [writer] using the representation consumed by the
  /// decoder's [readHuffmanCode].
  static void writeTree(Uint8List codeLengths, BitStreamWriter writer) {
    if (codeLengths.isEmpty) {
      return;
    }

    // Count non-zero code lengths and collect the symbols
    final nonZeroSymbols = <int>[];
    for (var i = 0; i < codeLengths.length; i++) {
      if (codeLengths[i] != 0) {
        nonZeroSymbols.add(i);
      }
    }

    // Use simple tree format if 1-4 symbols (more efficient)
    if (nonZeroSymbols.length >= 1 && nonZeroSymbols.length <= 4) {
      _writeSimpleTree(codeLengths.length, nonZeroSymbols, writer);
      return;
    }

    // Fall back to complex tree format
    _writeComplexTree(codeLengths, writer);
  }

  static void _writeSimpleTree(
    int alphabetSize,
    List<int> symbols,
    BitStreamWriter writer,
  ) {
    // Simple tree format per RFC 7932 and Java reference:
    // - 2 bits: value 1 (indicates simple tree, i.e. bits "01")
    // - 2 bits: number of symbols - 1 (NSYM - 1)
    // - For each symbol: ceil(log2(alphabetSize)) bits for symbol index
    // - For 4 symbols: 1 extra bit to select tree shape
    
    final numSymbols = symbols.length;

    // Write the simple code marker (value 1 = "01" in 2 bits)
    writer.writeBits(1, 2);
    
    // Write number of symbols minus 1 (in 2 bits)
    writer.writeBits(numSymbols - 1, 2);

    // Calculate bits needed for symbol indices: 1 + log2floor(alphabetSize - 1)
    var maxBits = 1;
    var counter = alphabetSize - 1;
    while (counter > 1) {
      counter >>= 1;
      maxBits++;
    }

    // Write each symbol
    for (var i = 0; i < numSymbols; i++) {
      writer.writeBits(symbols[i], maxBits);
    }

    // For 4 symbols, need an extra bit to choose between tree shapes
    // histogramId = numSymbols + (extra bit)
    // histogramId 4 = [2,2,2,2], histogramId 5 = [1,2,3,3]
    if (numSymbols == 4) {
      // Use the [2,2,2,2] shape (write 0)
      writer.writeBits(0, 1);
    }
  }

  static void _writeComplexTree(Uint8List codeLengths, BitStreamWriter writer) {
    final treeSymbols = <int>[];
    final treeExtraBits = <int>[];
    _writeHuffmanTree(codeLengths, treeSymbols, treeExtraBits);

    final histogram = List<int>.filled(_codeLengthAlphabetSize, 0);
    for (final symbol in treeSymbols) {
      histogram[symbol]++;
    }

    var numCodes = 0;
    var loneCode = 0;
    for (var i = 0; i < histogram.length; i++) {
      if (histogram[i] == 0) {
        continue;
      }
      if (numCodes == 0) {
        loneCode = i;
        numCodes = 1;
      } else {
        numCodes = 2;
        break;
      }
    }

    final codeLengthBitDepth = buildLimitedHuffmanCodeLengths(
      histogram,
      _codeLengthAlphabetSize,
      5,
    );
    final codeLengthSymbols = convertBitDepthsToSymbols(codeLengthBitDepth);

    final skipSome = _determineSkipAmount(numCodes, codeLengthBitDepth);
    // RFC 7932: For complex tree, write skip value directly (0, 2, or 3)
    // Value 1 is reserved for simple tree indicator
    writer.writeBits(skipSome, 2);
    _storeHuffmanTreeOfHuffmanTree(
      numCodes,
      codeLengthBitDepth,
      skipSome,
      writer,
    );

    if (numCodes == 1) {
      codeLengthBitDepth[loneCode] = 0;
    }

    _storeHuffmanTree(
      treeSymbols,
      treeExtraBits,
      codeLengthBitDepth,
      codeLengthSymbols,
      writer,
    );
  }
}

void _writeHuffmanTree(
  Uint8List depths,
  List<int> treeSymbols,
  List<int> treeExtraBits,
) {
  var newLength = depths.length;
  while (newLength > 0 && depths[newLength - 1] == 0) {
    newLength--;
  }
  if (newLength == 0) {
    treeSymbols.add(0);
    treeExtraBits.add(0);
    return;
  }

  final decision = _computeRleUsage(depths, newLength);
  var previousValue = _initialRepeatedCodeLength;
  var index = 0;
  while (index < newLength) {
    final value = depths[index];
    var repetitions = 1;
    if ((value != 0 && decision.useRleForNonZero) ||
        (value == 0 && decision.useRleForZero)) {
      var next = index + 1;
      while (next < newLength && depths[next] == value) {
        repetitions++;
        next++;
      }
    }
    if (value == 0) {
      _writeRepetitionsZeros(repetitions, treeSymbols, treeExtraBits);
    } else {
      _writeRepetitions(previousValue, value, repetitions, treeSymbols, treeExtraBits);
      previousValue = value;
    }
    index += repetitions;
  }
}

void _writeRepetitions(
  int previousValue,
  int value,
  int repetitions,
  List<int> treeSymbols,
  List<int> treeExtraBits,
) {
  if (previousValue != value) {
    treeSymbols.add(value);
    treeExtraBits.add(0);
    repetitions--;
  }
  if (repetitions == 7) {
    treeSymbols.add(value);
    treeExtraBits.add(0);
    repetitions--;
  }
  if (repetitions < 3) {
    for (var i = 0; i < repetitions; i++) {
      treeSymbols.add(value);
      treeExtraBits.add(0);
    }
    return;
  }

  final start = treeSymbols.length;
  var remaining = repetitions - 3;
  while (true) {
    treeSymbols.add(_repeatPreviousCodeLength);
    treeExtraBits.add(remaining & 0x3);
    remaining >>= 2;
    if (remaining == 0) {
      break;
    }
    remaining--;
  }
  _reverse(treeSymbols, start, treeSymbols.length);
  _reverse(treeExtraBits, start, treeExtraBits.length);
}

void _writeRepetitionsZeros(
  int repetitions,
  List<int> treeSymbols,
  List<int> treeExtraBits,
) {
  if (repetitions == 11) {
    treeSymbols.add(0);
    treeExtraBits.add(0);
    repetitions--;
  }
  if (repetitions < 3) {
    for (var i = 0; i < repetitions; i++) {
      treeSymbols.add(0);
      treeExtraBits.add(0);
    }
    return;
  }

  final start = treeSymbols.length;
  var remaining = repetitions - 3;
  while (true) {
    treeSymbols.add(_repeatZeroCodeLength);
    treeExtraBits.add(remaining & 0x7);
    remaining >>= 3;
    if (remaining == 0) {
      break;
    }
    remaining--;
  }
  _reverse(treeSymbols, start, treeSymbols.length);
  _reverse(treeExtraBits, start, treeExtraBits.length);
}

class _RleUsage {
  _RleUsage(this.useRleForNonZero, this.useRleForZero);

  final bool useRleForNonZero;
  final bool useRleForZero;
}

_RleUsage _computeRleUsage(Uint8List depth, int length) {
  var totalRepsZero = 0;
  var totalRepsNonZero = 0;
  var countRepsZero = 1;
  var countRepsNonZero = 1;
  var i = 0;
  while (i < length) {
    final value = depth[i];
    var reps = 1;
    var k = i + 1;
    while (k < length && depth[k] == value) {
      reps++;
      k++;
    }
    if (reps >= 3 && value == 0) {
      totalRepsZero += reps;
      countRepsZero++;
    }
    if (reps >= 4 && value != 0) {
      totalRepsNonZero += reps;
      countRepsNonZero++;
    }
    i += reps;
  }
  return _RleUsage(
    totalRepsNonZero > countRepsNonZero * 2,
    totalRepsZero > countRepsZero * 2,
  );
}

int _determineSkipAmount(int numCodes, Uint8List codeLengthBitDepth) {
  if (numCodes <= 1) {
    return 0;
  }
  if (codeLengthBitDepth[_codeLengthCodeOrder[0]] == 0 &&
      codeLengthBitDepth[_codeLengthCodeOrder[1]] == 0) {
    if (codeLengthBitDepth[_codeLengthCodeOrder[2]] == 0) {
      return 3;
    }
    return 2;
  }
  return 0;
}

void _storeHuffmanTreeOfHuffmanTree(
  int numCodes,
  Uint8List codeLengthBitDepth,
  int skipSome,
  BitStreamWriter writer,
) {
  // Match the decoder's stopping condition: stop when space <= 0
  int space = 32;
  for (var i = skipSome; i < _codeLengthAlphabetSize; i++) {
    final codeLenIdx = _codeLengthCodeOrder[i];
    final symbolId = codeLengthBitDepth[codeLenIdx];
    writer.writeBits(
      _bitLengthHuffmanSymbols[symbolId],
      _bitLengthHuffmanBitLengths[symbolId],
    );
    if (symbolId != 0) {
      space -= (32 >> symbolId);
      if (space <= 0) {
        break;
      }
    }
  }
}

void _storeHuffmanTree(
  List<int> treeSymbols,
  List<int> treeExtraBits,
  Uint8List codeLengthBitDepth,
  Uint16List codeLengthSymbols,
  BitStreamWriter writer,
) {
  for (var i = 0; i < treeSymbols.length; i++) {
    final symbol = treeSymbols[i];
    final bitDepth = codeLengthBitDepth[symbol];
    final code = codeLengthSymbols[symbol];
    writer.writeBits(code, bitDepth);
    switch (symbol) {
      case _repeatPreviousCodeLength:
        writer.writeBits(treeExtraBits[i], 2);
        break;
      case _repeatZeroCodeLength:
        writer.writeBits(treeExtraBits[i], 3);
        break;
      default:
        break;
    }
  }
}

void _reverse(List<int> data, int start, int end) {
  var i = start;
  var j = end - 1;
  while (i < j) {
    final tmp = data[i];
    data[i] = data[j];
    data[j] = tmp;
    i++;
    j--;
  }
}

/// Stores a VarLen uint8 used by meta-block headers.
void storeVarLenUint8(BitStreamWriter writer, int value) {
  if (value < 0 || value > 255) {
    throw ArgumentError.value(value, 'value', 'Must fit in uint8');
  }
  if (value == 0) {
    writer.writeBool(false);
    return;
  }
  writer.writeBool(true);
  if (value == 1) {
    writer.writeBits(0, 3);
    return;
  }
  final nbits = _log2Floor(value);
  writer.writeBits(nbits, 3);
  final base = 1 << nbits;
  writer.writeBits(value - base, nbits);
}

int _log2Floor(int value) {
  var n = value;
  var result = 0;
  while (n > 1) {
    n >>= 1;
    result++;
  }
  return result;
}
