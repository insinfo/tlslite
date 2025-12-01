// decode.dart
import 'dart:typed_data';
import 'huffman.dart';
import 'prefix.dart';
import 'bit_reader.dart';
import 'dictionary.dart';
import 'context.dart';
import 'transform.dart';

// --- Constants ---
const int kDefaultCodeLength = 8;
const int kCodeLengthRepeatCode = 16;
const int kNumLiteralCodes = 256;
const int kNumInsertAndCopyCodes = 704;
const int kNumBlockLengthCodes = 26;
const int kLiteralContextBits = 6;
const int kDistanceContextBits = 2;
const int huffmanTableBits = 8;
const int huffmanTableMask = 0xff;
const int huffmanMaxTableSize = 1080;
const int codeLengthCodes = 18;
const bool _debugCodeLengthLut = false;
final List<int> kCodeLengthCodeOrder = List.unmodifiable(
    [1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
final List<int> kCodeLengthFixedTable = List.unmodifiable([
  0x020000, 0x020004, 0x020003, 0x030002,
  0x020000, 0x020004, 0x020003, 0x040001,
  0x020000, 0x020004, 0x020003, 0x030002,
  0x020000, 0x020004, 0x020003, 0x040005,
]);
const int numDistanceShortCodes = 16;
final List<int> kDistanceShortCodeIndexOffset =
    List.unmodifiable([0, 3, 2, 1, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3]);
final List<int> kDistanceShortCodeValueOffset =
    List.unmodifiable([0, 0, 0, 0, -1, 1, -2, 2, -3, 3, -1, 1, -2, 2, -3, 3]);
final List<int> kMaxHuffmanTableSize = List.unmodifiable([
  // Preserve formatting
  256, 402, 436, 468, 500, 534, 566, 598, 630,
  662, 694, 726, 758, 790, 822, 854, 886, 920,
  952, 984, 1016, 1048, 1080
]);

// --- Helper Functions ---
// ... (decodeWindowBits, decodeVarLenUint8 - no changes) ...
int decodeWindowBits(BrotliBitReader br) {
  if (br.read_bits(1) == 0) return 16;
  int n = br.read_bits(3);
  if (n > 0) return 17 + n;
  n = br.read_bits(3);
  if (n > 0) return 8 + n;
  return 17;
}

int decodeVarLenUint8(BrotliBitReader br) {
  if (br.read_bits(1) != 0) {
    int nbits = br.read_bits(3);
    if (nbits == 0) return 1;
    return br.read_bits(nbits) + (1 << nbits);
  }
  return 0;
}

// ... (MetaBlockLength class, decodeMetaBlockLength - no changes) ...
class MetaBlockLength {
  int metaBlockLength = 0;
  bool inputEnd = false;
  bool isUncompressed = false;
  bool isMetadata = false;
}

MetaBlockLength decodeMetaBlockLength(BrotliBitReader br) {
  final out = MetaBlockLength();
  out.inputEnd = br.read_bits(1) != 0;
  if (out.inputEnd && br.read_bits(1) != 0) return out;
  int sizeNibbles = br.read_bits(2) + 4;
  if (sizeNibbles == 7) {
    /* metadata */ out.isMetadata = true;
    if (br.read_bits(1) != 0) throw Exception('Invalid reserved bit');
    int sizeBytes = br.read_bits(2);
    if (sizeBytes == 0) return out;
    for (int i = 0; i < sizeBytes; i++) {
      int nextByte = br.read_bits(8);
      if (i + 1 == sizeBytes && sizeBytes > 1 && nextByte == 0)
        throw Exception('Invalid size byte');
      out.metaBlockLength |= (nextByte << (i * 8));
    }
  } else {
    /* normal */ for (int i = 0; i < sizeNibbles; i++) {
      int nextNibble = br.read_bits(4);
      if (i + 1 == sizeNibbles && sizeNibbles > 4 && nextNibble == 0)
        throw Exception('Invalid size nibble');
      out.metaBlockLength |= (nextNibble << (i * 4));
    }
  }
  out.metaBlockLength += 1;
  if (!out.inputEnd && !out.isMetadata) {
    out.isUncompressed = br.read_bits(1) != 0;
  }
  return out;
}

// ... (readSymbol - use corrected version from previous step) ...
int readSymbol(List<HuffmanCode> table, int tableIndex, BrotliBitReader br) {
  int index = tableIndex;
  final int xBits = br.read_bits(16, bits_to_skip: 0);
  index += (xBits & huffmanTableMask);
  int nbits = table[index].bits - huffmanTableBits;
  int skip = 0;
  if (nbits > 0) {
    skip = huffmanTableBits;
    final int mask = BrotliBitReader.kBitMask[nbits];
    index += table[index].value + ((xBits >> huffmanTableBits) & mask);
  }
  final int totalBits = skip + table[index].bits;
  br.read_bits(0, bits_to_skip: totalBits);
  return table[index].value;
}

// ... (readHuffmanCodeLengths - use corrected version from previous step) ...
void readHuffmanCodeLengths(List<int> codeLengthCodeLengths, int numSymbols,
    Uint8List codeLengths, BrotliBitReader br) {
  int symbol = 0;
  int prevCodeLen = kDefaultCodeLength;
  int repeat = 0;
  int repeatCodeLen = 0;
  int space = 32768;
  final List<HuffmanCode> table =
      List.generate(huffmanMaxTableSize, (_) => HuffmanCode(0, 0));
  brotli_build_huffman_table(table, 0, 5, codeLengthCodeLengths, codeLengthCodes);

  while (symbol < numSymbols && space > 0) {
    final int p = br.read_bits(5, bits_to_skip: 0);
    final HuffmanCode entry = table[p];
    br.read_bits(0, bits_to_skip: entry.bits);
    final int codeLen = entry.value & 0xff;
    if (_debugCodeLengthLut && numSymbols <= 16) {
      print('codeLen symbol[$symbol] p=$p value=$codeLen bits=${entry.bits}');
    }
    if (codeLen < kCodeLengthRepeatCode) {
      repeat = 0;
      codeLengths[symbol++] = codeLen;
      if (codeLen != 0) {
        prevCodeLen = codeLen;
        space -= (32768 >> codeLen);
      }
    } else {
      final int extraBits = codeLen - 14;
      int newLen = 0;
      if (codeLen == kCodeLengthRepeatCode) {
        newLen = prevCodeLen;
      }
      if (repeatCodeLen != newLen) {
        repeat = 0;
        repeatCodeLen = newLen;
      }
      final int oldRepeat = repeat;
      if (repeat > 0) {
        repeat -= 2;
        repeat <<= extraBits;
      }
      repeat += br.read_bits(extraBits) + 3;
      final int repeatDelta = repeat - oldRepeat;
      if (symbol + repeatDelta > numSymbols) {
        throw Exception('Repeat count exceeds symbol count');
      }
      for (int i = 0; i < repeatDelta; i++) {
        codeLengths[symbol + i] = repeatCodeLen;
      }
      symbol += repeatDelta;
      if (repeatCodeLen != 0) {
        space -= repeatDelta << (15 - repeatCodeLen);
      }
    }
  }

  if (space != 0) {
    throw Exception('Unused Huffman space: $space');
  }
  for (int i = symbol; i < numSymbols; i++) {
    codeLengths[i] = 0;
  }
}

// ... (readHuffmanCode - use corrected version from previous step) ...
int readHuffmanCode(int alphabetSize, List<HuffmanCode> tables, int tableIndex,
    BrotliBitReader br) {
  final Uint8List codeLengths = Uint8List(alphabetSize);
  final int simpleCodeOrSkip = br.read_bits(2);
  // Per RFC 7932 and reference implementation:
  // simpleCodeOrSkip == 1 means simple tree
  // simpleCodeOrSkip == 0, 2, 3 means complex tree with skip = 0, 2, or 3
  if (simpleCodeOrSkip == 1) {
    /* simple tree */
    // Calculate maxBits: 1 + log2floor(alphabetSize - 1)
    int maxBitsCounter = alphabetSize - 1;
    int maxBits = 0;
    while (maxBitsCounter > 0) {
      maxBitsCounter >>= 1;
      maxBits++;
    }
    
    final List<int> symbols = [0, 0, 0, 0];
    // Read number of symbols (NSYM - 1) in 2 bits, then add 1
    final int numSymbols = br.read_bits(2) + 1;
    
    for (int i = 0; i < numSymbols; i++) {
      final int symbolIndex = br.read_bits(maxBits);
      if (symbolIndex >= alphabetSize) throw Exception('Symbol index OOB');
      symbols[i] = symbolIndex;
    }
    /* Assign lengths based on numSymbols, check duplicates */
    if (numSymbols == 1) {
      codeLengths[symbols[0]] = 1;
    } else if (numSymbols == 2) {
      if (symbols[0] == symbols[1]) throw Exception("dup");
      codeLengths[symbols[0]] = 1;
      codeLengths[symbols[1]] = 1;
    } else if (numSymbols == 3) {
      if (symbols[0] == symbols[1] ||
          symbols[0] == symbols[2] ||
          symbols[1] == symbols[2]) throw Exception("dup");
      codeLengths[symbols[0]] = 1;
      codeLengths[symbols[1]] = 2;
      codeLengths[symbols[2]] = 2;
    } else {
      if (symbols[0] == symbols[1] ||
          symbols[0] == symbols[2] ||
          symbols[0] == symbols[3] ||
          symbols[1] == symbols[2] ||
          symbols[1] == symbols[3] ||
          symbols[2] == symbols[3]) throw Exception("dup");
      if (br.read_bits(1) != 0) {
        codeLengths[symbols[0]] = 1;
        codeLengths[symbols[1]] = 2;
        codeLengths[symbols[2]] = 3;
        codeLengths[symbols[3]] = 3;
      } else {
        codeLengths[symbols[0]] = 2;
        codeLengths[symbols[1]] = 2;
        codeLengths[symbols[2]] = 2;
        codeLengths[symbols[3]] = 2;
      }
    }
  } else {
    /* complex tree */
    // RFC 7932: simpleCodeOrSkip is 0, 2, or 3 for complex tree (1 = simple)
    // The value is used directly as the number of symbols to skip
    final int skip = simpleCodeOrSkip;  // 0, 2, or 3
    final List<int> codeLengthCodeLengths = List.filled(codeLengthCodes, 0);
    int space = 32;
    int numCodes = 0;
    if (_debugCodeLengthLut) {
      print('--- decode code-length hist skip=$skip');
    }
    for (int i = skip; i < codeLengthCodes; i++) {
      final int codeLenIdx = kCodeLengthCodeOrder[i];
      final int peek = br.read_bits(4, bits_to_skip: 0) & 0xF;
      final int entry = kCodeLengthFixedTable[peek];
      final int bitsToDrop = entry >> 16;
      final int codeLen = entry & 0xFFFF;
      br.read_bits(0, bits_to_skip: bitsToDrop);
      if (_debugCodeLengthLut) {
        print(
        'codeLenIdx=$codeLenIdx peek=$peek bits=$bitsToDrop len=$codeLen');
      }
      codeLengthCodeLengths[codeLenIdx] = codeLen;
      if (codeLen != 0) {
        space -= (32 >> codeLen);
        numCodes++;
        if (space <= 0) {
          break;
        }
      }
    }
    if (space != 0 && numCodes != 1) {
      throw Exception(
          'Invalid code length code lengths (skip=$simpleCodeOrSkip space=$space numCodes=$numCodes values=$codeLengthCodeLengths)');
    }
    if (_debugCodeLengthLut && alphabetSize <= 16) {
      print('codeLengthCodeLengths: $codeLengthCodeLengths');
    }
    readHuffmanCodeLengths(
        codeLengthCodeLengths, alphabetSize, codeLengths, br);
    if (_debugCodeLengthLut && alphabetSize <= 16) {
      print('decoded code lengths: ${codeLengths.sublist(0, alphabetSize)}');
    }
  }
  int tableSize = brotli_build_huffman_table(
      tables, tableIndex, huffmanTableBits, codeLengths, alphabetSize);
  if (tableSize == 0) {
    if (alphabetSize > 1) throw Exception('BuildHuffmanTable failed');
    if (alphabetSize == 1 && codeLengths[0] == 0) {
      if (tableIndex < tables.length) {
        tables[tableIndex] = HuffmanCode(0, 0);
        return 1;
      } else {
        throw Exception("OOB");
      }
    } else {
      throw Exception('BuildHuffmanTable failed');
    }
  }
  return tableSize;
}

// ... (readBlockLength - no changes needed if readSymbol is correct) ...
int readBlockLength(
    List<HuffmanCode> table, int tableIndex, BrotliBitReader br) {
  int code = readSymbol(table, tableIndex, br);
  int nbits = kBlockLengthPrefixCode[code].nbits;
  int offset = kBlockLengthPrefixCode[code].offset;
  if (nbits > 0) {
    return offset + br.read_bits(nbits);
  }
  return offset;
}

// ... (translateShortCodes, moveToFront, inverseMoveToFrontTransform - no changes needed) ...
int translateShortCodes(int code, List<int> ringbuffer, int index) {
  int val;
  if (code < numDistanceShortCodes) {
    int rbIndex = index + kDistanceShortCodeIndexOffset[code];
    rbIndex &= 3;
    val = ringbuffer[rbIndex] + kDistanceShortCodeValueOffset[code];
    if (val <= 0) throw Exception("Invalid distance <= 0");
  } else {
    val = code - numDistanceShortCodes + 1;
  }
  return val;
}

void moveToFront(List<int> v, int index) {
  if (index <= 0 || index >= v.length) return;
  int value = v.removeAt(index);
  v.insert(0, value);
}

void inverseMoveToFrontTransform(Uint8List v, int vLen) {
  final List<int> mtf = List.generate(256, (i) => i);
  for (int i = 0; i < vLen; i++) {
    int index = v[i];
    if (index >= mtf.length) throw Exception("Invalid MTF index: $index");
    v[i] = mtf[index];
    if (index != 0) {
      moveToFront(mtf, index);
    }
  }
}

// --- Classes ---

/// Contains a collection of Huffman trees with the same alphabet size. (Corrected)
class HuffmanTreeGroup {
  final int alphabetSize;
  final int numHuffTrees;
  late final List<HuffmanCode> codes;
  late final List<int> huffTrees;

  HuffmanTreeGroup(this.alphabetSize, this.numHuffTrees) {
    // Fix: Ensure index is int and multiplication result is int
    int index = (alphabetSize + 31) >> 5;
    if (index < 0 || index >= kMaxHuffmanTableSize.length) {
      throw Exception(
          "Invalid alphabet size for kMaxHuffmanTableSize lookup: $alphabetSize");
    }
    int estimatedTableSize = kMaxHuffmanTableSize[index]; // Lookup is int
    int sizeEstimate = numHuffTrees +
        (numHuffTrees * estimatedTableSize); // int + (int * int) is int

    codes =
        List.generate(sizeEstimate, (_) => HuffmanCode(0, 0), growable: false);
    huffTrees = List.filled(numHuffTrees, 0, growable: false);
  }

  void decode(BrotliBitReader br) {
    // Uses corrected readHuffmanCode
    int nextEntry = 0;
    for (int i = 0; i < numHuffTrees; i++) {
      huffTrees[i] = nextEntry;
      if (nextEntry >= codes.length)
        throw Exception("HuffmanTreeGroup buffer too small");
      int tableSize = readHuffmanCode(alphabetSize, codes, nextEntry, br);
      nextEntry += tableSize;
      if (tableSize == 0 && alphabetSize > 1)
        throw Exception("readHuffmanCode returned 0");
    }
  }
}

// ... (DecodeContextMap - uses corrected readSymbol, readHuffmanCode, read_bits) ...
class DecodeContextMap {
  late final int numHuffTrees;
  late final Uint8List contextMap;
  DecodeContextMap(int contextMapSize, BrotliBitReader br) {
    numHuffTrees = decodeVarLenUint8(br) + 1;
    contextMap = Uint8List(contextMapSize);
    if (numHuffTrees <= 1) return;
    bool useRleForZeros = br.read_bits(1) != 0;
    int maxRunLengthPrefix = 0;
    if (useRleForZeros) {
      maxRunLengthPrefix = br.read_bits(4) + 1;
    }
    final List<HuffmanCode> table =
        List.generate(huffmanMaxTableSize, (_) => HuffmanCode(0, 0));
    readHuffmanCode(numHuffTrees + maxRunLengthPrefix, table, 0, br);
    int i = 0;
    while (i < contextMapSize) {
      int code = readSymbol(table, 0, br);
      if (code == 0) {
        contextMap[i] = 0;
        i++;
      } else if (code <= maxRunLengthPrefix) {
        int reps = (1 << code) + br.read_bits(code);
        if (i + reps > contextMapSize) throw Exception('RLE run exceeds size');
        i += reps;
      } else {
        contextMap[i] = code - maxRunLengthPrefix;
        if (contextMap[i] >= numHuffTrees)
          throw Exception('Context map index OOB');
        i++;
      }
    }
    if (br.read_bits(1) != 0) {
      inverseMoveToFrontTransform(contextMap, contextMapSize);
    }
  }
}

// ... (decodeBlockType - uses corrected readSymbol) ...
void decodeBlockType(
    int maxBlockType,
    List<HuffmanCode> trees, // Combined block type trees (e.g., blockTypeTrees)
    int treeType, // 0: literal, 1: insert/copy, 2: distance
    List<int> blockTypes, // Output: current block type for each tree type
    List<int> ringBuffers, // Ring buffers for block types (size 6)
    List<int> indexes, // Indexes for ring buffers (size 3)
    BrotliBitReader br) {
  // FIX: Multiply by the integer constant 'huffmanMaxTableSize',
  //      not the list 'kMaxHuffmanTableSize'.
  final int treeIndex = treeType * huffmanMaxTableSize;

  // Optional: Add a bounds check for safety, although if 'trees' is allocated
  // correctly (e.g., 3 * huffmanMaxTableSize), this shouldn't be strictly necessary
  // unless treeType is invalid.
  if (treeIndex < 0 || treeIndex >= trees.length) {
    throw Exception(
        "Calculated treeIndex $treeIndex out of bounds for list length ${trees.length}, treeType was $treeType");
  }

  final int ringbufferOffset = treeType * 2;
  final int indexOffset = treeType;

  // Read the type code symbol using the calculated starting index
  final int typeCode = readSymbol(trees, treeIndex, br);
  int blockType; // The actual block type ID

  if (typeCode == 0) {
    blockType = ringBuffers[ringbufferOffset + (indexes[indexOffset] & 1)];
  } else if (typeCode == 1) {
    // Ensure the index doesn't go negative if indexes[indexOffset] is 0
    blockType =
        ringBuffers[ringbufferOffset + ((indexes[indexOffset] - 1) & 1)] + 1;
  } else {
    blockType = typeCode - 2;
  }

  // Handle wrap-around if block type exceeds max
  if (blockType >= maxBlockType) {
    blockType -= maxBlockType;
  }

  // Store the result
  blockTypes[treeType] = blockType;

  // Update the ring buffer and index
  ringBuffers[ringbufferOffset + (indexes[indexOffset] & 1)] = blockType;
  indexes[indexOffset]++;
}

// ... (copyUncompressedBlockToOutput, jumpToByteBoundary - use copy_bytes, assume it works) ...
void copyUncompressedBlockToOutput(
    int length, int pos, List<int> outputBuffer, BrotliBitReader br) {
  _ensureOutputCapacity(outputBuffer, pos + length);
  br.copy_bytes(outputBuffer, pos, length);
}

void jumpToByteBoundary(BrotliBitReader br) {
  br.copy_bytes(Uint8List(0), 0, 0);
} // Align using copy_bytes

void _ensureOutputCapacity(List<int> buffer, int requiredLength) {
  if (requiredLength <= buffer.length) {
    return;
  }
  final growBy = requiredLength - buffer.length;
  buffer.addAll(List<int>.filled(growBy, 0));
}

// --- Main Decompression Function
Uint8List brotliDecompressBuffer(Uint8List inputBuffer, {int? bufferLimit}) {
  final br = BrotliBitReader(inputBuffer);
  final List<int> outputBuffer = [];
  int pos = 0;
  bool inputEnd = false;
  // Initialize distance ring buffer as per Java reference: [16, 15, 11, 4]
  final List<int> distRb = [16, 15, 11, 4];
  int distRbIdx = 3;
  final List<HuffmanTreeGroup?> hgroup = List.filled(3, null);
  final int windowBits = decodeWindowBits(br);
  if (windowBits == 0) throw Exception("Invalid window bits");
  final int maxBackwardDistance = (1 << windowBits) - 16;
  final int maxCombinedTableSize = 3 * huffmanMaxTableSize;
  final List<HuffmanCode> blockTypeTrees =
      List.generate(maxCombinedTableSize, (_) => HuffmanCode(0, 0));
  final List<HuffmanCode> blockLenTrees =
      List.generate(maxCombinedTableSize, (_) => HuffmanCode(0, 0));

  while (!inputEnd) {
    final List<int> blockLength = [1 << 28, 1 << 28, 1 << 28];
    final List<int> blockType = [0, 0, 0];
    final List<int> numBlockTypes = [1, 1, 1];
    final List<int> blockTypeRb = [0, 1, 0, 1, 0, 1];
    final List<int> blockTypeRbIndex = [0, 0, 0];

    if (bufferLimit != null && outputBuffer.length > bufferLimit) {
      throw Exception("Output buffer limit exceeded: $bufferLimit");
    }
    hgroup[0] = null;
    hgroup[1] = null;
    hgroup[2] = null;

    final MetaBlockLength metaBlockInfo = decodeMetaBlockLength(br);
    int metaBlockRemainingLen = metaBlockInfo.metaBlockLength;
    inputEnd = metaBlockInfo.inputEnd;
    final bool isUncompressed = metaBlockInfo.isUncompressed;

    if (metaBlockInfo.isMetadata) {
      jumpToByteBoundary(br);
      // Simulate dropBytes using copy_bytes with dummy output
      br.copy_bytes(Uint8List(0), 0, metaBlockRemainingLen);
      continue;
    }
    // Skip empty meta-blocks (whether last or not)
    if (metaBlockRemainingLen == 0) continue;
    _ensureOutputCapacity(outputBuffer, pos + metaBlockRemainingLen);

    if (isUncompressed) {
      jumpToByteBoundary(br);
      copyUncompressedBlockToOutput(
          metaBlockRemainingLen, pos, outputBuffer, br);
      pos += metaBlockRemainingLen;
      continue;
    }

    // --- Compressed Meta-block Decoding ---
    for (int i = 0; i < 3; i++) {
      numBlockTypes[i] = decodeVarLenUint8(br) + 1;
      if (numBlockTypes[i] >= 2) {
        readHuffmanCode(
            numBlockTypes[i] + 2, blockTypeTrees, i * huffmanMaxTableSize, br);
        readHuffmanCode(
            kNumBlockLengthCodes, blockLenTrees, i * huffmanMaxTableSize, br);
        blockLength[i] =
            readBlockLength(blockLenTrees, i * huffmanMaxTableSize, br);
        blockTypeRbIndex[i] = 1;
      }
    }

    final int distancePostfixBits = br.read_bits(2);
    final int numDirectDistanceCodes =
        numDistanceShortCodes + (br.read_bits(4) << distancePostfixBits);
    final int distancePostfixMask = (1 << distancePostfixBits) - 1;
    final int numDistanceCodes =
        numDirectDistanceCodes + (48 << distancePostfixBits);
    final Uint8List contextModes = Uint8List(numBlockTypes[0]);
    for (int i = 0; i < numBlockTypes[0]; i++) {
      contextModes[i] = (br.read_bits(2) << 1);
    }

    final DecodeContextMap literalContextMapInfo =
        DecodeContextMap(numBlockTypes[0] << kLiteralContextBits, br);
    final int numLiteralHuffTrees = literalContextMapInfo.numHuffTrees;
    final Uint8List contextMap = literalContextMapInfo.contextMap;
    final DecodeContextMap distContextMapInfo =
        DecodeContextMap(numBlockTypes[2] << kDistanceContextBits, br);
    final int numDistHuffTrees = distContextMapInfo.numHuffTrees;
    final Uint8List distContextMap = distContextMapInfo.contextMap;

    hgroup[0] = HuffmanTreeGroup(kNumLiteralCodes, numLiteralHuffTrees);
    hgroup[1] = HuffmanTreeGroup(kNumInsertAndCopyCodes, numBlockTypes[1]);
    hgroup[2] = HuffmanTreeGroup(numDistanceCodes, numDistHuffTrees);
    for (int i = 0; i < 3; i++) {
      hgroup[i]!.decode(br);
    }

    // --- Inner Loop: Process Commands ---
    int contextMapSlice = 0;
    int distContextMapSlice = 0;
    int contextMode = contextModes[blockType[0]];
    // int contextLookupOffset1 = Context.lookupOffsets[contextMode]; // Moved inside loop
    // int contextLookupOffset2 = Context.lookupOffsets[contextMode + 1]; // Moved inside loop
    int huffTreeCommandIndex = hgroup[1]!.huffTrees[blockType[1]];

    while (metaBlockRemainingLen > 0) {
      if (blockLength[1] == 0) {
        decodeBlockType(numBlockTypes[1], blockTypeTrees, 1, blockType,
            blockTypeRb, blockTypeRbIndex, br);
        blockLength[1] =
            readBlockLength(blockLenTrees, huffmanMaxTableSize, br);
        huffTreeCommandIndex = hgroup[1]!.huffTrees[blockType[1]];
      }
      blockLength[1]--;

      final int cmdCode =
          readSymbol(hgroup[1]!.codes, huffTreeCommandIndex, br);

      // --- Decode cmdCode into insert/copy codes using reference algorithm ---
      int rangeIdx = cmdCode >> 6;
      // Compute distanceContextOffset: -4 for rangeIdx<2 (cmdCode<128), 0 for rangeIdx>=2 (cmdCode>=128)
      int distanceContextOffset = -4;
      if (rangeIdx >= 2) {
        rangeIdx -= 2;
        distanceContextOffset = 0;
      }
      // Magic numbers from reference implementation:
      // 0x29850 for insert, 0x26244 for copy
      final int insertLenCode = 
          (((0x29850 >> (rangeIdx * 2)) & 0x3) << 3) | ((cmdCode >> 3) & 7);
      final int copyLenCode = 
          (((0x26244 >> (rangeIdx * 2)) & 0x3) << 3) | (cmdCode & 7);

      if (insertLenCode >= kInsertLengthPrefixCode.length ||
          insertLenCode < 0) {
        throw Exception(
            "Invalid insert length code: $insertLenCode from cmd $cmdCode");
      }
      if (copyLenCode >= kCopyLengthPrefixCode.length || copyLenCode < 0) {
        throw Exception(
            "Invalid copy length code: $copyLenCode from cmd $cmdCode");
      }
      // --- End decode cmdCode ---

      final int insertNExtra = kInsertLengthPrefixCode[insertLenCode].nbits;
      final int insertLength = kInsertLengthPrefixCode[insertLenCode].offset +
          br.read_bits(insertNExtra);
      final int copyNExtra = kCopyLengthPrefixCode[copyLenCode].nbits;
      int copyLength =
          kCopyLengthPrefixCode[copyLenCode].offset + br.read_bits(copyNExtra);

      // --- Insert Literals ---
      int prevByte1 = (pos > 0) ? outputBuffer[pos - 1] : 0;
      int prevByte2 = (pos > 1) ? outputBuffer[pos - 2] : 0;
      for (int j = 0; j < insertLength; j++) {
        if (pos >= outputBuffer.length) _ensureOutputCapacity(outputBuffer, pos + 1);
        if (blockLength[0] == 0) {
          decodeBlockType(numBlockTypes[0], blockTypeTrees, 0, blockType,
              blockTypeRb, blockTypeRbIndex, br);
          blockLength[0] = readBlockLength(blockLenTrees, 0, br);
          contextMapSlice = blockType[0] << kLiteralContextBits;
          contextMode = contextModes[blockType[0]];
          // contextLookupOffset1 = Context.lookupOffsets[contextMode]; // Recalculate here
          // contextLookupOffset2 = Context.lookupOffsets[contextMode + 1]; // Recalculate here
        }
        blockLength[0]--;

        // --- FIX: Calculate context directly ---
        final int offset1 =
            Context.lookupOffsets[contextMode]; // contextMode is 0, 2, 4, 6
        final int offset2 = Context.lookupOffsets[contextMode + 1];
        // Bounds check indices before lookup
        final int index1 = offset1 + prevByte1;
        final int index2 = offset2 + prevByte2;
        if (index1 >= Context.lookup.length ||
            index1 < 0 ||
            index2 >= Context.lookup.length ||
            index2 < 0) {
          throw Exception(
              "Context lookup index out of bounds: mode=$contextMode p1=$prevByte1 p2=$prevByte2");
        }
        final int context = Context.lookup[index1] | Context.lookup[index2];
        // --- End FIX ---

        final int literalHuffTreeIndex = contextMap[contextMapSlice + context];
        final int literal = readSymbol(
            hgroup[0]!.codes, hgroup[0]!.huffTrees[literalHuffTreeIndex], br);
        outputBuffer[pos] = literal;
        prevByte2 = prevByte1;
        prevByte1 = literal;
        pos++;
      } // End insert loop

      metaBlockRemainingLen -= insertLength;
      if (metaBlockRemainingLen <= 0) break;

      // --- Handle Copy ---
      if (blockLength[2] == 0) {
        decodeBlockType(numBlockTypes[2], blockTypeTrees, 2, blockType,
            blockTypeRb, blockTypeRbIndex, br);
        blockLength[2] =
            readBlockLength(blockLenTrees, 2 * huffmanMaxTableSize, br);
        distContextMapSlice = blockType[2] << kDistanceContextBits;
      }
      blockLength[2]--;
      int distanceContext = (copyLength < 2)
          ? 0
          : (copyLength < 3)
              ? 1
              : (copyLength < 4)
                  ? 2
                  : 3;
      final int distHuffTreeIndex =
          distContextMap[distContextMapSlice + distanceContext];
      int distanceCode = readSymbol(
          hgroup[2]!.codes, hgroup[2]!.huffTrees[distHuffTreeIndex], br);

      if (distanceCode >= numDirectDistanceCodes) {
        int postfix = distanceCode & distancePostfixMask;
        int hc = (distanceCode - numDirectDistanceCodes) >> distancePostfixBits;
        int nbits = (hc >> 1) + 1;
        int offset = ((2 + (hc & 1)) << nbits) - 4;
        distanceCode = numDirectDistanceCodes +
            (((offset + br.read_bits(nbits)) << distancePostfixBits) + postfix);
      }

      int distance = translateShortCodes(distanceCode, distRb, distRbIdx);
      
      int currentMaxDistance =
          (pos < maxBackwardDistance) ? pos : maxBackwardDistance;

      if (distance > currentMaxDistance) {
        // Dictionary lookup
        int wordId = distance - currentMaxDistance - 1;
        int address = BrotliDictionary.findPos(copyLength, wordId);
        int transformId = BrotliDictionary.findTransform(wordId, copyLength);
        // Validate transformId against number of transforms (121 for RFC)
        if (address < 0 || transformId < 0 || transformId >= 121) {
          throw Exception("Invalid dictionary lookup: address=$address transformId=$transformId wordId=$wordId copyLength=$copyLength");
        }
        int roughEstimate = pos + copyLength + 30; // Increased estimate
        _ensureOutputCapacity(outputBuffer, roughEstimate);
        int transformLen = Transform.transformDictionaryWord(
            outputBuffer, pos, address, copyLength, transformId);
        _ensureOutputCapacity(outputBuffer, pos + transformLen);
        pos += transformLen;
        metaBlockRemainingLen -= transformLen;
      } else {
        // Standard backward copy
        if (distanceCode > 0) {
          distRb[distRbIdx & 3] = distance;
          distRbIdx++;
        }
        if (copyLength > metaBlockRemainingLen)
          throw Exception("Copy length exceeds remaining");
        _ensureOutputCapacity(outputBuffer, pos + copyLength);
        for (int j = 0; j < copyLength; j++) {
          outputBuffer[pos] = outputBuffer[pos - distance];
          pos++;
        }
        metaBlockRemainingLen -= copyLength;
      }
    } // End while metaBlockRemainingLen > 0
  } // End while !inputEnd

  if (outputBuffer.length > pos)
    outputBuffer.removeRange(pos, outputBuffer.length);
  return Uint8List.fromList(outputBuffer);
}
