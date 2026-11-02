
import 'dart:typed_data';
import 'state.dart';
import 'utils.dart';
import 'bit_reader.dart';
import 'brotli_error.dart';
import 'huffman.dart';
import 'context.dart';
import 'dictionary.dart';
import 'transform.dart';
import 'brotli_runtime_exception.dart';

/// API for Brotli decompression.
final class Decode {
  static const int minLargeWindowBits = 10;
  /* Maximum was chosen to be 30 to allow efficient decoder implementation.
   * Format allows bigger window, but Java does not support 2G+ arrays. */
  static const int maxLargeWindowBits = 30;

  //----------------------------------------------------------------------------
  // RunningState
  //----------------------------------------------------------------------------
  // NB: negative values are used for errors.
  static const int uninitialized = 0;
  static const int initialized = 1;
  static const int blockStart = 2;
  static const int compressedBlockStart = 3;
  static const int mainLoop = 4;
  static const int readMetadata = 5;
  static const int copyUncompressed = 6;
  static const int insertLoop = 7;
  static const int copyLoop = 8;
  static const int useDictionary = 9;
  static const int finished = 10;
  static const int closed = 11;
  static const int initWrite = 12;
  static const int write = 13;
  static const int copyFromCompoundDictionaryState = 14;

  static const int defaultCodeLength = 8;
  static const int codeLengthRepeatCode = 16;
  static const int numLiteralCodes = 256;
  static const int numCommandCodes = 704;
  static const int numBlockLengthCodes = 26;
  static const int literalContextBits = 6;
  static const int distanceContextBits = 2;

  static const int cdBlockMapBits = 8;
  static const int huffmanTableBits = 8;
  static const int huffmanTableMask = 0xFF;

  static final Int32List maxHuffmanTableSize = Int32List.fromList([
      256, 402, 436, 468, 500, 534, 566, 598, 630, 662, 694, 726, 758, 790, 822,
      854, 886, 920, 952, 984, 1016, 1048, 1080
  ]);

  static const int huffmanTableSize26 = 396;
  static const int huffmanTableSize258 = 632;

  static const int codeLengthCodes = 18;
  static final Int32List codeLengthCodeOrder = Int32List.fromList([
      1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  ]);

  static const int numDistanceShortCodes = 16;
  static final Int32List distanceShortCodeIndexOffset = Int32List.fromList([
    0, 3, 2, 1, 0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 3, 3
  ]);

  static final Int32List distanceShortCodeValueOffset = Int32List.fromList([
      0, 0, 0, 0, -1, 1, -2, 2, -3, 3, -1, 1, -2, 2, -3, 3
  ]);

  static final Int32List fixedTable = Int32List.fromList([
      0x020000, 0x020004, 0x020003, 0x030002, 0x020000, 0x020004, 0x020003, 0x040001,
      0x020000, 0x020004, 0x020003, 0x030002, 0x020000, 0x020004, 0x020003, 0x040005
  ]);

  static const int maxTransformedWordLength = 5 + 24 + 8;

  static const int maxDistanceBits = 24;
  static const int maxLargeWindowDistanceBits = 62;

  static const int maxAllowedDistance = 0x7FFFFFFC;

  static final Int32List blockLengthOffset = Int32List.fromList([
      1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497,
      753, 1265, 2289, 4337, 8433, 16625
  ]);

  static final Int32List blockLengthNBits = Int32List.fromList([
      2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24
  ]);

  static final Int16List insertLengthNBits = Int16List.fromList([
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x02, 0x03, 0x03,
      0x04, 0x04, 0x05, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0C, 0x0E, 0x18
  ]);

  static final Int16List copyLengthNBits = Int16List.fromList([
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x02,
      0x03, 0x03, 0x04, 0x04, 0x05, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x18
  ]);

  static final Int16List cmdLookup = _buildCommandLookup();

  static Int16List _buildCommandLookup() {
    final Int16List cmdLookup = Int16List(numCommandCodes * 4);
    unpackCommandLookupTable(cmdLookup);
    return cmdLookup;
  }

  static int log2floor(int i) {
    int result = -1;
    int step = 16;
    int v = i;
    while (step > 0) {
      int next = v >> step;
      if (next != 0) {
        result += step;
        v = next;
      }
      step = step >> 1;
    }
    return result + v;
  }

  static int calculateDistanceAlphabetSize(int npostfix, int ndirect, int maxndistbits) {
    return numDistanceShortCodes + ndirect + 2 * (maxndistbits << npostfix);
  }

  static int calculateDistanceAlphabetLimit(State s, int maxDistance, int npostfix, int ndirect) {
    if (maxDistance < ndirect + (2 << npostfix)) {
      return Utils.makeError(s, BrotliError.brotliPanicMaxDistanceTooSmall);
    }
    final int offset = ((maxDistance - ndirect) >> npostfix) + 4;
    final int ndistbits = log2floor(offset) - 1;
    final int group = ((ndistbits - 1) << 1) | ((offset >> ndistbits) & 1);
    return ((group - 1) << npostfix) + (1 << npostfix) + ndirect + numDistanceShortCodes;
  }

  static void unpackCommandLookupTable(Int16List cmdLookup) {
    final Int32List insertLengthOffsets = Int32List(24);
    final Int32List copyLengthOffsets = Int32List(24);
    copyLengthOffsets[0] = 2;
    for (int i = 0; i < 23; ++i) {
      insertLengthOffsets[i + 1] = insertLengthOffsets[i] + (1 << insertLengthNBits[i]);
      copyLengthOffsets[i + 1] = copyLengthOffsets[i] + (1 << copyLengthNBits[i]);
    }

    for (int cmdCode = 0; cmdCode < numCommandCodes; ++cmdCode) {
      int rangeIdx = cmdCode >> 6;
      int distanceContextOffset = -4;
      if (rangeIdx >= 2) {
        rangeIdx -= 2;
        distanceContextOffset = 0;
      }
      final int insertCode = (((0x29850 >> (rangeIdx * 2)) & 0x3) << 3) | ((cmdCode >> 3) & 7);
      final int copyCode = (((0x26244 >> (rangeIdx * 2)) & 0x3) << 3) | (cmdCode & 7);
      final int copyLengthOffset = copyLengthOffsets[copyCode];
      final int distanceContext = distanceContextOffset + Utils.min(copyLengthOffset, 5) - 2;
      final int index = cmdCode * 4;
      cmdLookup[index + 0] =
          (insertLengthNBits[insertCode] | (copyLengthNBits[copyCode] << 8));
      cmdLookup[index + 1] = insertLengthOffsets[insertCode];
      cmdLookup[index + 2] = copyLengthOffsets[copyCode];
      cmdLookup[index + 3] = distanceContext;
    }
  }

  static int decodeWindowBits(State s) {
    final int largeWindowEnabled = s.isLargeWindow;
    s.isLargeWindow = 0;

    BitReader.fillBitWindow(s);
    if (BitReader.readFewBits(s, 1) == 0) {
      return 16;
    }
    int n = BitReader.readFewBits(s, 3);
    if (n != 0) {
      return 17 + n;
    }
    n = BitReader.readFewBits(s, 3);
    if (n != 0) {
      if (n == 1) {
        if (largeWindowEnabled == 0) {
          return -1;
        }
        s.isLargeWindow = 1;
        if (BitReader.readFewBits(s, 1) == 1) {
          return -1;
        }
        n = BitReader.readFewBits(s, 6);
        if (n < minLargeWindowBits || n > maxLargeWindowBits) {
          return -1;
        }
        return n;
      }
      return 8 + n;
    }
    return 17;
  }

  static int enableEagerOutput(State s) {
    if (s.runningState != initialized) {
      return Utils.makeError(s, BrotliError.brotliPanicStateNotFresh);
    }
    s.isEager = 1;
    return BrotliError.brotliOk;
  }

  static int enableLargeWindow(State s) {
    if (s.runningState != initialized) {
      return Utils.makeError(s, BrotliError.brotliPanicStateNotFresh);
    }
    s.isLargeWindow = 1;
    return BrotliError.brotliOk;
  }

  static int attachDictionaryChunk(State s, Uint8List data) {
    if (s.runningState != initialized) {
      return Utils.makeError(s, BrotliError.brotliPanicStateNotFresh);
    }
    if (s.cdNumChunks == 0) {
      s.cdChunks = List.filled(16, Uint8List(0));
      s.cdChunkOffsets = Int32List(16);
      s.cdBlockBits = -1;
    }
    if (s.cdNumChunks == 15) {
      return Utils.makeError(s, BrotliError.brotliPanicTooManyDictionaryChunks);
    }
    s.cdChunks[s.cdNumChunks] = data;
    s.cdNumChunks++;
    s.cdTotalSize += data.length;
    s.cdChunkOffsets[s.cdNumChunks] = s.cdTotalSize;
    return BrotliError.brotliOk;
  }

  static int initState(State s) {
    if (s.runningState != uninitialized) {
      return Utils.makeError(s, BrotliError.brotliPanicStateNotUninitialized);
    }
    s.blockTrees = Int32List(7 + 3 * (huffmanTableSize258 + huffmanTableSize26));
    s.blockTrees[0] = 7;
    s.distRbIdx = 3;
    int result = calculateDistanceAlphabetLimit(s, maxAllowedDistance, 3, 15 << 3);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    final int maxDistanceAlphabetLimit = result;
    s.distExtraBits = Uint8List(maxDistanceAlphabetLimit);
    s.distOffset = Int32List(maxDistanceAlphabetLimit);
    result = BitReader.initBitReader(s);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    s.runningState = initialized;
    return BrotliError.brotliOk;
  }

  static int close(State s) {
    if (s.runningState == uninitialized) {
      return Utils.makeError(s, BrotliError.brotliPanicStateNotInitialized);
    }
    if (s.runningState > 0) {
      s.runningState = closed;
    }
    return BrotliError.brotliOk;
  }

  static int decodeVarLenUnsignedByte(State s) {
    BitReader.fillBitWindow(s);
    if (BitReader.readFewBits(s, 1) != 0) {
      final int n = BitReader.readFewBits(s, 3);
      if (n == 0) {
        return 1;
      }
      return BitReader.readFewBits(s, n) + (1 << n);
    }
    return 0;
  }

  static int decodeMetaBlockLength(State s) {
    BitReader.fillBitWindow(s);
    s.inputEnd = BitReader.readFewBits(s, 1);
    s.metaBlockLength = 0;
    s.isUncompressed = 0;
    s.isMetadata = 0;
    if ((s.inputEnd != 0) && BitReader.readFewBits(s, 1) != 0) {
      return BrotliError.brotliOk;
    }
    final int sizeNibbles = BitReader.readFewBits(s, 2) + 4;
    if (sizeNibbles == 7) {
      s.isMetadata = 1;
      if (BitReader.readFewBits(s, 1) != 0) {
        return Utils.makeError(s, BrotliError.brotliErrorCorruptedReservedBit);
      }
      final int sizeBytes = BitReader.readFewBits(s, 2);
      if (sizeBytes == 0) {
        return BrotliError.brotliOk;
      }
      for (int i = 0; i < sizeBytes; ++i) {
        BitReader.fillBitWindow(s);
        final int bits = BitReader.readFewBits(s, 8);
        if (bits == 0 && i + 1 == sizeBytes && sizeBytes > 1) {
          return Utils.makeError(s, BrotliError.brotliErrorExuberantNibble);
        }
        s.metaBlockLength += bits << (i * 8);
      }
    } else {
      for (int i = 0; i < sizeNibbles; ++i) {
        BitReader.fillBitWindow(s);
        final int bits = BitReader.readFewBits(s, 4);
        if (bits == 0 && i + 1 == sizeNibbles && sizeNibbles > 4) {
          return Utils.makeError(s, BrotliError.brotliErrorExuberantNibble);
        }
        s.metaBlockLength += bits << (i * 4);
      }
    }
    s.metaBlockLength++;
    if (s.inputEnd == 0) {
      s.isUncompressed = BitReader.readFewBits(s, 1);
    }
    return BrotliError.brotliOk;
  }

  static int readSymbol(Int32List tableGroup, int tableIdx, State s) {
    int offset = tableGroup[tableIdx];
    final int v = BitReader.peekBits(s);
    offset += v & huffmanTableMask;
    final int bits = tableGroup[offset] >> 16;
    final int sym = tableGroup[offset] & 0xFFFF;
    if (bits <= huffmanTableBits) {
      s.bitOffset += bits;
      return sym;
    }
    offset += sym;
    final int mask = (1 << bits) - 1;
    offset += Utils.shr32(v & mask, huffmanTableBits);
    s.bitOffset += ((tableGroup[offset] >> 16) + huffmanTableBits);
    return tableGroup[offset] & 0xFFFF;
  }

  static int readBlockLength(Int32List tableGroup, int tableIdx, State s) {
    BitReader.fillBitWindow(s);
    final int code = readSymbol(tableGroup, tableIdx, s);
    final int n = blockLengthNBits[code];
    BitReader.fillBitWindow(s);
    return blockLengthOffset[code] + BitReader.readBits(s, n);
  }

  static void moveToFront(Int32List v, int index) {
    int i = index;
    final int value = v[i];
    while (i > 0) {
      v[i] = v[i - 1];
      i--;
    }
    v[0] = value;
  }

  static void inverseMoveToFrontTransform(Uint8List v, int vLen) {
    final Int32List mtf = Int32List(256);
    for (int i = 0; i < 256; ++i) {
      mtf[i] = i;
    }
    for (int i = 0; i < vLen; ++i) {
      final int index = v[i] & 0xFF;
      v[i] = mtf[index];
      if (index != 0) {
        moveToFront(mtf, index);
      }
    }
  }

  static int readHuffmanCodeLengths(
      Int32List codeLengthCodeLengths, int numSymbols, Int32List codeLengths, State s) {
    int symbol = 0;
    int prevCodeLen = defaultCodeLength;
    int repeat = 0;
    int repeatCodeLen = 0;
    int space = 32768;
    final Int32List table = Int32List(32 + 1);
    final int tableIdx = table.length - 1;
    Huffman.buildHuffmanTable(table, tableIdx, 5, codeLengthCodeLengths, codeLengthCodes);

    while (symbol < numSymbols && space > 0) {
      if (s.halfOffset > BitReader.halfWaterline) {
        final int result = BitReader.readMoreInput(s);
        if (result < BrotliError.brotliOk) {
          return result;
        }
      }
      BitReader.fillBitWindow(s);
      final int p = BitReader.peekBits(s) & 31;
      s.bitOffset += table[p] >> 16;
      final int codeLen = table[p] & 0xFFFF;
      if (codeLen < codeLengthRepeatCode) {
        repeat = 0;
        codeLengths[symbol++] = codeLen;
        if (codeLen != 0) {
          prevCodeLen = codeLen;
          space -= 32768 >> codeLen;
        }
      } else {
        final int extraBits = codeLen - 14;
        int newLen = 0;
        if (codeLen == codeLengthRepeatCode) {
          newLen = prevCodeLen;
        }
        if (repeatCodeLen != newLen) {
          repeat = 0;
          repeatCodeLen = newLen;
        }
        final int oldRepeat = repeat;
        if (repeat > 0) {
          repeat -= 2;
          repeat = repeat << extraBits;
        }
        BitReader.fillBitWindow(s);
        repeat += BitReader.readFewBits(s, extraBits) + 3;
        final int repeatDelta = repeat - oldRepeat;
        if (symbol + repeatDelta > numSymbols) {
          return Utils.makeError(s, BrotliError.brotliErrorCorruptedCodeLengthTable);
        }
        for (int i = 0; i < repeatDelta; ++i) {
          codeLengths[symbol++] = repeatCodeLen;
        }
        if (repeatCodeLen != 0) {
          space -= repeatDelta << (15 - repeatCodeLen);
        }
      }
    }
    if (space != 0) {
      return Utils.makeError(s, BrotliError.brotliErrorUnusedHuffmanSpace);
    }
    Utils.fillIntsWithZeroes(codeLengths, symbol, numSymbols);
    return BrotliError.brotliOk;
  }

  static int checkDupes(State s, Int32List symbols, int length) {
    for (int i = 0; i < length - 1; ++i) {
      for (int j = i + 1; j < length; ++j) {
        if (symbols[i] == symbols[j]) {
          return Utils.makeError(s, BrotliError.brotliErrorDuplicateSimpleHuffmanSymbol);
        }
      }
    }
    return BrotliError.brotliOk;
  }

  static int readSimpleHuffmanCode(int alphabetSizeMax, int alphabetSizeLimit,
      Int32List tableGroup, int tableIdx, State s) {
    final Int32List codeLengths = Int32List(alphabetSizeLimit);
    final Int32List symbols = Int32List(4);

    final int maxBits = 1 + log2floor(alphabetSizeMax - 1);

    final int numSymbols = BitReader.readFewBits(s, 2) + 1;
    for (int i = 0; i < numSymbols; ++i) {
      BitReader.fillBitWindow(s);
      final int symbol = BitReader.readFewBits(s, maxBits);
      if (symbol >= alphabetSizeLimit) {
        return Utils.makeError(s, BrotliError.brotliErrorSymbolOutOfRange);
      }
      symbols[i] = symbol;
    }
    final int result = checkDupes(s, symbols, numSymbols);
    if (result < BrotliError.brotliOk) {
      return result;
    }

    int histogramId = numSymbols;
    if (numSymbols == 4) {
      histogramId += BitReader.readFewBits(s, 1);
    }

    switch (histogramId) {
      case 1:
        codeLengths[symbols[0]] = 1;
        break;

      case 2:
        codeLengths[symbols[0]] = 1;
        codeLengths[symbols[1]] = 1;
        break;

      case 3:
        codeLengths[symbols[0]] = 1;
        codeLengths[symbols[1]] = 2;
        codeLengths[symbols[2]] = 2;
        break;

      case 4:
        codeLengths[symbols[0]] = 2;
        codeLengths[symbols[1]] = 2;
        codeLengths[symbols[2]] = 2;
        codeLengths[symbols[3]] = 2;
        break;

      case 5:
        codeLengths[symbols[0]] = 1;
        codeLengths[symbols[1]] = 2;
        codeLengths[symbols[2]] = 3;
        codeLengths[symbols[3]] = 3;
        break;

      default:
        break;
    }

    return Huffman.buildHuffmanTable(
        tableGroup, tableIdx, huffmanTableBits, codeLengths, alphabetSizeLimit);
  }

  static int readComplexHuffmanCode(int alphabetSizeLimit, int skip,
      Int32List tableGroup, int tableIdx, State s) {
    final Int32List codeLengths = Int32List(alphabetSizeLimit);
    final Int32List codeLengthCodeLengths = Int32List(codeLengthCodes);
    int space = 32;
    int numCodes = 0;
    for (int i = skip; i < codeLengthCodes; ++i) {
      final int codeLenIdx = codeLengthCodeOrder[i];
      BitReader.fillBitWindow(s);
      final int p = BitReader.peekBits(s) & 15;
      s.bitOffset += fixedTable[p] >> 16;
      final int v = fixedTable[p] & 0xFFFF;
      codeLengthCodeLengths[codeLenIdx] = v;
      if (v != 0) {
        space -= (32 >> v);
        numCodes++;
        if (space <= 0) {
          break;
        }
      }
    }
    if (space != 0 && numCodes != 1) {
      return Utils.makeError(s, BrotliError.brotliErrorCorruptedHuffmanCodeHistogram);
    }

    final int result = readHuffmanCodeLengths(codeLengthCodeLengths, alphabetSizeLimit, codeLengths, s);
    if (result < BrotliError.brotliOk) {
      return result;
    }

    return Huffman.buildHuffmanTable(
        tableGroup, tableIdx, huffmanTableBits, codeLengths, alphabetSizeLimit);
  }

  static int readHuffmanCode(int alphabetSizeMax, int alphabetSizeLimit,
      Int32List tableGroup, int tableIdx, State s) {
    if (s.halfOffset > BitReader.halfWaterline) {
      final int result = BitReader.readMoreInput(s);
      if (result < BrotliError.brotliOk) {
        return result;
      }
    }
    BitReader.fillBitWindow(s);
    final int simpleCodeOrSkip = BitReader.readFewBits(s, 2);
    if (simpleCodeOrSkip == 1) {
      return readSimpleHuffmanCode(alphabetSizeMax, alphabetSizeLimit, tableGroup, tableIdx, s);
    }
    return readComplexHuffmanCode(alphabetSizeLimit, simpleCodeOrSkip, tableGroup, tableIdx, s);
  }

  static int decodeContextMap(int contextMapSize, Uint8List contextMap, State s) {
    int result;
    if (s.halfOffset > BitReader.halfWaterline) {
      result = BitReader.readMoreInput(s);
      if (result < BrotliError.brotliOk) {
        return result;
      }
    }
    final int numTrees = decodeVarLenUnsignedByte(s) + 1;

    if (numTrees == 1) {
      Utils.fillBytesWithZeroes(contextMap, 0, contextMapSize);
      return numTrees;
    }

    BitReader.fillBitWindow(s);
    final int useRleForZeros = BitReader.readFewBits(s, 1);
    int maxRunLengthPrefix = 0;
    if (useRleForZeros != 0) {
      maxRunLengthPrefix = BitReader.readFewBits(s, 4) + 1;
    }
    final int alphabetSize = numTrees + maxRunLengthPrefix;
    final int tableSize = maxHuffmanTableSize[(alphabetSize + 31) >> 5];
    final Int32List table = Int32List(tableSize + 1);
    final int tableIdx = table.length - 1;
    result = readHuffmanCode(alphabetSize, alphabetSize, table, tableIdx, s);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    int i = 0;
    while (i < contextMapSize) {
      if (s.halfOffset > BitReader.halfWaterline) {
        result = BitReader.readMoreInput(s);
        if (result < BrotliError.brotliOk) {
          return result;
        }
      }
      BitReader.fillBitWindow(s);
      final int code = readSymbol(table, tableIdx, s);
      if (code == 0) {
        contextMap[i] = 0;
        i++;
      } else if (code <= maxRunLengthPrefix) {
        BitReader.fillBitWindow(s);
        int reps = (1 << code) + BitReader.readFewBits(s, code);
        while (reps != 0) {
          if (i >= contextMapSize) {
            return Utils.makeError(s, BrotliError.brotliErrorCorruptedContextMap);
          }
          contextMap[i] = 0;
          i++;
          reps--;
        }
      } else {
        contextMap[i] = (code - maxRunLengthPrefix);
        i++;
      }
    }
    BitReader.fillBitWindow(s);
    if (BitReader.readFewBits(s, 1) == 1) {
      inverseMoveToFrontTransform(contextMap, contextMapSize);
    }
    return numTrees;
  }

  static int decodeBlockTypeAndLength(State s, int treeType, int numBlockTypes) {
    final Int32List ringBuffers = s.rings;
    final int offset = 4 + treeType * 2;
    BitReader.fillBitWindow(s);
    int blockType = readSymbol(s.blockTrees, 2 * treeType, s);
    final int result = readBlockLength(s.blockTrees, 2 * treeType + 1, s);

    if (blockType == 1) {
      blockType = ringBuffers[offset + 1] + 1;
    } else if (blockType == 0) {
      blockType = ringBuffers[offset];
    } else {
      blockType -= 2;
    }
    if (blockType >= numBlockTypes) {
      blockType -= numBlockTypes;
    }
    ringBuffers[offset] = ringBuffers[offset + 1];
    ringBuffers[offset + 1] = blockType;
    return result;
  }

  static void decodeLiteralBlockSwitch(State s) {
    s.literalBlockLength = decodeBlockTypeAndLength(s, 0, s.numLiteralBlockTypes);
    final int literalBlockType = s.rings[5];
    s.contextMapSlice = literalBlockType << literalContextBits;
    s.literalTreeIdx = s.contextMap[s.contextMapSlice] & 0xFF;
    final int contextMode = s.contextModes[literalBlockType];
    s.contextLookupOffset1 = contextMode << 9;
    s.contextLookupOffset2 = s.contextLookupOffset1 + 256;
  }

  static void decodeCommandBlockSwitch(State s) {
    s.commandBlockLength = decodeBlockTypeAndLength(s, 1, s.numCommandBlockTypes);
    s.commandTreeIdx = s.rings[7];
  }

  static void decodeDistanceBlockSwitch(State s) {
    s.distanceBlockLength = decodeBlockTypeAndLength(s, 2, s.numDistanceBlockTypes);
    s.distContextMapSlice = s.rings[9] << distanceContextBits;
  }

  static void maybeReallocateRingBuffer(State s) {
    int newSize = s.maxRingBufferSize;
    if (newSize > s.expectedTotalSize) {
      final int minimalNewSize = s.expectedTotalSize;
      while ((newSize >> 1) > minimalNewSize) {
        newSize = newSize >> 1;
      }
      if ((s.inputEnd == 0) && newSize < 16384 && s.maxRingBufferSize >= 16384) {
        newSize = 16384;
      }
    }
    if (newSize <= s.ringBufferSize) {
      return;
    }
    final int ringBufferSizeWithSlack = newSize + maxTransformedWordLength;
    final Uint8List newBuffer = Uint8List(ringBufferSizeWithSlack);
    final Uint8List oldBuffer = s.ringBuffer;
    if (oldBuffer.isNotEmpty) {
      Utils.copyBytes(newBuffer, 0, oldBuffer, 0, s.ringBufferSize);
    }
    s.ringBuffer = newBuffer;
    s.ringBufferSize = newSize;
  }

  static int readNextMetablockHeader(State s) {
    if (s.inputEnd != 0) {
      s.nextRunningState = finished;
      s.runningState = initWrite;
      return BrotliError.brotliOk;
    }
    s.literalTreeGroup = Int32List(0);
    s.commandTreeGroup = Int32List(0);
    s.distanceTreeGroup = Int32List(0);

    int result;
    if (s.halfOffset > BitReader.halfWaterline) {
      result = BitReader.readMoreInput(s);
      if (result < BrotliError.brotliOk) {
        return result;
      }
    }
    result = decodeMetaBlockLength(s);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    if ((s.metaBlockLength == 0) && (s.isMetadata == 0)) {
      return BrotliError.brotliOk;
    }
    if ((s.isUncompressed != 0) || (s.isMetadata != 0)) {
      result = BitReader.jumpToByteBoundary(s);
      if (result < BrotliError.brotliOk) {
        return result;
      }
      if (s.isMetadata == 0) {
        s.runningState = copyUncompressed;
      } else {
        s.runningState = readMetadata;
      }
    } else {
      s.runningState = compressedBlockStart;
    }

    if (s.isMetadata != 0) {
      return BrotliError.brotliOk;
    }
    s.expectedTotalSize += s.metaBlockLength;
    if (s.expectedTotalSize > 1 << 30) {
      s.expectedTotalSize = 1 << 30;
    }
    if (s.ringBufferSize < s.maxRingBufferSize) {
      maybeReallocateRingBuffer(s);
    }
    return BrotliError.brotliOk;
  }

  static int readMetablockPartition(State s, int treeType, int numBlockTypes) {
    int offset = s.blockTrees[2 * treeType];
    if (numBlockTypes <= 1) {
      s.blockTrees[2 * treeType + 1] = offset;
      s.blockTrees[2 * treeType + 2] = offset;
      return 1 << 28;
    }

    final int blockTypeAlphabetSize = numBlockTypes + 2;
    int result = readHuffmanCode(
        blockTypeAlphabetSize, blockTypeAlphabetSize, s.blockTrees, 2 * treeType, s);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    offset += result;
    s.blockTrees[2 * treeType + 1] = offset;

    final int blockLengthAlphabetSize = numBlockLengthCodes;
    result = readHuffmanCode(
        blockLengthAlphabetSize, blockLengthAlphabetSize, s.blockTrees, 2 * treeType + 1, s);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    offset += result;
    s.blockTrees[2 * treeType + 2] = offset;

    return readBlockLength(s.blockTrees, 2 * treeType + 1, s);
  }

  static void calculateDistanceLut(State s, int alphabetSizeLimit) {
    final Uint8List distExtraBits = s.distExtraBits;
    final Int32List distOffset = s.distOffset;
    final int npostfix = s.distancePostfixBits;
    final int ndirect = s.numDirectDistanceCodes;
    final int postfix = 1 << npostfix;
    int bits = 1;
    int half = 0;

    int i = numDistanceShortCodes;

    for (int j = 0; j < ndirect; ++j) {
      distExtraBits[i] = 0;
      distOffset[i] = j + 1;
      ++i;
    }

    while (i < alphabetSizeLimit) {
      final int base = ndirect + ((((2 + half) << bits) - 4) << npostfix) + 1;
      for (int j = 0; j < postfix; ++j) {
        distExtraBits[i] = bits;
        distOffset[i] = base + j;
        ++i;
      }
      bits = bits + half;
      half = half ^ 1;
    }
  }

  static int readMetablockHuffmanCodesAndContextMaps(State s) {
    s.numLiteralBlockTypes = decodeVarLenUnsignedByte(s) + 1;
    int result = readMetablockPartition(s, 0, s.numLiteralBlockTypes);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    s.literalBlockLength = result;
    s.numCommandBlockTypes = decodeVarLenUnsignedByte(s) + 1;
    result = readMetablockPartition(s, 1, s.numCommandBlockTypes);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    s.commandBlockLength = result;
    s.numDistanceBlockTypes = decodeVarLenUnsignedByte(s) + 1;
    result = readMetablockPartition(s, 2, s.numDistanceBlockTypes);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    s.distanceBlockLength = result;

    if (s.halfOffset > BitReader.halfWaterline) {
      result = BitReader.readMoreInput(s);
      if (result < BrotliError.brotliOk) {
        return result;
      }
    }
    BitReader.fillBitWindow(s);
    s.distancePostfixBits = BitReader.readFewBits(s, 2);
    s.numDirectDistanceCodes = BitReader.readFewBits(s, 4) << s.distancePostfixBits;
    s.contextModes = Uint8List(s.numLiteralBlockTypes);
    int i = 0;
    while (i < s.numLiteralBlockTypes) {
      final int limit = Utils.min(i + 96, s.numLiteralBlockTypes);
      while (i < limit) {
        BitReader.fillBitWindow(s);
        s.contextModes[i] = BitReader.readFewBits(s, 2);
        i++;
      }
      if (s.halfOffset > BitReader.halfWaterline) {
        result = BitReader.readMoreInput(s);
        if (result < BrotliError.brotliOk) {
          return result;
        }
      }
    }

    final int contextMapLength = s.numLiteralBlockTypes << literalContextBits;
    s.contextMap = Uint8List(contextMapLength);
    result = decodeContextMap(contextMapLength, s.contextMap, s);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    final int numLiteralTrees = result;
    s.trivialLiteralContext = 1;
    for (int j = 0; j < contextMapLength; ++j) {
      if (s.contextMap[j] != j >> literalContextBits) {
        s.trivialLiteralContext = 0;
        break;
      }
    }

    s.distContextMap = Uint8List(s.numDistanceBlockTypes << distanceContextBits);
    result = decodeContextMap(s.numDistanceBlockTypes << distanceContextBits,
        s.distContextMap, s);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    final int numDistTrees = result;

    s.literalTreeGroup = Int32List(huffmanTreeGroupAllocSize(numLiteralCodes, numLiteralTrees));
    result = decodeHuffmanTreeGroup(
        numLiteralCodes, numLiteralCodes, numLiteralTrees, s, s.literalTreeGroup);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    s.commandTreeGroup =
        Int32List(huffmanTreeGroupAllocSize(numCommandCodes, s.numCommandBlockTypes));
    result = decodeHuffmanTreeGroup(
        numCommandCodes, numCommandCodes, s.numCommandBlockTypes, s, s.commandTreeGroup);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    int distanceAlphabetSizeMax = calculateDistanceAlphabetSize(
        s.distancePostfixBits, s.numDirectDistanceCodes, maxDistanceBits);
    int distanceAlphabetSizeLimit = distanceAlphabetSizeMax;
    if (s.isLargeWindow == 1) {
      distanceAlphabetSizeMax = calculateDistanceAlphabetSize(
          s.distancePostfixBits, s.numDirectDistanceCodes, maxLargeWindowDistanceBits);
      result = calculateDistanceAlphabetLimit(
          s, maxAllowedDistance, s.distancePostfixBits, s.numDirectDistanceCodes);
      if (result < BrotliError.brotliOk) {
        return result;
      }
      distanceAlphabetSizeLimit = result;
    }
    s.distanceTreeGroup =
        Int32List(huffmanTreeGroupAllocSize(distanceAlphabetSizeLimit, numDistTrees));
    result = decodeHuffmanTreeGroup(
        distanceAlphabetSizeMax, distanceAlphabetSizeLimit, numDistTrees, s, s.distanceTreeGroup);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    calculateDistanceLut(s, distanceAlphabetSizeLimit);

    s.contextMapSlice = 0;
    s.distContextMapSlice = 0;
    s.contextLookupOffset1 = s.contextModes[0] * 512;
    s.contextLookupOffset2 = s.contextLookupOffset1 + 256;
    s.literalTreeIdx = 0;
    s.commandTreeIdx = 0;

    s.rings[4] = 1;
    s.rings[5] = 0;
    s.rings[6] = 1;
    s.rings[7] = 0;
    s.rings[8] = 1;
    s.rings[9] = 0;
    return BrotliError.brotliOk;
  }

  static int copyUncompressedData(State s) {
    final Uint8List ringBuffer = s.ringBuffer;
    int result;

    if (s.metaBlockLength <= 0) {
      result = BitReader.reload(s);
      if (result < BrotliError.brotliOk) {
        return result;
      }
      s.runningState = blockStart;
      return BrotliError.brotliOk;
    }

    final int chunkLength = Utils.min(s.ringBufferSize - s.pos, s.metaBlockLength);
    result = BitReader.copyRawBytes(s, ringBuffer, s.pos, chunkLength);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    s.metaBlockLength -= chunkLength;
    s.pos += chunkLength;
    if (s.pos == s.ringBufferSize) {
        s.nextRunningState = copyUncompressed;
        s.runningState = initWrite;
        return BrotliError.brotliOk;
      }

    result = BitReader.reload(s);
    if (result < BrotliError.brotliOk) {
      return result;
    }
    s.runningState = blockStart;
    return BrotliError.brotliOk;
  }

  static int writeRingBuffer(State s) {
    final int toWrite = Utils.min(s.outputLength - s.outputUsed,
        s.ringBufferBytesReady - s.ringBufferBytesWritten);
    if (toWrite != 0) {
      Utils.copyBytes(s.output, s.outputOffset + s.outputUsed, s.ringBuffer,
          s.ringBufferBytesWritten, s.ringBufferBytesWritten + toWrite);
      s.outputUsed += toWrite;
      s.ringBufferBytesWritten += toWrite;
    }

    if (s.outputUsed < s.outputLength) {
      return BrotliError.brotliOk;
    }
    return BrotliError.brotliOkNeedMoreOutput;
  }

  static int huffmanTreeGroupAllocSize(int alphabetSizeLimit, int n) {
    final int maxTableSize = maxHuffmanTableSize[(alphabetSizeLimit + 31) >> 5];
    return n + n * maxTableSize;
  }

  static int decodeHuffmanTreeGroup(int alphabetSizeMax, int alphabetSizeLimit,
      int n, State s, Int32List group) {
    int next = n;
    for (int i = 0; i < n; ++i) {
      group[i] = next;
      final int result = readHuffmanCode(alphabetSizeMax, alphabetSizeLimit, group, i, s);
      if (result < BrotliError.brotliOk) {
        return result;
      }
      next += result;
    }
    return BrotliError.brotliOk;
  }

  static int calculateFence(State s) {
    int result = s.ringBufferSize;
    if (s.isEager != 0) {
      result = Utils.min(result, s.ringBufferBytesWritten + s.outputLength - s.outputUsed);
    }
    return result;
  }

  static int doUseDictionary(State s, int fence) {
    if (s.distance > maxAllowedDistance) {
      return Utils.makeError(s, BrotliError.brotliErrorInvalidBackwardReference);
    }
    final int address = s.distance - s.maxDistance - 1 - s.cdTotalSize;
    if (address < 0) {
      final int result = initializeCompoundDictionaryCopy(s, -address - 1, s.copyLength);
      if (result < BrotliError.brotliOk) {
        return result;
      }
      s.runningState = copyFromCompoundDictionaryState;
    } else {
      final Uint8List dictionaryData = Dictionary.getData();
      final int wordLength = s.copyLength;
      if (wordLength > Dictionary.maxDictionaryWordLength) {
        return Utils.makeError(s, BrotliError.brotliErrorInvalidBackwardReference);
      }
      final int shift = Dictionary.sizeBits[wordLength];
      if (shift == 0) {
        return Utils.makeError(s, BrotliError.brotliErrorInvalidBackwardReference);
      }
      int offset = Dictionary.offsets[wordLength];
      final int mask = (1 << shift) - 1;
      final int wordIdx = address & mask;
      final int transformIdx = address >> shift;
      offset += wordIdx * wordLength;
      final Transforms transforms = Transform.rfcTransforms;
      if (transformIdx >= transforms.numTransforms) {
        return Utils.makeError(s, BrotliError.brotliErrorInvalidBackwardReference);
      }
      final int len = Transform.transformDictionaryWord(s.ringBuffer, s.pos, dictionaryData,
          offset, wordLength, transforms, transformIdx);
      s.pos += len;
      s.metaBlockLength -= len;
      if (s.pos >= fence) {
        s.nextRunningState = mainLoop;
        s.runningState = initWrite;
        return BrotliError.brotliOk;
      }
      s.runningState = mainLoop;
    }
    return BrotliError.brotliOk;
  }

  static void initializeCompoundDictionary(State s) {
    s.cdBlockMap = Uint8List(1 << cdBlockMapBits);
    int blockBits = cdBlockMapBits;
    while (((s.cdTotalSize - 1) >> blockBits) != 0) {
      blockBits++;
    }
    blockBits -= cdBlockMapBits;
    s.cdBlockBits = blockBits;
    int cursor = 0;
    int index = 0;
    while (cursor < s.cdTotalSize) {
      while (s.cdChunkOffsets[index + 1] < cursor) {
        index++;
      }
      s.cdBlockMap[cursor >> blockBits] = index;
      cursor += 1 << blockBits;
    }
  }

  static int initializeCompoundDictionaryCopy(State s, int address, int length) {
    if (s.cdBlockBits == -1) {
      initializeCompoundDictionary(s);
    }
    int index = s.cdBlockMap[address >> s.cdBlockBits];
    while (address >= s.cdChunkOffsets[index + 1]) {
      index++;
    }
    if (s.cdTotalSize > address + length) {
      return Utils.makeError(s, BrotliError.brotliErrorInvalidBackwardReference);
    }
    s.distRbIdx = (s.distRbIdx + 1) & 0x3;
    s.rings[s.distRbIdx] = s.distance;
    s.metaBlockLength -= length;
    s.cdBrIndex = index;
    s.cdBrOffset = address - s.cdChunkOffsets[index];
    s.cdBrLength = length;
    s.cdBrCopied = 0;
    return BrotliError.brotliOk;
  }

  static int copyFromCompoundDictionary(State s, int fence) {
    int pos = s.pos;
    final int origPos = pos;
    while (s.cdBrLength != s.cdBrCopied) {
      final int space = fence - pos;
      final int chunkLength = s.cdChunkOffsets[s.cdBrIndex + 1] - s.cdChunkOffsets[s.cdBrIndex];
      final int remChunkLength = chunkLength - s.cdBrOffset;
      int length = s.cdBrLength - s.cdBrCopied;
      if (length > remChunkLength) {
        length = remChunkLength;
      }
      if (length > space) {
        length = space;
      }
      Utils.copyBytes(
          s.ringBuffer, pos, s.cdChunks[s.cdBrIndex], s.cdBrOffset, s.cdBrOffset + length);
      pos += length;
      s.cdBrOffset += length;
      s.cdBrCopied += length;
      if (length == remChunkLength) {
        s.cdBrIndex++;
        s.cdBrOffset = 0;
      }
      if (pos >= fence) {
        break;
      }
    }
    return pos - origPos;
  }

  static int decompress(State s) {
    int result;
    if (s.runningState == uninitialized) {
      return Utils.makeError(s, BrotliError.brotliPanicStateNotInitialized);
    }
    if (s.runningState < 0) {
      return Utils.makeError(s, BrotliError.brotliPanicUnexpectedState);
    }
    if (s.runningState == closed) {
      return Utils.makeError(s, BrotliError.brotliPanicAlreadyClosed);
    }
    if (s.runningState == initialized) {
      final int windowBits = decodeWindowBits(s);
      if (windowBits == -1) {
        return Utils.makeError(s, BrotliError.brotliErrorInvalidWindowBits);
      }
      s.maxRingBufferSize = 1 << windowBits;
      s.maxBackwardDistance = s.maxRingBufferSize - 16;
      s.runningState = blockStart;
    }

    int fence = calculateFence(s);
    int ringBufferMask = s.ringBufferSize - 1;
    Uint8List ringBuffer = s.ringBuffer;

    while (s.runningState != finished) {
      switch (s.runningState) {
        case blockStart:
          if (s.metaBlockLength < 0) {
            return Utils.makeError(s, BrotliError.brotliErrorInvalidMetablockLength);
          }
          result = readNextMetablockHeader(s);
          if (result < BrotliError.brotliOk) {
            return result;
          }
          fence = calculateFence(s);
          ringBufferMask = s.ringBufferSize - 1;
          ringBuffer = s.ringBuffer;
          continue;

        case compressedBlockStart: {
          result = readMetablockHuffmanCodesAndContextMaps(s);
          if (result < BrotliError.brotliOk) {
            return result;
          }
          s.runningState = mainLoop;
          continue;
        }

        case mainLoop:
          if (s.metaBlockLength <= 0) {
            s.runningState = blockStart;
            continue;
          }
          if (s.halfOffset > BitReader.halfWaterline) {
            result = BitReader.readMoreInput(s);
            if (result < BrotliError.brotliOk) {
              return result;
            }
          }
          if (s.commandBlockLength == 0) {
            decodeCommandBlockSwitch(s);
          }
          s.commandBlockLength--;
            BitReader.fillBitWindow(s);
            final int commandSymbol = readSymbol(s.commandTreeGroup, s.commandTreeIdx, s);
          
            final int cmdCode = commandSymbol << 2;
            final int insertAndCopyExtraBits = cmdLookup[cmdCode];
          
          final int insertLengthOffset = cmdLookup[cmdCode + 1];
          final int copyLengthOffset = cmdLookup[cmdCode + 2];
          s.distanceCode = cmdLookup[cmdCode + 3];
          BitReader.fillBitWindow(s);
          {
            final int insertLengthExtraBits = insertAndCopyExtraBits & 0xFF;
            // OPTIMIZATION: Could mask unnecessary bits but readBits handles this
            // if (insertLengthExtraBits > 0) {
            //   final int mask = (1 << insertLengthExtraBits) - 1;
            // }
            final int insertExtraValueRead = BitReader.readBits(s, insertLengthExtraBits);
            s.insertLength = insertLengthOffset + insertExtraValueRead;
          }
          BitReader.fillBitWindow(s);
          {
            final int copyLengthExtraBits = insertAndCopyExtraBits >> 8;
            s.copyLength = copyLengthOffset + BitReader.readBits(s, copyLengthExtraBits);
           
          }

          s.j = 0;
          s.runningState = insertLoop;
          continue;

        case insertLoop:
          if (s.trivialLiteralContext != 0) {
            while (s.j < s.insertLength) {
              if (s.halfOffset > BitReader.halfWaterline) {
                result = BitReader.readMoreInput(s);
                if (result < BrotliError.brotliOk) {
                  return result;
                }
              }
              if (s.literalBlockLength == 0) {
                decodeLiteralBlockSwitch(s);
              }
              s.literalBlockLength--;
              BitReader.fillBitWindow(s);
              ringBuffer[s.pos] = readSymbol(s.literalTreeGroup, s.literalTreeIdx, s);
              s.pos++;
              s.j++;
              if (s.pos >= fence) {
                s.nextRunningState = insertLoop;
                s.runningState = initWrite;
                break;
              }
            }
          } else {
            int prevByte1 = ringBuffer[(s.pos - 1) & ringBufferMask] & 0xFF;
            int prevByte2 = ringBuffer[(s.pos - 2) & ringBufferMask] & 0xFF;
            while (s.j < s.insertLength) {
              if (s.halfOffset > BitReader.halfWaterline) {
                result = BitReader.readMoreInput(s);
                if (result < BrotliError.brotliOk) {
                  return result;
                }
              }
              if (s.literalBlockLength == 0) {
                decodeLiteralBlockSwitch(s);
              }
              final int literalContext = Context.lookup[s.contextLookupOffset1 + prevByte1]
                  | Context.lookup[s.contextLookupOffset2 + prevByte2];
              final int literalTreeIdx =
                  s.contextMap[s.contextMapSlice + literalContext] & 0xFF;
              s.literalBlockLength--;
              prevByte2 = prevByte1;
              BitReader.fillBitWindow(s);
              prevByte1 = readSymbol(s.literalTreeGroup, literalTreeIdx, s);
              ringBuffer[s.pos] = prevByte1;
              s.pos++;
              s.j++;
              if (s.pos >= fence) {
                s.nextRunningState = insertLoop;
                s.runningState = initWrite;
                break;
              }
            }
          }
          if (s.runningState != insertLoop) {
            continue;
          }
          final int remainingAfterInsert = s.metaBlockLength - s.insertLength;
          if (remainingAfterInsert < 0) {
           
          }
          s.metaBlockLength = remainingAfterInsert;
          if (s.metaBlockLength <= 0) {
            s.runningState = mainLoop;
            continue;
          }
          int distanceCode = s.distanceCode;
          if (distanceCode < 0) {
            s.distance = s.rings[s.distRbIdx];
            
          } else {
            if (s.halfOffset > BitReader.halfWaterline) {
              result = BitReader.readMoreInput(s);
              if (result < BrotliError.brotliOk) {
                return result;
              }
            }
            if (s.distanceBlockLength == 0) {
              decodeDistanceBlockSwitch(s);
            }
            s.distanceBlockLength--;
            BitReader.fillBitWindow(s);
            final int distTreeIdx =
                s.distContextMap[s.distContextMapSlice + distanceCode] & 0xFF;
            distanceCode = readSymbol(s.distanceTreeGroup, distTreeIdx, s);

            if (distanceCode < numDistanceShortCodes) {
              final int index =
                  (s.distRbIdx + distanceShortCodeIndexOffset[distanceCode]) & 0x3;
              s.distance = s.rings[index] + distanceShortCodeValueOffset[distanceCode];
             
              if (s.distance < 0) {
                return Utils.makeError(s, BrotliError.brotliErrorNegativeDistance);
              }
            } else {
              final int extraBits = s.distExtraBits[distanceCode];
              int bits;
              if (s.bitOffset + extraBits <= BitReader.bitness) {
                bits = BitReader.readFewBits(s, extraBits);
              } else {
                BitReader.fillBitWindow(s);
                bits = BitReader.readBits(s, extraBits);
              }
              s.distance = s.distOffset[distanceCode] + (bits << s.distancePostfixBits);
            }
          }

          if (s.maxDistance != s.maxBackwardDistance
              && s.pos < s.maxBackwardDistance) {
            s.maxDistance = s.pos;
          } else {
            s.maxDistance = s.maxBackwardDistance;
          }

          if (s.distance > s.maxDistance) {
            s.runningState = useDictionary;
            continue;
          }

          if (distanceCode > 0) {
            s.distRbIdx = (s.distRbIdx + 1) & 0x3;
            s.rings[s.distRbIdx] = s.distance;
          }

          if (s.copyLength > s.metaBlockLength) {
            return Utils.makeError(s, BrotliError.brotliErrorInvalidBackwardReference);
          }
          s.j = 0;
          s.runningState = copyLoop;
          continue;

        case copyLoop:
          int src = (s.pos - s.distance) & ringBufferMask;
          int dst = s.pos;
          final int copyLength = s.copyLength - s.j;
          final int srcEnd = src + copyLength;
          final int dstEnd = dst + copyLength;
          if ((srcEnd < ringBufferMask) && (dstEnd < ringBufferMask)) {
            if (copyLength < 12 || (srcEnd > dst && dstEnd > src)) {
              final int numQuads = (copyLength + 3) >> 2;
              for (int k = 0; k < numQuads; ++k) {
                ringBuffer[dst++] = ringBuffer[src++];
                ringBuffer[dst++] = ringBuffer[src++];
                ringBuffer[dst++] = ringBuffer[src++];
                ringBuffer[dst++] = ringBuffer[src++];
              }
            } else {
              Utils.copyBytesWithin(ringBuffer, dst, src, srcEnd);
            }
            s.j += copyLength;
            s.metaBlockLength -= copyLength;
            s.pos += copyLength;
          } else {
            while (s.j < s.copyLength) {
              ringBuffer[s.pos] =
                  ringBuffer[(s.pos - s.distance) & ringBufferMask];
              s.metaBlockLength--;
              s.pos++;
              s.j++;
              if (s.pos >= fence) {
                s.nextRunningState = copyLoop;
                s.runningState = initWrite;
                break;
              }
            }
          }
          if (s.runningState == copyLoop) {
            s.runningState = mainLoop;
          }
          continue;

        case useDictionary:
          result = doUseDictionary(s, fence);
          if (result < BrotliError.brotliOk) {
            return result;
          }
          continue;

        case copyFromCompoundDictionaryState:
          s.pos += copyFromCompoundDictionary(s, fence);
          if (s.pos >= fence) {
            s.nextRunningState = copyFromCompoundDictionaryState;
            s.runningState = initWrite;
            return BrotliError.brotliOkNeedMoreOutput;
          }
          s.runningState = mainLoop;
          continue;

        case readMetadata:
          while (s.metaBlockLength > 0) {
            if (s.halfOffset > BitReader.halfWaterline) {
              result = BitReader.readMoreInput(s);
              if (result < BrotliError.brotliOk) {
                return result;
              }
            }
            BitReader.fillBitWindow(s);
            BitReader.readFewBits(s, 8);
            s.metaBlockLength--;
          }
          s.runningState = blockStart;
          continue;

        case copyUncompressed:
          result = copyUncompressedData(s);
          if (result < BrotliError.brotliOk) {
            return result;
          }
          continue;

        case initWrite:
          s.ringBufferBytesReady = Utils.min(s.pos, s.ringBufferSize);
          s.runningState = write;
          continue;

        case write:
          result = writeRingBuffer(s);
          if (result != BrotliError.brotliOk) {
            return result;
          }
          if (s.pos >= s.maxBackwardDistance) {
            s.maxDistance = s.maxBackwardDistance;
          }
          if (s.pos >= s.ringBufferSize) {
            if (s.pos > s.ringBufferSize) {
              Utils.copyBytesWithin(ringBuffer, 0, s.ringBufferSize, s.pos);
            }
            s.pos = s.pos & ringBufferMask;
            s.ringBufferBytesWritten = 0;
          }
          s.runningState = s.nextRunningState;
          continue;

        default:
          return Utils.makeError(s, BrotliError.brotliPanicUnexpectedState);
      }
    }
    if (s.runningState != finished) {
      return Utils.makeError(s, BrotliError.brotliPanicUnreachable);
    }
    if (s.metaBlockLength < 0) {
      return Utils.makeError(s, BrotliError.brotliErrorInvalidMetablockLength);
    }
    result = BitReader.jumpToByteBoundary(s);
    if (result != BrotliError.brotliOk) {
      return result;
    }
    result = BitReader.checkHealth(s, 1);
    if (result != BrotliError.brotliOk) {
      return result;
    }
    return BrotliError.brotliOkDone;
  }
}

const int _kDefaultDecompressChunkSize = 1 << 16;

/// Decompresses a Brotli-compressed buffer into a freshly allocated [Uint8List].
Uint8List brotliDecompressBuffer(Uint8List input, {int? bufferLimit}) {
  if (bufferLimit != null && bufferLimit < 0) {
    throw ArgumentError.value(bufferLimit, 'bufferLimit', 'must be non-negative');
  }

  final State state = State();
  state.input = ByteArrayInputStream(input);

  int result = Decode.initState(state);
  if (result != BrotliError.brotliOk) {
    throw BrotliRuntimeException('Brotli decoder initialization failed (code: $result)');
  }

  result = Decode.enableLargeWindow(state);
  if (result != BrotliError.brotliOk) {
    Decode.close(state);
    Utils.closeInput(state);
    throw BrotliRuntimeException('Failed to enable large window mode (code: $result)');
  }

  final BytesBuilder outputBuilder = BytesBuilder(copy: false);
  final Uint8List chunk = Uint8List(_kDefaultDecompressChunkSize);

  try {
    while (true) {
      final int available = bufferLimit == null
          ? chunk.length
          : bufferLimit - outputBuilder.length;
      if (available <= 0) {
        throw BrotliRuntimeException('Trying to obtain buffer larger than $bufferLimit');
      }

      state.output = chunk;
      state.outputOffset = 0;
      state.outputLength = Utils.min(chunk.length, available);
      state.outputUsed = 0;

      final int status = Decode.decompress(state);
      if (status < BrotliError.brotliOk) {
        throw BrotliRuntimeException('Brotli stream decoding failed (code: $status)');
      }

      if (state.outputUsed > 0) {
        outputBuilder.add(chunk.sublist(0, state.outputUsed));
      }

      if (status == BrotliError.brotliOkDone) {
        break;
      }
    }
    return outputBuilder.takeBytes();
  } finally {
    Decode.close(state);
    Utils.closeInput(state);
  }
}
