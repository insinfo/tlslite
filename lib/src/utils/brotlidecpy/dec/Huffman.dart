import 'dart:typed_data';

class Huffman {
  static const int MAX_LENGTH = 15;

  static int getNextKey(int key, int len) {
    int step = 1 << (len - 1);
    while ((key & step) != 0) {
      step = step >> 1;
    }
    return (key & (step - 1)) + step;
  }

  static void replicateValue(Int32List table, int offset, int step, int end, int item) {
    int pos = end;
    while (pos > 0) {
      pos -= step;
      table[offset + pos] = item;
    }
  }

  static int nextTableBitSize(Int32List count, int len, int rootBits) {
    int bits = len;
    int left = 1 << (bits - rootBits);
    while (bits < MAX_LENGTH) {
      left -= count[bits];
      if (left <= 0) {
        break;
      }
      bits++;
      left = left << 1;
    }
    return bits - rootBits;
  }

  static int buildHuffmanTable(Int32List tableGroup, int tableIdx, int rootBits, Int32List codeLengths, int codeLengthsSize) {
    final int tableOffset = tableGroup[tableIdx];
    final Int32List sorted = Int32List(codeLengthsSize);
    final Int32List count = Int32List(MAX_LENGTH + 1);
    final Int32List offset = Int32List(MAX_LENGTH + 1);

    for (int sym = 0; sym < codeLengthsSize; ++sym) {
      count[codeLengths[sym]]++;
    }

    offset[1] = 0;
    for (int len = 1; len < MAX_LENGTH; ++len) {
      offset[len + 1] = offset[len] + count[len];
    }

    for (int sym = 0; sym < codeLengthsSize; ++sym) {
      if (codeLengths[sym] != 0) {
        sorted[offset[codeLengths[sym]]++] = sym;
      }
    }

    int tableBits = rootBits;
    int tableSize = 1 << tableBits;
    int totalSize = tableSize;

    if (offset[MAX_LENGTH] == 1) {
      for (int k = 0; k < totalSize; ++k) {
        tableGroup[tableOffset + k] = sorted[0];
      }
      return totalSize;
    }

    int key = 0;
    int symbol = 0;
    int step = 1;
    for (int len = 1; len <= rootBits; ++len) {
      step = step << 1;
      while (count[len] > 0) {
        replicateValue(tableGroup, tableOffset + key, step, tableSize, (len << 16) | sorted[symbol++]);
        key = getNextKey(key, len);
        count[len]--;
      }
    }

    final int mask = totalSize - 1;
    int low = -1;
    int currentOffset = tableOffset;
    step = 1;
    for (int len = rootBits + 1; len <= MAX_LENGTH; ++len) {
      step = step << 1;
      while (count[len] > 0) {
        if ((key & mask) != low) {
          currentOffset += tableSize;
          tableBits = nextTableBitSize(count, len, rootBits);
          tableSize = 1 << tableBits;
          totalSize += tableSize;
          low = key & mask;
          tableGroup[tableOffset + low] = ((tableBits + rootBits) << 16) | (currentOffset - tableOffset - low);
        }
        replicateValue(tableGroup, currentOffset + (key >> rootBits), step, tableSize, ((len - rootBits) << 16) | sorted[symbol++]);
        key = getNextKey(key, len);
        count[len]--;
      }
    }
    return totalSize;
  }
}

/// Mirrors the Java reference's constant so callers can import MAX_LENGTH
/// without referencing the Huffman class directly.
const int MAX_LENGTH = Huffman.MAX_LENGTH;
