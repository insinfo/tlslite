import 'dart:typed_data';

import 'byte_reader.dart';
import 'frame_header.dart';

const int fseMinTableLog = 5;
const int fseTableLogAbsoluteMax = 15;

class FseTableDescriptor {
  FseTableDescriptor({
    required this.tableLog,
    required this.normalizedCounts,
    required this.maxSymbol,
    required this.maxSymbolUsed,
  });

  final int tableLog;
  final List<int> normalizedCounts;
  final int maxSymbol;
  final int maxSymbolUsed;
}

class SequenceDecodingEntry {
  const SequenceDecodingEntry({
    required this.symbol,
    required this.baseValue,
    required this.nbAdditionalBits,
    required this.nbBits,
    required this.nextState,
  });

  final int symbol;
  final int baseValue;
  final int nbAdditionalBits;
  final int nbBits;
  final int nextState;
}

class SequenceDecodingTable {
  SequenceDecodingTable({
    required this.entries,
    required this.tableLog,
  });

  final List<SequenceDecodingEntry> entries;
  final int tableLog;

  int get size => entries.length;
}

/// A simple bit reader for reading bits from a byte stream in reverse order
/// (ANS/FSE style - reads from end of buffer backwards).
class BitReader {
  BitReader(this._buffer)
      : _offset = _buffer.length,
        _bits = 0,
        _bitsAvailable = 0;

  final List<int> _buffer;
  int _offset;
  int _bits;
  int _bitsAvailable;

  /// Initialize the bit reader by reading the initial bits from the end.
  /// Returns false if the buffer is empty.
  bool init() {
    if (_offset == 0) return false;
    
    // Find the highest set bit in the last byte to determine padding
    _offset--;
    int lastByte = _buffer[_offset];
    if (lastByte == 0) {
      throw ZstdFrameFormatException('Invalid bitstream: last byte is zero');
    }
    
    // Find position of highest bit (the sentinel bit)
    int highBit = 7;
    while (highBit >= 0 && ((lastByte >> highBit) & 1) == 0) {
      highBit--;
    }
    
    // The bits below the sentinel are the actual data bits
    _bits = lastByte & ((1 << highBit) - 1);
    _bitsAvailable = highBit;
    
    return true;
  }

  /// Read [count] bits from the stream.
  int readBits(int count) {
    while (_bitsAvailable < count && _offset > 0) {
      _offset--;
      _bits |= _buffer[_offset] << _bitsAvailable;
      _bitsAvailable += 8;
    }
    
    if (_bitsAvailable < count) {
      throw ZstdFrameFormatException('Not enough bits in stream');
    }
    
    final result = _bits & ((1 << count) - 1);
    _bits >>= count;
    _bitsAvailable -= count;
    return result;
  }

  /// Read bits without consuming them (for FSE state initialization).
  int peekBits(int count) {
    while (_bitsAvailable < count && _offset > 0) {
      _offset--;
      _bits |= _buffer[_offset] << _bitsAvailable;
      _bitsAvailable += 8;
    }
    
    if (_bitsAvailable < count) {
      throw ZstdFrameFormatException('Not enough bits to peek');
    }
    
    return _bits & ((1 << count) - 1);
  }

  /// Reload bits if needed (for 32-bit systems compatibility).
  void reload() {
    while (_bitsAvailable <= 24 && _offset > 0) {
      _offset--;
      _bits |= _buffer[_offset] << _bitsAvailable;
      _bitsAvailable += 8;
    }
  }

  /// Check if the stream is finished.
  bool get isFinished => _offset == 0 && _bitsAvailable == 0;
  
  /// Get remaining bits available.
  int get bitsAvailable => _bitsAvailable;
}

FseTableDescriptor readFseTable(ZstdByteReader reader, int maxSymbol) {
  final remaining = reader.remaining;
  if (remaining <= 0) {
    throw ZstdFrameFormatException('Unexpected end of input while reading FSE table');
  }

  final buffer = reader.buffer;
  final start = reader.offset;
  final result = _readNCount(buffer, start, remaining, maxSymbol);
  reader.offset += result.bytesRead;
  return result.descriptor;
}

SequenceDecodingTable buildSequenceDecodingTable({
  required FseTableDescriptor descriptor,
  required List<int> baseValues,
  required List<int> extraBits,
}) {
  final tableLog = descriptor.tableLog;
  if (tableLog < 1 || tableLog > fseTableLogAbsoluteMax) {
    throw ZstdFrameFormatException('Invalid FSE tableLog $tableLog');
  }

  final counts = descriptor.normalizedCounts;
  if (counts.length < descriptor.maxSymbol + 1) {
    throw ZstdFrameFormatException('Normalized count table too small');
  }
  if (descriptor.maxSymbolUsed >= baseValues.length ||
      descriptor.maxSymbolUsed >= extraBits.length) {
    throw ZstdFrameFormatException('Base or extra bit table too small for decoded symbol range');
  }

  final tableSize = 1 << tableLog;
  final symbolNext = List<int>.filled(descriptor.maxSymbol + 1, 0);
  final tableSymbols = List<int>.filled(tableSize, 0);
  final largeLimit = 1 << (tableLog - 1);
  int highThreshold = tableSize - 1;

  for (int symbol = 0; symbol <= descriptor.maxSymbol; symbol++) {
    final count = counts[symbol];
    if (count == -1) {
      if (highThreshold < 0) {
        throw ZstdFrameFormatException('FSE table overflows low probability area');
      }
      tableSymbols[highThreshold--] = symbol;
      symbolNext[symbol] = 1;
    } else if (count > 0) {
      if (count >= largeLimit) {
        // Fast mode flag ignored for now, but we keep the same validation as reference.
      }
      symbolNext[symbol] = count;
    }
  }

  final tableMask = tableSize - 1;
  final step = _fseTableStep(tableSize);
  int position = 0;
  for (int symbol = 0; symbol <= descriptor.maxSymbol; symbol++) {
    final count = counts[symbol];
    if (count <= 0) continue;
    for (int i = 0; i < count; i++) {
      tableSymbols[position] = symbol;
      position = (position + step) & tableMask;
      while (position > highThreshold) {
        position = (position + step) & tableMask;
      }
    }
  }
  if (position != 0) {
    throw ZstdFrameFormatException('Invalid FSE distribution (position mismatch)');
  }

  final entries = List<SequenceDecodingEntry>.filled(tableSize, const SequenceDecodingEntry(
    symbol: 0,
    baseValue: 0,
    nbAdditionalBits: 0,
    nbBits: 0,
    nextState: 0,
  ));

  for (int tableIndex = 0; tableIndex < tableSize; tableIndex++) {
    final symbol = tableSymbols[tableIndex];
    final nextState = symbolNext[symbol]++;
    final nbBits = tableLog - _highBit32(nextState);
    final newState = (nextState << nbBits) - tableSize;
    entries[tableIndex] = SequenceDecodingEntry(
      symbol: symbol,
      baseValue: baseValues[symbol],
      nbAdditionalBits: extraBits[symbol],
      nbBits: nbBits,
      nextState: newState,
    );
  }

  return SequenceDecodingTable(entries: List<SequenceDecodingEntry>.unmodifiable(entries), tableLog: tableLog);
}

class _FseReadResult {
  _FseReadResult({required this.descriptor, required this.bytesRead});

  final FseTableDescriptor descriptor;
  final int bytesRead;
}

_FseReadResult _readNCount(
  Uint8List buffer,
  int offset,
  int length,
  int maxSymbol,
) {
  if (maxSymbol <= 0) {
    throw ZstdFrameFormatException('Invalid maxSymbol for FSE table: $maxSymbol');
  }

  final maxIndex = offset + length;
  if (length < 1) {
    throw ZstdFrameFormatException('Not enough data for FSE table');
  }

  if (length < 4) {
    final tmp = Uint8List(4);
    tmp.setRange(0, length, buffer.sublist(offset, maxIndex));
    final result = _readNCount(tmp, 0, tmp.length, maxSymbol);
    if (result.bytesRead > length) {
      throw ZstdFrameFormatException('Corrupted FSE header (size mismatch)');
    }
    return _FseReadResult(
      descriptor: result.descriptor,
      bytesRead: result.bytesRead,
    );
  }

  final normalized = List<int>.filled(maxSymbol + 1, 0);
  final start = offset;
  int ip = offset;
  final end = maxIndex;

  int bitStream = _readLE32(buffer, ip, end);
  int nbBits = (bitStream & 0xF) + fseMinTableLog;
  if (nbBits > fseTableLogAbsoluteMax) {
    throw ZstdFrameFormatException('FSE tableLog too large: $nbBits');
  }
  bitStream >>= 4;
  int bitCount = 4;
  final int originalTableLog = nbBits;
  int remaining = (1 << nbBits) + 1;
  int threshold = 1 << nbBits;
  nbBits++;

  int charnum = 0;
  bool previousZero = false;

  while (remaining > 1 && charnum <= maxSymbol) {
    if (previousZero) {
      int n0 = charnum;
      while ((bitStream & 0xFFFF) == 0xFFFF) {
        n0 += 24;
        if (ip < end - 5) {
          ip += 2;
          bitStream = _readLE32(buffer, ip, end) >> bitCount;
        } else {
          bitStream >>= 16;
          bitCount += 16;
        }
      }
      while ((bitStream & 3) == 3) {
        n0 += 3;
        bitStream >>= 2;
        bitCount += 2;
      }
      n0 += bitStream & 3;
      bitCount += 2;
      if (n0 > maxSymbol) {
        throw ZstdFrameFormatException('FSE symbol index exceeds maxSymbol');
      }
      while (charnum < n0) {
        normalized[charnum++] = 0;
      }
      if ((ip <= end - 7) || (ip + (bitCount >> 3) <= end - 4)) {
        ip += bitCount >> 3;
        bitCount &= 7;
        bitStream = _readLE32(buffer, ip, end) >> bitCount;
      } else {
        bitStream >>= 2;
      }
    }

    final int max = (2 * threshold - 1) - remaining;
    int count;
    if ((bitStream & (threshold - 1)) < max) {
      count = bitStream & (threshold - 1);
      bitCount += nbBits - 1;
    } else {
      count = bitStream & ((threshold * 2) - 1);
      if (count >= threshold) {
        count -= max;
      }
      bitCount += nbBits;
    }
    count--;
    remaining -= count < 0 ? -count : count;
    normalized[charnum++] = count;
    previousZero = count == 0;
    while (remaining < threshold) {
      nbBits--;
      threshold >>= 1;
    }

    if ((ip <= end - 7) || (ip + (bitCount >> 3) <= end - 4)) {
      ip += bitCount >> 3;
      bitCount &= 7;
    } else {
      bitCount -= 8 * ((end - 4) - ip);
      ip = end - 4;
    }
    bitStream = _readLE32(buffer, ip, end) >> (bitCount & 31);
  }

  if (remaining != 1) {
    throw ZstdFrameFormatException('Corrupted FSE header (remaining != 1)');
  }
  if (bitCount > 32) {
    throw ZstdFrameFormatException('Corrupted FSE header (bitCount overflow)');
  }

  final maxSymbolUsed = charnum - 1;
  ip += (bitCount + 7) >> 3;
  final consumed = ip - start;
  if (consumed > length) {
    throw ZstdFrameFormatException('FSE header overruns input');
  }

  return _FseReadResult(
    descriptor: FseTableDescriptor(
      tableLog: originalTableLog,
      normalizedCounts: normalized,
      maxSymbol: maxSymbol,
      maxSymbolUsed: maxSymbolUsed,
    ),
    bytesRead: consumed,
  );
}

int _readLE32(Uint8List buffer, int offset, int limit) {
  int value = 0;
  for (int i = 0; i < 4; i++) {
    final idx = offset + i;
    final byte = idx < limit ? buffer[idx] : 0;
    value |= (byte & 0xFF) << (8 * i);
  }
  return value & 0xFFFFFFFF;
}

int _fseTableStep(int tableSize) => (tableSize >> 1) + (tableSize >> 3) + 3;

int _highBit32(int value) {
  if (value <= 0) return 0;
  return value.bitLength - 1;
}

/// FSE (Finite State Entropy) decoding table entry.
class FseTableEntry {
  FseTableEntry({
    required this.symbol,
    required this.nbBits,
    required this.newState,
  });

  final int symbol;
  final int nbBits;
  final int newState;
}

/// FSE decoding state.
class FseState {
  FseState(this.table, this.tableLog);

  final List<FseTableEntry> table;
  final int tableLog;
  int state = 0;

  /// Initialize state from bit reader.
  void init(BitReader bits) {
    state = bits.readBits(tableLog);
  }

  /// Get current symbol without advancing state.
  int get symbol => table[state].symbol;

  /// Advance to next state.
  void advance(BitReader bits) {
    final entry = table[state];
    final lowBits = bits.readBits(entry.nbBits);
    state = entry.newState + lowBits;
  }
}
