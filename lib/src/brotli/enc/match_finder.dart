import 'dart:typed_data';

import 'brotli_encoder.dart';

/// Greedy match finder inspired by brotli-go's matchfinder.M0 implementation.
class BrotliMatchFinder {
  BrotliMatchFinder({
    this.lazyMatching = true,
    int? maxDistance,
    this.maxMatchLength,
  }) : _maxDistance = maxDistance ?? (1 << 16);

  static const int _hashLen = 5;
  static const int _tableBits = 16;
  static const int _tableSize = 1 << _tableBits;
  static const int _tableMask = _tableSize - 1;
  static const int _hashMul64 = 0x1e35a7bd;
  static const int _inputMargin = 16 - 1;
  static const int _minNonLiteralBlockSize = 1 + 1 + _inputMargin;
  static const int _mask64 = 0xFFFFFFFFFFFFFFFF;

  final bool lazyMatching;
  final int _maxDistance;
  final int? maxMatchLength;

  final Uint32List _table = Uint32List(_tableSize);

  /// Clears the internal hash table so the finder can be reused.
  void reset() {
    _table.fillRange(0, _table.length, 0);
  }

  /// Produces a sequence of [BrotliMatch] covering the entire [input].
  List<BrotliMatch> findMatches(Uint8List input, {List<BrotliMatch>? reuse}) {
    final matches = reuse ?? <BrotliMatch>[];
    matches.clear();

    if (input.length < _minNonLiteralBlockSize) {
      if (input.isNotEmpty) {
        matches.add(BrotliMatch(
          unmatchedLength: input.length,
          matchLength: 0,
          distance: 0,
        ));
      }
      return matches;
    }

    reset();

    final int sLimit = input.length - _inputMargin;
    var nextEmit = 0;
    var s = 1;
    var nextHash = _hashAt(input, s);

    outerLoop:
    while (true) {
      var skip = 32;
      var nextS = s;
      var candidate = -1;

      while (true) {
        s = nextS;
        final bytesBetween = skip >> 5;
        nextS = s + bytesBetween;
        skip += bytesBetween;
        if (nextS > sLimit) {
          break outerLoop;
        }
        candidate = _takeCandidate(nextHash);
        _setCandidate(nextHash, s);
        nextHash = _hashAt(input, nextS);
        if (candidate < 0) {
          continue;
        }
        if (_maxDistance > 0 && s - candidate > _maxDistance) {
          continue;
        }
        if (_load32(input, s) == _load32(input, candidate)) {
          break;
        }
      }

      var base = s;
      var matchPos = candidate;
      s = _extendMatch(input, matchPos + 4, s + 4);

      final origBase = base;
      if (lazyMatching && base + 1 < sLimit) {
        final newBase = base + 1;
        final h = _hashAt(input, newBase);
        final newCandidate = _takeCandidate(h);
        _setCandidate(h, newBase);
        var okDistance = true;
        if (newCandidate < 0) {
          okDistance = false;
        } else if (_maxDistance > 0 && newBase - newCandidate > _maxDistance) {
          okDistance = false;
        }
        if (okDistance &&
            _load32(input, newBase) == _load32(input, newCandidate)) {
          final newS = _extendMatch(input, newCandidate + 4, newBase + 4);
          if (newS - newBase > s - base + 1) {
            s = newS;
            base = newBase;
            matchPos = newCandidate;
          }
        }
      }

      var matchLength = s - base;
      if (maxMatchLength != null && matchLength > maxMatchLength!) {
        matchLength = maxMatchLength!;
        s = base + matchLength;
      }

      matches.add(BrotliMatch(
        unmatchedLength: base - nextEmit,
        matchLength: matchLength,
        distance: base - matchPos,
      ));
      nextEmit = s;
      if (s >= sLimit) {
        break;
      }

      if (lazyMatching) {
        for (var i = origBase + 2; i < s - 3; i++) {
          final x = _load64(input, i);
          _setCandidate(_hashFromValue(x), i);
        }
      } else {
        final x = _load64(input, base + 1);
        _setCandidate(_hashFromValue(x), base + 1);
      }

      final tailIndex = s - 3;
      final tailValue = _load64(input, tailIndex);
      _setCandidate(_hashFromValue(tailValue), tailIndex);
      _setCandidate(_hashFromValue(tailValue >> 8), tailIndex + 1);
      final prevHash = _hashFromValue(tailValue >> 16);
      _setCandidate(prevHash, tailIndex + 2);
      nextHash = _hashFromValue(tailValue >> 24);
    }

    if (nextEmit < input.length) {
      matches.add(BrotliMatch(
        unmatchedLength: input.length - nextEmit,
        matchLength: 0,
        distance: 0,
      ));
    }

    return matches;
  }

  int _hashAt(Uint8List input, int offset) {
    final value = _load64(input, offset);
    return _hashFromValue(value);
  }

  int _hashFromValue(int value) {
    final shifted = (value << (64 - 8 * _hashLen)) & _mask64;
    final hashed = (shifted * _hashMul64) & _mask64;
    return (hashed >> (64 - _tableBits)) & _tableMask;
  }

  void _setCandidate(int hash, int position) {
    _table[hash] = position + 1;
  }

  int _takeCandidate(int hash) {
    final entry = _table[hash];
    return entry == 0 ? -1 : (entry - 1);
  }

  static int _extendMatch(Uint8List input, int candidate, int cursor) {
    final limit = input.length;
    var c = candidate;
    var s = cursor;
    while (c < limit && s < limit && input[c] == input[s]) {
      c++;
      s++;
    }
    return s;
  }

  static int _load32(Uint8List input, int offset) {
    return (input[offset]) |
        (input[offset + 1] << 8) |
        (input[offset + 2] << 16) |
        (input[offset + 3] << 24);
  }

  static int _load64(Uint8List input, int offset) {
    var result = 0;
    for (var i = 0; i < 8; i++) {
      result |= input[offset + i] << (8 * i);
    }
    return result & _mask64;
  }
}
