import 'dart:typed_data';

class ZstdEncoderSequence {
  ZstdEncoderSequence({
    required this.literalLength,
    required this.matchLength,
    required this.offset,
  });

  final int literalLength;
  final int matchLength;
  final int offset;
}

class ZstdMatchPlan {
  ZstdMatchPlan({
    required this.sequences,
    required this.literalBytes,
  });

  final List<ZstdEncoderSequence> sequences;
  final Uint8List literalBytes;

  bool get hasMatches => sequences.isNotEmpty;
}

const int _minMatch = 3;
const int zstdMatchWindowBytes = 1 << 18; // 256 KiB sliding window
const int _maxMatchLength = 1 << 16;

ZstdMatchPlan planMatches(
  Uint8List input, {
  Uint8List? history,
}) {
  if (input.isEmpty) {
    return ZstdMatchPlan(sequences: const [], literalBytes: Uint8List(0));
  }

  final historyLength = history?.length ?? 0;
  final useHistory = historyLength > 0;
  final buffer = useHistory
      ? (Uint8List(historyLength + input.length)
        ..setRange(0, historyLength, history!)
        ..setRange(historyLength, historyLength + input.length, input))
      : input;

  final baseIndex = useHistory ? historyLength : 0;
  final literals = BytesBuilder(copy: false);
  final sequences = <ZstdEncoderSequence>[];
  final positions = <int, int>{};

  if (useHistory) {
    final limit = historyLength - _minMatch;
    for (var i = 0; i <= limit; i++) {
      final hash = _hash3(buffer, i);
      positions[hash] = i;
    }
  }

  var anchor = baseIndex;
  var position = baseIndex;

  while (position + _minMatch <= buffer.length) {
    final hash = _hash3(buffer, position);
    final candidate = positions[hash];
    positions[hash] = position;

    if (candidate != null) {
      final distance = position - candidate;
      if (distance > 0 && distance <= zstdMatchWindowBytes) {
        final matchLength = _measureMatch(buffer, position, candidate);
        if (matchLength >= _minMatch) {
          final literalLength = position - anchor;
          if (literalLength > 0) {
            _appendLiteralRange(
              literals,
              input,
              baseIndex,
              anchor,
              position,
            );
          }
          sequences.add(
            ZstdEncoderSequence(
              literalLength: literalLength,
              matchLength: matchLength,
              offset: distance,
            ),
          );
          position += matchLength;
          anchor = position;
          continue;
        }
      }
    }

    position += 1;
  }

  if (anchor < buffer.length) {
    _appendLiteralRange(
      literals,
      input,
      baseIndex,
      anchor,
      buffer.length,
    );
  }

  return ZstdMatchPlan(
    sequences: List<ZstdEncoderSequence>.unmodifiable(sequences),
    literalBytes: literals.takeBytes(),
  );
}

int _hash3(Uint8List data, int index) {
  final v0 = data[index];
  final v1 = data[index + 1];
  final v2 = data[index + 2];
  return ((v0 << 8) ^ (v1 << 4) ^ v2) & 0xFFFF;
}

int _measureMatch(Uint8List data, int current, int candidate) {
  final limit = data.length;
  var length = 0;
  final maxLength = _maxMatchLength;
  while (current + length < limit && candidate + length < limit) {
    if (data[current + length] != data[candidate + length]) {
      break;
    }
    length += 1;
    if (length >= maxLength) {
      break;
    }
  }
  return length;
}

void _appendLiteralRange(
  BytesBuilder literals,
  Uint8List source,
  int baseIndex,
  int anchor,
  int position,
) {
  final start = anchor - baseIndex;
  final end = position - baseIndex;
  if (start < 0 || end <= start) {
    return;
  }
  if (end > source.length) {
    return;
  }
  literals.add(source.sublist(start, end));
}
