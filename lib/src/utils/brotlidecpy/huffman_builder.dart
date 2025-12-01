import 'dart:math';
import 'dart:typed_data';

import 'package:collection/collection.dart';

/// Builds canonical Huffman code lengths for a given histogram while enforcing
/// a maximum depth using the same count-lifting strategy as the reference
/// Brotli encoder.
Uint8List buildLimitedHuffmanCodeLengths(
  List<int> counts,
  int alphabetSize,
  int maxBits,
) {
  if (alphabetSize != counts.length) {
    throw ArgumentError(
      'Alphabet size ($alphabetSize) must match counts length (${counts.length}).',
    );
  }
  if (alphabetSize == 0) {
    return Uint8List(0);
  }
  if (maxBits <= 0) {
    throw ArgumentError.value(maxBits, 'maxBits', 'Must be positive');
  }

  final lengths = Uint8List(alphabetSize);
  if (counts.every((value) => value == 0)) {
    return lengths;
  }

  var countLimit = 1;
  while (true) {
    final queue = PriorityQueue<_BuilderNode>();
    for (var symbol = 0; symbol < alphabetSize; symbol++) {
      final count = counts[symbol];
      if (count <= 0) {
        continue;
      }
      final weight = count < countLimit ? countLimit : count;
      queue.add(_BuilderNode(symbol: symbol, weight: weight));
    }

    if (queue.isEmpty) {
      return lengths;
    }

    if (queue.length == 1) {
      lengths.fillRange(0, alphabetSize, 0);
      lengths[queue.first.symbol!] = 1;
      return lengths;
    }

    while (queue.length > 1) {
      final left = queue.removeFirst();
      final right = queue.removeFirst();
      queue.add(_BuilderNode(
        weight: left.weight + right.weight,
        left: left,
        right: right,
      ));
    }

    final root = queue.removeFirst();
    lengths.fillRange(0, alphabetSize, 0);
    final maxDepth = _assignCodeLengths(root, 0, lengths);
    if (maxDepth <= maxBits) {
      return lengths;
    }

    countLimit <<= 1;
    if (countLimit > 1 << 24) {
      throw StateError('Failed to construct Huffman tree constrained to $maxBits bits.');
    }
  }
}

/// Converts canonical code lengths into the corresponding reversed bit codes
/// (LSB-first) as required by the Brotli bitstream.
Uint16List convertBitDepthsToSymbols(Uint8List depths) {
  var maxBits = 0;
  for (final depth in depths) {
    if (depth > maxBits) {
      maxBits = depth;
    }
  }
  if (maxBits == 0) {
    return Uint16List(depths.length);
  }

  final blCount = List<int>.filled(maxBits + 1, 0);
  for (final depth in depths) {
    if (depth > 0) {
      blCount[depth]++;
    }
  }
  blCount[0] = 0;

  final nextCode = List<int>.filled(maxBits + 1, 0);
  var code = 0;
  for (var bits = 1; bits <= maxBits; bits++) {
    code = (code + blCount[bits - 1]) << 1;
    nextCode[bits] = code;
  }

  final result = Uint16List(depths.length);
  for (var i = 0; i < depths.length; i++) {
    final bits = depths[i];
    if (bits == 0) {
      continue;
    }
    final value = _reverseBits(nextCode[bits], bits);
    result[i] = value;
    nextCode[bits]++;
  }
  return result;
}

int _assignCodeLengths(_BuilderNode node, int depth, Uint8List output) {
  if (node.isLeaf) {
    final length = depth == 0 ? 1 : depth;
    output[node.symbol!] = length;
    return length;
  }
  final leftDepth = _assignCodeLengths(node.left!, depth + 1, output);
  final rightDepth = _assignCodeLengths(node.right!, depth + 1, output);
  return max(leftDepth, rightDepth);
}

int _reverseBits(int value, int numBits) {
  var result = 0;
  for (var i = 0; i < numBits; i++) {
    result = (result << 1) | (value & 1);
    value >>= 1;
  }
  return result;
}

class _BuilderNode implements Comparable<_BuilderNode> {
  _BuilderNode({this.symbol, required this.weight, this.left, this.right});

  final int? symbol;
  final int weight;
  final _BuilderNode? left;
  final _BuilderNode? right;

  bool get isLeaf => symbol != null;

  @override
  int compareTo(_BuilderNode other) {
    final diff = weight.compareTo(other.weight);
    if (diff != 0) {
      return diff;
    }
    if (isLeaf && other.isLeaf) {
      return symbol!.compareTo(other.symbol!);
    }
    if (isLeaf) {
      return -1;
    }
    if (other.isLeaf) {
      return 1;
    }
    return 0;
  }
}
