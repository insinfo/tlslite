import 'dart:math';
import 'dart:typed_data';

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
    final queue = _MinHeap<_BuilderNode>();
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

/// Minimal binary min-heap. Mirrors the algorithm of `HeapPriorityQueue`
/// from `package:collection` exactly (same tie-breaking), so the generated
/// Huffman trees stay byte-identical.
class _MinHeap<E extends Comparable<E>> {
  final List<E> _queue = <E>[];

  int get length => _queue.length;
  bool get isEmpty => _queue.isEmpty;

  E get first {
    if (_queue.isEmpty) throw StateError('No element');
    return _queue[0];
  }

  void add(E element) {
    _queue.add(element);
    _bubbleUp(element, _queue.length - 1);
  }

  E removeFirst() {
    if (_queue.isEmpty) throw StateError('No element');
    final result = _queue[0];
    final last = _queue.removeLast();
    if (_queue.isNotEmpty) {
      _bubbleDown(last, 0);
    }
    return result;
  }

  void _bubbleUp(E element, int index) {
    while (index > 0) {
      final parentIndex = (index - 1) ~/ 2;
      final parent = _queue[parentIndex];
      if (element.compareTo(parent) > 0) break;
      _queue[index] = parent;
      index = parentIndex;
    }
    _queue[index] = element;
  }

  void _bubbleDown(E element, int index) {
    final length = _queue.length;
    var rightChildIndex = index * 2 + 2;
    while (rightChildIndex < length) {
      final leftChildIndex = rightChildIndex - 1;
      final leftChild = _queue[leftChildIndex];
      final rightChild = _queue[rightChildIndex];
      int minChildIndex;
      E minChild;
      if (leftChild.compareTo(rightChild) < 0) {
        minChild = leftChild;
        minChildIndex = leftChildIndex;
      } else {
        minChild = rightChild;
        minChildIndex = rightChildIndex;
      }
      if (element.compareTo(minChild) <= 0) {
        _queue[index] = element;
        return;
      }
      _queue[index] = minChild;
      index = minChildIndex;
      rightChildIndex = index * 2 + 2;
    }
    final leftChildIndex = rightChildIndex - 1;
    if (leftChildIndex < length) {
      final child = _queue[leftChildIndex];
      if (element.compareTo(child) > 0) {
        _queue[index] = child;
        index = leftChildIndex;
      }
    }
    _queue[index] = element;
  }
}
