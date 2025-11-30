import 'dart:typed_data';

import 'package:collection/collection.dart';

import 'huffman.dart';

const int _literalAlphabetSize = 256;

/// Accumulates literal frequencies for a Brotli meta-block.
class BrotliLiteralHistogram {
  BrotliLiteralHistogram()
      : _counts = List<int>.filled(_literalAlphabetSize, 0, growable: false),
        totalLiterals = 0;

  final List<int> _counts;
  int totalLiterals;

  List<int> get counts => _counts;

  void addSlice(Uint8List slice, [int start = 0, int? end]) {
    final limit = end ?? slice.length;
    for (var i = start; i < limit; i++) {
      _counts[slice[i] & 0xFF]++;
    }
    totalLiterals += limit - start;
  }
}

Uint8List buildLiteralCodeLengths(BrotliLiteralHistogram histogram) {
  if (histogram.totalLiterals == 0) {
    return Uint8List(_literalAlphabetSize);
  }
  final nodes = PriorityQueue<_HuffNode>();
  for (var symbol = 0; symbol < _literalAlphabetSize; symbol++) {
    final count = histogram.counts[symbol];
    if (count > 0) {
      nodes.add(_HuffNode(symbol: symbol, weight: count));
    }
  }
  if (nodes.length == 1) {
    final lengths = Uint8List(_literalAlphabetSize);
    lengths[nodes.first.symbol!] = 1;
    return lengths;
  }
  while (nodes.length > 1) {
    final left = nodes.removeFirst();
    final right = nodes.removeFirst();
    nodes.add(_HuffNode(weight: left.weight + right.weight, left: left, right: right));
  }
  final root = nodes.removeFirst();
  final lengths = Uint8List(_literalAlphabetSize);
  _assignCodeLengths(root, 0, lengths);
  return lengths;
}

void _assignCodeLengths(_HuffNode node, int depth, Uint8List output) {
  if (node.isLeaf) {
    final length = depth == 0 ? 1 : depth;
    output[node.symbol!] = length;
    return;
  }
  _assignCodeLengths(node.left!, depth + 1, output);
  _assignCodeLengths(node.right!, depth + 1, output);
}

class _HuffNode implements Comparable<_HuffNode> {
  _HuffNode({this.symbol, required this.weight, this.left, this.right});

  final int? symbol;
  final int weight;
  final _HuffNode? left;
  final _HuffNode? right;

  bool get isLeaf => symbol != null;

  @override
  int compareTo(_HuffNode other) {
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

void validateCodeLengths(Uint8List codeLengths) {
  final table = List<HuffmanCode?>.filled(2048, null);
  brotli_build_huffman_table(table, 0, 8, codeLengths, codeLengths.length);
}
