import 'dart:typed_data';

import 'bit_stream_writer.dart';

/// Represents the block type/length metadata for one Brotli tree category.
class BlockSplit {
  BlockSplit({
    required this.types,
    required this.lengths,
  })  : numBlocks = types.length,
        numTypes = _computeNumTypes(types);

  /// Creates a split composed of a single block that spans [length] bytes.
  factory BlockSplit.single(int length) {
    final types = Uint8List(1);
    final lengths = Uint32List(1)..[0] = length;
    return BlockSplit(types: types, lengths: lengths);
  }

  /// Block type identifiers for each contiguous block.
  final Uint8List types;

  /// Length of each block in bytes.
  final Uint32List lengths;

  /// Total number of blocks described by this split.
  final int numBlocks;

  /// Total number of distinct block types.
  final int numTypes;

  bool get isTrivial => numTypes <= 1;

  static int _computeNumTypes(Uint8List types) {
    var maxType = -1;
    for (final value in types) {
      if (value > maxType) {
        maxType = value;
      }
    }
    return maxType + 1;
  }
}

/// Serializes block split metadata into the Brotli bit stream.
class BlockStructureWriter {
  const BlockStructureWriter();

  /// Writes the literal, command and distance block split sections.
  ///
  /// Only trivial single-block splits are supported for now to match the
  /// existing encoder behavior. The structure mirrors `brotli-go`'s block
  /// switching pipeline so the full implementation can be ported incrementally.
  void writeTrivialSplits(
    BitStreamWriter writer, {
    required BlockSplit literal,
    required BlockSplit command,
    required BlockSplit distance,
  }) {
    _debugCheckTrivial(literal);
    _debugCheckTrivial(command);
    _debugCheckTrivial(distance);

    // The current encoder only emits a single block type per category, which
    // translates to thirteen zero bits in the block switch section. This keeps
    // the emitted bitstream identical to the previous placeholder while
    // centralizing the logic for future block splitting support.
    writer.writeBits(0, 13);
  }

  void _debugCheckTrivial(BlockSplit split) {
    assert(
      split.isTrivial,
      'Non-trivial block splits are not supported yet. Implement the full block '
      'switch writer before calling writeTrivialSplits().',
    );
  }
}
