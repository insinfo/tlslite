/// Represents the range of values belonging to a prefix code:
/// `[offset, offset + 2^nbits)`
class Prefix {
  /// The starting value of the range.
  final int offset;

  /// The number of extra bits required to represent values within the range.
  /// The range size is `1 << nbits`.
  final int nbits;

  /// Creates a compile-time constant Prefix instance.
  const Prefix(this.offset, this.nbits);

  /// Lookup table possibly related to insert range calculation based on distance.
  /// Note: Indexing depends on usage context, typically involving distance codes.
  static const List<int> kInsertRangeLut = [
    0, 0, 8, 8, 0, 16, 8, 16, 16 // Indices 0-8
  ];

  /// Lookup table possibly related to copy range calculation based on distance.
  /// Note: Indexing depends on usage context, typically involving distance codes.
  static const List<int> kCopyRangeLut = [
    0, 8, 0, 8, 16, 0, 16, 8, 16 // Indices 0-8
  ];

  @override
  String toString() => 'Prefix(offset: $offset, nbits: $nbits)';
}

// --- Top-level Constant Definitions ---

/// Prefix codes representing ranges for block lengths used in meta-blocks.
/// Each entry `p` at index `i` defines a range starting at `p.offset`.
/// To decode a value `v` for code `i`, read `p.nbits` extra bits `e` and
/// calculate `v = p.offset + e`.
const List<Prefix> kBlockLengthPrefixCode = [
  // code index: (offset, nbits)
  // Preserve formatting
  Prefix(1, 2), Prefix(5, 2), Prefix(9, 2), Prefix(13, 2), // 0-3
  Prefix(17, 3), Prefix(25, 3), Prefix(33, 3), Prefix(41, 3), // 4-7
  Prefix(49, 4), Prefix(65, 4), Prefix(81, 4), Prefix(97, 4), // 8-11
  Prefix(113, 5), Prefix(145, 5), Prefix(177, 5), Prefix(209, 5), // 12-15
  Prefix(241, 6), Prefix(305, 6), Prefix(369, 7), Prefix(497, 8), // 16-19
  Prefix(753, 9), Prefix(1265, 10), Prefix(2289, 11), Prefix(4337, 12), // 20-23
  Prefix(8433, 13), Prefix(16625, 24) // 24-25
];

/// Prefix codes representing ranges for insert lengths (part of InsertAndCopy command).
/// Decoding follows the same pattern as [kBlockLengthPrefixCode].
const List<Prefix> kInsertLengthPrefixCode = [
  // code index: (offset, nbits)
  // Preserve formatting
  Prefix(0, 0), Prefix(1, 0), Prefix(2, 0), Prefix(3, 0), // 0-3
  Prefix(4, 0), Prefix(5, 0), Prefix(6, 1), Prefix(8, 1), // 4-7
  Prefix(10, 2), Prefix(14, 2), Prefix(18, 3), Prefix(26, 3), // 8-11
  Prefix(34, 4), Prefix(50, 4), Prefix(66, 5), Prefix(98, 5), // 12-15
  Prefix(130, 6), Prefix(194, 7), Prefix(322, 8), Prefix(578, 9), // 16-19
  Prefix(1090, 10), Prefix(2114, 12), Prefix(6210, 14),
  Prefix(22594, 24) // 20-23
];

/// Prefix codes representing ranges for copy lengths (part of InsertAndCopy command).
/// Decoding follows the same pattern as [kBlockLengthPrefixCode].
const List<Prefix> kCopyLengthPrefixCode = [
  // code index: (offset, nbits)
  // Preserve formatting
  Prefix(2, 0), Prefix(3, 0), Prefix(4, 0), Prefix(5, 0), // 0-3
  Prefix(6, 0), Prefix(7, 0), Prefix(8, 0), Prefix(9, 0), // 4-7
  Prefix(10, 1), Prefix(12, 1), Prefix(14, 2), Prefix(18, 2), // 8-11
  Prefix(22, 3), Prefix(30, 3), Prefix(38, 4), Prefix(54, 4), // 12-15
  Prefix(70, 5), Prefix(102, 5), Prefix(134, 6), Prefix(198, 7), // 16-19
  Prefix(326, 8), Prefix(582, 9), Prefix(1094, 10), Prefix(2118, 24) // 20-23
];
