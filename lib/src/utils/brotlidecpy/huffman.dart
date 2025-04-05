// --- Top-level Constants and Helper Functions ---

const int MAX_LENGTH = 15;

/// Calculates the next canonical Huffman code key in reversed bit order.
///
/// Returns reverse(reverse(key, length) + 1, length), where reverse(key, length) is
/// the bit-wise reversal of the [length] least significant bits of [key].
/// Essentially increments the reversed code and reverses it back.
int _get_next_key(int key, int length) {
  int step = 1 <<
      (length - 1); // Start with the most significant bit for the given length
  // Find the least significant bit that is 0
  while ((key & step) != 0) {
    step >>= 1;
    if (step == 0) {
      // If all bits are 1 (e.g., key=7, length=3 -> 111), the next key is 0
      // This wraps around according to canonical Huffman code generation.
      return 0;
    }
  }
  // Flip the least significant 0 bit to 1, and clear all bits to its right (more significant in original order)
  // Equivalent to: (key & (step - 1)) | step
  return (key & (step - 1)) + step;
}

/// Stores [code] in table entries based on step and end indices.
///
/// Stores the HuffmanCode(code.bits, code.value) in
/// table[i], table[i + step], table[i + 2*step], ..., up to table[i + end - step].
/// Assumes [end] is an integer multiple of [step].
/// The loop iterates downwards from the end index.
void _replicate_value(
    List<HuffmanCode?> table, int i, int step, int end, HuffmanCode code) {
  // Loop bounds derived from Python's range(i + end - step, i - step, -step)
  // Start: i + end - step
  // Stop: i (inclusive)
  // Step: -step
  for (int index = i + end - step; index >= i; index -= step) {
    // Basic bounds check for safety
    if (index < 0 || index >= table.length) {
      print(
          "Error: _replicate_value index $index out of bounds for table size ${table.length}. i=$i, step=$step, end=$end");
      // Depending on context, might throw an error or just continue/break
      // throw RangeError.index(index, table, "table index");
      break; // Stop replication if out of bounds
    }
    // Create a new HuffmanCode instance for each slot
    table[index] = HuffmanCode(code.bits, code.value);
  }
}

/// Returns the table width (number of bits) for the next 2nd level table.
///
/// [count] is the histogram of bit lengths for the remaining symbols.
/// [length] is the code length of the next symbol to be processed.
/// [root_bits] is the number of bits in the root table lookup.
int _next_table_bit_size(List<int> count, int length, int root_bits) {
  int left =
      1 << (length - root_bits); // Number of slots available at this level
  while (length < MAX_LENGTH) {
    left -= count[length]; // Subtract slots consumed by codes of current length
    if (left <= 0) {
      // Not enough slots left, break
      break;
    }
    length++; // Check next length
    left <<= 1; // Double remaining slots for the next bit level
  }
  // The required table size covers up to the determined 'length'
  return length - root_bits;
}

// --- HuffmanCode Class ---

/// Represents an entry in the Huffman lookup table.
class HuffmanCode {
  /// For leaf nodes: the number of bits used for this symbol's code.
  /// For intermediate nodes: `(sub_table_bits + root_bits)`.
  final int bits;

  /// For leaf nodes: the symbol value.
  /// For intermediate nodes: the offset to the sub-table.
  final int value;

  HuffmanCode(this.bits, this.value);

  @override
  String toString() {
    return 'HuffmanCode(bits: $bits, value: $value)';
  }
}

// --- Main Table Building Function ---

/// Builds a Huffman lookup table suitable for fast decoding.
///
/// Populates the [root_table] (and potential sub-tables within it) based on
/// the provided [code_lengths]. The table uses a multi-level approach where
/// the first [root_bits] determine an index in the root level. Entries can
/// either be a direct symbol (leaf node) or a pointer to a sub-table for
/// longer codes.
///
/// - [root_table]: The List where the Huffman table will be stored. It should be
///   pre-allocated and sufficiently large. The required size is the value
///   returned by this function. Elements can be null initially. Modified in place.
/// - [table]: The starting index within [root_table] where the table building begins.
///   This acts as the base offset for all writes.
/// - [root_bits]: The number of bits used for the initial lookup in the root table
///   (root table size will be `1 << root_bits`).
/// - [code_lengths]: A list containing the Huffman code length for each symbol.
///   A length of 0 means the symbol does not have a code.
/// - [code_lengths_size]: The number of symbols (size of [code_lengths]).
///
/// Returns the total size (number of entries) required for the Huffman table
/// stored within [root_table] starting from the initial [table] index.
/// Throws [ArgumentError] if any code length exceeds MAX_LENGTH.
/// Throws [Exception] or [RangeError] if [root_table] is not large enough.
int brotli_build_huffman_table(
    List<HuffmanCode?> root_table, // The table to fill (passed by reference)
    int table, // Starting offset index within root_table
    int root_bits,
    List<int> code_lengths,
    int code_lengths_size) {
  // Remember the absolute starting index in the provided root_table list.
  int start_table = table;

  // --- Step 1: Initialization and Histogram ---
  // `count`: Stores the number of symbols for each code length (1 to MAX_LENGTH).
  // `offset`: Used temporarily to calculate starting positions in `sorted_symbols`.
  List<int> count = List<int>.filled(MAX_LENGTH + 1, 0);
  List<int> offset = List<int>.filled(MAX_LENGTH + 1, 0);

  // `sorted_symbols`: Stores symbol indices, sorted by their code length.
  List<int> sorted_symbols = List<int>.filled(code_lengths_size, 0);

  // Build histogram of code lengths.
  int total_coded_symbols = 0;
  for (int symbol = 0; symbol < code_lengths_size; symbol++) {
    int cl = code_lengths[symbol];
    if (cl > MAX_LENGTH) {
      throw ArgumentError(
          "Code length $cl for symbol $symbol exceeds MAX_LENGTH $MAX_LENGTH");
    }
    if (cl > 0) {
      count[cl]++;
      total_coded_symbols++;
    }
  }

  // --- Step 2: Calculate Offsets and Sort Symbols ---
  // Calculate starting offset for each code length in the sorted_symbols array.
  offset[1] = 0;
  for (int length = 1; length < MAX_LENGTH; length++) {
    // Offset for length L+1 starts after all symbols of length L.
    offset[length + 1] = offset[length] + count[length];
  }

  // Sort symbols by code length (using the offsets) and symbol value (implicitly).
  // The offset array is modified in place during this step to track the next available slot.
  for (int symbol = 0; symbol < code_lengths_size; symbol++) {
    int length = code_lengths[symbol];
    if (length != 0) {
      // Place the symbol at the current position for its length.
      sorted_symbols[offset[length]] = symbol;
      // Move the offset to the next slot for this length.
      offset[length]++;
    }
  }
  // Note: After this, offset[length] points *after* the last symbol of that length.

  // --- Step 3: Initialize Table Size ---
  int table_bits = root_bits;
  int table_size = 1 << table_bits; // Size of the root table level
  int total_size = table_size; // Total size allocated so far

  // --- Step 4: Handle Special Case: Only One Symbol ---
  if (total_coded_symbols == 1) {
    int symbol_value =
        sorted_symbols[0] & 0xffff; // Get the single symbol's value (masked)
    for (int key = 0; key < total_size; key++) {
      int current_index = start_table + key;
      if (current_index >= root_table.length) {
        throw RangeError.range(current_index, 0, root_table.length - 1,
            "root_table index", "Table too small for special case");
      }
      // Assign code with length 0, value = symbol value
      root_table[current_index] = HuffmanCode(0, symbol_value);
    }
    return total_size; // Only the root table size is needed
  }

  // --- Step 5: Fill Root Table Entries (Lengths 1 to root_bits) ---
  int key = 0; // Current reversed Huffman code being processed
  int symbol = 0; // Index into the sorted_symbols array
  int step = 2; // Replication step size (starts at 2 for length 1)

  for (int length = 1; length <= root_bits; length++) {
    while (count[length] > 0) {
      // Process all symbols of current length
      HuffmanCode code = HuffmanCode(
          length & 0xff, // bits = length (masked)
          sorted_symbols[symbol] & 0xffff // value = symbol (masked)
          );
      symbol++; // Move to the next sorted symbol

      // Replicate the entry in the root table
      _replicate_value(root_table, start_table + key, step, table_size, code);

      key = _get_next_key(key, length); // Get next canonical code (reversed)
      count[length]--;
    }
    step <<= 1; // Double step size for the next bit length
  }

  // --- Step 6: Fill Sub-tables and Root Table Pointers (Lengths > root_bits) ---
  int mask = table_size - 1; // Mask to extract root table index from key
  int low = -1; // Tracks the last root index that got a sub-table pointer
  step = 2; // Reset step for sub-table replication (Python code does this)

  for (int length = root_bits + 1; length <= MAX_LENGTH; length++) {
    while (count[length] > 0) {
      // Process all symbols of current length
      int current_root_index = key & mask;

      // Check if this key falls into a root entry that doesn't have a sub-table yet
      if (current_root_index != low) {
        // --- Allocate new sub-table ---
        table +=
            table_size; // Advance 'table' offset to start of new sub-table space

        // Calculate size needed for this sub-table
        int sub_table_bits = _next_table_bit_size(count, length, root_bits);
        table_bits = sub_table_bits;
        table_size = 1 << table_bits;
        total_size += table_size; // Add size to total

        low = current_root_index; // Mark this root entry as processed

        // --- Create pointer in root table ---
        int pointer_bits = (sub_table_bits + root_bits) & 0xff;
        // Value is offset from this root entry to the start of the sub-table
        int pointer_value = (table - (start_table + low)) & 0xffff;

        int root_pointer_index = start_table + low;
        if (root_pointer_index >= root_table.length) {
          throw RangeError.range(root_pointer_index, 0, root_table.length - 1,
              "root_table index", "Table too small for root pointer");
        }
        root_table[root_pointer_index] =
            HuffmanCode(pointer_bits, pointer_value);
      }

      // --- Create entry in the current sub-table ---
      HuffmanCode code = HuffmanCode(
          (length - root_bits) &
              0xff, // bits = length relative to sub-table start (masked)
          sorted_symbols[symbol] & 0xffff // value = symbol (masked)
          );
      symbol++; // Move to next sorted symbol

      // Replicate the entry in the current sub-table
      // Index within sub-table is (key >> root_bits)
      // Absolute index in root_table is table + (key >> root_bits)
      _replicate_value(
          root_table, table + (key >> root_bits), step, table_size, code);

      key = _get_next_key(key, length); // Get next canonical code (reversed)
      count[length]--;
    }
    step <<= 1; // Double step size for next bit length
  }

  // Sanity check: Ensure all symbols with codes were assigned table entries.
  if (symbol != total_coded_symbols) {
    // This indicates a potential issue in the logic or input data.
    print(
        "Warning: Symbol processing mismatch. Processed: $symbol, Expected: $total_coded_symbols");
  }

  // --- Step 7: Return Total Size ---
  return total_size;
}
