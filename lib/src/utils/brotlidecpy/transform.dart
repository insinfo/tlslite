// transform.dart
import 'dart:typed_data';
import 'dictionary.dart';

// --- Transformation Type Constants ---
// (Moved here for self-containment, or import from a shared constants file)
const int kIdentity = 0;
const int kOmitLast1 = 1;
const int kOmitLast2 = 2;
const int kOmitLast3 = 3;
const int kOmitLast4 = 4;
const int kOmitLast5 = 5;
const int kOmitLast6 = 6;
const int kOmitLast7 = 7;
const int kOmitLast8 = 8;
const int kOmitLast9 = 9;
const int kUppercaseFirst = 10;
const int kUppercaseAll = 11;
const int kOmitFirst1 = 12;
const int kOmitFirst2 = 13;
const int kOmitFirst3 = 14;
const int kOmitFirst4 = 15;
const int kOmitFirst5 = 16;
const int kOmitFirst6 = 17;
const int kOmitFirst7 = 18;
const int kOmitFirst8 = 19;
const int kOmitFirst9 = 20;

/// Transformations on dictionary words
class Transform {
  final Uint8List prefix;
  final int transform; // Corresponds to kIdentity, kOmitLast1, etc.
  final Uint8List suffix;

  // Non-const constructor (as determined previously)
  Transform(List<int> prefixBytes, this.transform, List<int> suffixBytes)
      : prefix = Uint8List.fromList(prefixBytes),
        suffix = Uint8List.fromList(suffixBytes);

  /// Applies a transformation to a dictionary word and writes it to [dst].
  /// (MODIFIED dst type to List<int>)
  ///
  /// Args:
  ///   dst: The destination buffer (List<int>) to write the transformed word into.
  ///   idx: The starting index in [dst] to write to.
  ///   word: The starting index of the word in the Brotli dictionary.
  ///   length: The original length requested for the copy.
  ///   transformIndex: The index of the transformation to apply from [kTransforms].
  ///
  /// Returns:
  ///   The number of bytes written to [dst].
  static int transformDictionaryWord(
      List<int> dst, // <<< CHANGED type here
      int idx,
      int word, // Dictionary offset
      int length, // Original copy length requested
      int transformIndex) {
    // Add validation or ensure kTransforms exists
    // if (kTransforms == null) throw StateError("kTransforms not initialized");
    if (transformIndex < 0 || transformIndex >= kTransforms.length) {
      throw ArgumentError("Invalid transformIndex: $transformIndex");
    }

    final transform = kTransforms[transformIndex];
    final Uint8List prefix = transform.prefix; // Source data remains Uint8List
    final Uint8List suffix = transform.suffix; // Source data remains Uint8List
    final int t = transform.transform;

    int skip = (t >= kOmitFirst1) ? (t - (kOmitFirst1 - 1)) : 0;
    final int startIdx = idx;

    if (skip > length) {
      skip = length;
    }

    // 1. Write prefix (Uint8List source to List<int> dest)
    for (int i = 0; i < prefix.length; ++i) {
      // Ensure capacity for List<int> before writing
      if (idx >= dst.length) dst.length = idx + 1;
      dst[idx++] = prefix[i]; // Direct assignment works (int to int)
    }

    // 2. Adjust word source position and effective length to copy
    word += skip;
    int currentLength =
        length - skip; // Length of segment to copy *from dictionary*

    // 3. Adjust length based on omit last count
    if (t <= kOmitLast9) {
      currentLength -= t;
    }
    // Ensure length is not negative after adjustments
    if (currentLength < 0) currentLength = 0;

    // 4. Write the core word segment from dictionary (Uint8List) to dst (List<int>)
    final int wordEnd = word + currentLength;
    int wordCopyStartIdx =
        idx; // Remember where the word part starts in dst for case change
    for (int i = word; i < wordEnd; ++i) {
      // Ensure capacity for List<int> before writing
      if (idx >= dst.length) dst.length = idx + 1;
      // Ensure BrotliDictionary.dictionary is accessible and i is within bounds
      if (i < 0 || i >= BrotliDictionary.dictionary.length) {
        throw RangeError("Dictionary index $i out of bounds");
      }
      dst[idx++] = BrotliDictionary.dictionary[i]; // Direct assignment
    }

    // 5. Apply case changes (if any) to dst (List<int>)
    int uppercaseIdx = wordCopyStartIdx;
    int remainingLengthForCaseChange =
        idx - wordCopyStartIdx; // Actual # bytes copied

    if (t == kUppercaseFirst) {
      if (remainingLengthForCaseChange > 0) {
        _toUpperCase(dst, uppercaseIdx); // Pass List<int>
      }
    } else if (t == kUppercaseAll) {
      while (remainingLengthForCaseChange > 0) {
        int step = _toUpperCase(dst, uppercaseIdx); // Pass List<int>
        if (step <= 0)
          break; // Avoid infinite loops if _toUpperCase returns 0 or less
        uppercaseIdx += step;
        remainingLengthForCaseChange -= step;
      }
    }

    // 6. Write suffix (Uint8List source to List<int> dest)
    for (int i = 0; i < suffix.length; ++i) {
      // Ensure capacity for List<int> before writing
      if (idx >= dst.length) dst.length = idx + 1;
      dst[idx++] = suffix[i]; // Direct assignment
    }

    return idx - startIdx; // Return the total number of bytes written
  }
}

// --- Predefined Transforms ---
// Helper to convert String to List<int> (byte values) for constructor
List<int> _b(String s) => s.codeUnits;

// 'final' is appropriate here since Transform objects are created at runtime
// Ensure this list definition is present and correct
final List<Transform> kTransforms = List.unmodifiable([
  Transform(_b(""), kIdentity, _b("")), // 0
  Transform(_b(""), kIdentity, _b(" ")), // 1
  Transform(_b(" "), kIdentity, _b(" ")), // 2
  Transform(_b(""), kOmitFirst1, _b("")), // 3
  Transform(_b(""), kUppercaseFirst, _b(" ")), // 4
  Transform(_b(""), kIdentity, _b(" the ")), // 5
  Transform(_b(" "), kIdentity, _b("")), // 6
  Transform(_b("s "), kIdentity, _b(" ")), // 7
  Transform(_b(""), kIdentity, _b(" of ")), // 8
  Transform(_b(""), kUppercaseFirst, _b("")), // 9
  Transform(_b(""), kIdentity, _b(" and ")), // 10
  Transform(_b(""), kOmitFirst2, _b("")), // 11
  Transform(_b(""), kOmitLast1, _b("")), // 12
  Transform(_b(", "), kIdentity, _b(" ")), // 13
  Transform(_b(""), kIdentity, _b(", ")), // 14
  Transform(_b(" "), kUppercaseFirst, _b(" ")), // 15
  Transform(_b(""), kIdentity, _b(" in ")), // 16
  Transform(_b(""), kIdentity, _b(" to ")), // 17
  Transform(_b("e "), kIdentity, _b(" ")), // 18
  Transform(_b(""), kIdentity, _b("\"")), // 19
  Transform(_b(""), kIdentity, _b(".")), // 20
  Transform(_b(""), kIdentity, _b("\">")), // 21
  Transform(_b(""), kIdentity, _b("\n")), // 22
  Transform(_b(""), kOmitLast3, _b("")), // 23
  Transform(_b(""), kIdentity, _b("]")), // 24
  Transform(_b(""), kIdentity, _b(" for ")), // 25
  Transform(_b(""), kOmitFirst3, _b("")), // 26
  Transform(_b(""), kOmitLast2, _b("")), // 27
  Transform(_b(""), kIdentity, _b(" a ")), // 28
  Transform(_b(""), kIdentity, _b(" that ")), // 29
  Transform(_b(" "), kUppercaseFirst, _b("")), // 30
  Transform(_b(""), kIdentity, _b(". ")), // 31
  Transform(_b("."), kIdentity, _b("")), // 32
  Transform(_b(" "), kIdentity, _b(", ")), // 33
  Transform(_b(""), kOmitFirst4, _b("")), // 34
  Transform(_b(""), kIdentity, _b(" with ")), // 35
  Transform(_b(""), kIdentity, _b("'")), // 36
  Transform(_b(""), kIdentity, _b(" from ")), // 37
  Transform(_b(""), kIdentity, _b(" by ")), // 38
  Transform(_b(""), kOmitFirst5, _b("")), // 39
  Transform(_b(""), kOmitFirst6, _b("")), // 40
  Transform(_b(" the "), kIdentity, _b("")), // 41
  Transform(_b(""), kOmitLast4, _b("")), // 42
  Transform(_b(""), kIdentity, _b(". The ")), // 43
  Transform(_b(""), kUppercaseAll, _b("")), // 44
  Transform(_b(""), kIdentity, _b(" on ")), // 45
  Transform(_b(""), kIdentity, _b(" as ")), // 46
  Transform(_b(""), kIdentity, _b(" is ")), // 47
  Transform(_b(""), kOmitLast7, _b("")), // 48
  Transform(_b(""), kOmitLast1, _b("ing ")), // 49
  Transform(_b(""), kIdentity, _b("\n\t")), // 50
  Transform(_b(""), kIdentity, _b(":")), // 51
  Transform(_b(" "), kIdentity, _b(". ")), // 52
  Transform(_b(""), kIdentity, _b("ed ")), // 53
  Transform(_b(""), kOmitFirst9, _b("")), // 54
  Transform(_b(""), kOmitFirst7, _b("")), // 55
  Transform(_b(""), kOmitLast6, _b("")), // 56
  Transform(_b(""), kIdentity, _b("(")), // 57
  Transform(_b(""), kUppercaseFirst, _b(", ")), // 58
  Transform(_b(""), kOmitLast8, _b("")), // 59
  Transform(_b(""), kIdentity, _b(" at ")), // 60
  Transform(_b(""), kIdentity, _b("ly ")), // 61
  Transform(_b(" the "), kIdentity, _b(" of ")), // 62
  Transform(_b(""), kOmitLast5, _b("")), // 63
  Transform(_b(""), kOmitLast9, _b("")), // 64
  Transform(_b(" "), kUppercaseFirst, _b(", ")), // 65
  Transform(_b(""), kUppercaseFirst, _b("\"")), // 66
  Transform(_b("."), kIdentity, _b("(")), // 67
  Transform(_b(""), kUppercaseAll, _b(" ")), // 68
  Transform(_b(""), kUppercaseFirst, _b("\">")), // 69
  Transform(_b(""), kIdentity, _b("=\"")), // 70
  Transform(_b(" "), kIdentity, _b(".")), // 71
  Transform(_b(".com/"), kIdentity, _b("")), // 72
  Transform(_b(" the "), kIdentity, _b(" of the ")), // 73
  Transform(_b(""), kUppercaseFirst, _b("'")), // 74
  Transform(_b(""), kIdentity, _b(". This ")), // 75
  Transform(_b(""), kIdentity, _b(",")), // 76
  Transform(_b("."), kIdentity, _b(" ")), // 77
  Transform(_b(""), kUppercaseFirst, _b("(")), // 78
  Transform(_b(""), kUppercaseFirst, _b(".")), // 79
  Transform(_b(""), kIdentity, _b(" not ")), // 80
  Transform(_b(" "), kIdentity, _b("=\"")), // 81
  Transform(_b(""), kIdentity, _b("er ")), // 82
  Transform(_b(" "), kUppercaseAll, _b(" ")), // 83
  Transform(_b(""), kIdentity, _b("al ")), // 84
  Transform(_b(" "), kUppercaseAll, _b("")), // 85
  Transform(_b(""), kIdentity, _b("='")), // 86
  Transform(_b(""), kUppercaseAll, _b("\"")), // 87
  Transform(_b(""), kUppercaseFirst, _b(". ")), // 88
  Transform(_b(" "), kIdentity, _b("(")), // 89
  Transform(_b(""), kIdentity, _b("ful ")), // 90
  Transform(_b(" "), kUppercaseFirst, _b(". ")), // 91
  Transform(_b(""), kIdentity, _b("ive ")), // 92
  Transform(_b(""), kIdentity, _b("less ")), // 93
  Transform(_b(""), kUppercaseAll, _b("'")), // 94
  Transform(_b(""), kIdentity, _b("est ")), // 95
  Transform(_b(" "), kUppercaseFirst, _b(".")), // 96
  Transform(_b(""), kUppercaseAll, _b("\">")), // 97
  Transform(_b(" "), kIdentity, _b("='")), // 98
  Transform(_b(""), kUppercaseFirst, _b(",")), // 99
  Transform(_b(""), kIdentity, _b("ize ")), // 100
  Transform(_b(""), kUppercaseAll, _b(".")), // 101
  Transform([0xc2, 0xa0], kIdentity, _b("")), // 102: Non-breaking space
  Transform(_b(" "), kIdentity, _b(",")), // 103
  Transform(_b(""), kUppercaseFirst, _b("=\"")), // 104
  Transform(_b(""), kUppercaseAll, _b("=\"")), // 105
  Transform(_b(""), kIdentity, _b("ous ")), // 106
  Transform(_b(""), kUppercaseAll, _b(", ")), // 107
  Transform(_b(""), kUppercaseFirst, _b("='")), // 108
  Transform(_b(" "), kUppercaseFirst, _b(",")), // 109
  Transform(_b(" "), kUppercaseAll, _b("=\"")), // 110
  Transform(_b(" "), kUppercaseAll, _b(", ")), // 111
  Transform(_b(""), kUppercaseAll, _b(",")), // 112
  Transform(_b(""), kUppercaseAll, _b("(")), // 113
  Transform(_b(""), kUppercaseAll, _b(". ")), // 114
  Transform(_b(" "), kUppercaseAll, _b(".")), // 115
  Transform(_b(""), kUppercaseAll, _b("='")), // 116
  Transform(_b(" "), kUppercaseAll, _b(". ")), // 117
  Transform(_b(" "), kUppercaseFirst, _b("=\"")), // 118
  Transform(_b(" "), kUppercaseAll, _b("='")), // 119
  Transform(_b(" "), kUppercaseFirst, _b("='")), // 120
]);

// Make this accessible if needed, though kTransforms.length can be used directly
// const int kNumTransforms = kTransforms.length; // 121

/// Converts the UTF-8 character starting at index [i] in [p] (List<int>) to uppercase.
/// (MODIFIED p type to List<int>)
///
/// This is the simplified model specified by RFC7932.
/// Returns the number of bytes processed (1, 2, or 3), or 0 if index is invalid.
int _toUpperCase(List<int> p, int i) {
  // <<< CHANGED type here
  // Add initial bounds check for safety
  if (i < 0 || i >= p.length) {
    return 0; // Invalid index
  }

  if (p[i] < 0xC0) {
    // 1-byte sequence (ASCII)
    if (p[i] >= 97 /* 'a' */ && p[i] <= 122 /* 'z' */) {
      p[i] ^= 32; // Toggle case bit
    }
    return 1;
  }
  // Check bounds before accessing p[i+1]
  if (p[i] < 0xE0) {
    // 2-byte sequence
    if ((i + 1) < p.length) {
      // Check bounds strictly
      // Apply simplified transform logic from RFC/Python code
      p[i + 1] ^= 32;
      return 2;
    } else {
      // Incomplete sequence, treat as 1 byte (no change)
      return 1;
    }
  }
  // Check bounds before accessing p[i+1], p[i+2]
  if (p[i] < 0xF0) {
    // 3-byte sequence
    if ((i + 2) < p.length) {
      // Check bounds strictly
      // Apply simplified transform logic from RFC/Python code
      p[i + 2] ^= 5;
      return 3;
    } else {
      // Incomplete sequence, treat as 1 byte (no change)
      return 1;
    }
  }

  // If >= 4 bytes or other invalid start byte, treat as 1 byte (no change)
  return 1;
}
