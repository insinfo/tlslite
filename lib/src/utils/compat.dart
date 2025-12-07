import 'dart:convert'; // For ascii, utf8, base64
import 'dart:io'; // For stdin, Platform
import 'dart:typed_data'; // For Uint8List, ByteData
import 'package:convert/convert.dart' show hex;

/// Converts an ASCII string to bytes (Uint8List).
/// Replaces dart's compatAscii2Bytes for dart 3.
Uint8List asciiToBytes(String val) {
  // Consider potential errors if val contains non-ASCII characters
  try {
    return ascii.encode(val);
  } on FormatException catch (e) {
    // Handle or rethrow if strict ASCII is required
    throw ArgumentError('String contains non-ASCII characters: ${e.message}');
  }
}

/// Converts bytes (Uint8List) representing ASCII characters to a String.
/// Replaces dart's compat_b2a.
String bytesToAscii(Uint8List val) {
  // Consider potential errors if bytes are not valid ASCII
  try {
    return ascii.decode(val);
  } on FormatException catch (e) {
    // Handle or rethrow if strict ASCII is required
    throw ArgumentError('Bytes do not represent valid ASCII: ${e.message}');
  }
}



// --- Base16 / Base64 Encoding ---

/// Decodes a hexadecimal string (ASCII) into bytes (Uint8List).
/// Replaces dart's a2b_hex.
/// Throws [FormatException] if the input string is not valid hex.
Uint8List hexDecode(String hexString) {
  try {
    // package:convert handles potential whitespace and case insensitivity
    return Uint8List.fromList(hex.decode(hexString));
  } catch (e) {
    // Wrap exception for consistency or let FormatException propagate
    throw FormatException('Invalid hexadecimal string: $e');
  }
}

/// Encodes bytes (Uint8List) into a hexadecimal string (lowercase ASCII).
/// Replaces dart's b2a_hex.
String hexEncode(Uint8List bytes) {
  return hex.encode(bytes);
}

/// Decodes a base64 string (ASCII) into bytes (Uint8List).
/// Handles standard base64 encoding.
/// Replaces dart's a2b_base64.
/// Throws [FormatException] if the input string is not valid base64.
Uint8List base64Decode(String base64String) {
  try {
    // Standard base64 decoder in dart:convert
    return base64.decode(base64String);
  } catch (e) {
    throw FormatException('Invalid base64 string: $e');
  }
}

/// Encodes bytes (Uint8List) into a base64 string (ASCII).
/// Uses standard base64 encoding (may include padding '=').
/// Replaces dart's b2a_base64.
String base64Encode(Uint8List bytes) {
  // Standard base64 encoder in dart:convert
  // Note: This might add line breaks depending on the encoder used.
  // base64UrlEncode might be closer if URL safety and no padding is needed.
  return base64.encode(bytes);
}

// --- Input / Output ---

/// Reads a line of text from standard input synchronously.
/// Similar to dart's raw_input / input().
String? readLineSync(String prompt) {
  stdout.write(prompt);
  return stdin.readLineSync();
}

/// Reads all available bytes from standard input asynchronously until EOF.
/// Replaces dart's readStdinBinary.
Future<Uint8List> readStdinBinary() async {
  final builder = BytesBuilder();
  await stdin.forEach((chunk) {
    builder.add(chunk);
  });
  return builder.toBytes();
}

/// Reads all available bytes from standard input synchronously until EOF.
/// Note: This can block indefinitely if stdin doesn't close.
/// Generally, the async version [readStdinBinary] is preferred.
Uint8List readStdinBinarySync() {
  final builder = BytesBuilder();
  while (true) {
    // readByteSync blocks until a byte is available or throws on EOF
    try {
      final byte = stdin.readByteSync();
      if (byte == -1) break; // Check for EOF marker (-1)
      builder.addByte(byte);
    } catch (e) {
      // Handle potential exceptions like closing stdin during read
      break; // Assume EOF or error
    }
  }
  return builder.toBytes();
}

// --- Integer / Bytes Conversion ---

/// Dart's `int` type handles arbitrary-precision integers, so no `long` needed.
/// Use `int` directly. Replaces `compatLong`.

/// Returns the minimum number of bits required to represent an integer.
/// Equivalent to dart's `int.bit_length()`.
int bitLength(int val) {
  return val.bitLength;
}

/// Returns the minimum number of bytes required to represent an integer.
int byteLength(int val) {
  // Handle negative numbers if necessary, depending on desired representation
  // bitLength handles negative numbers correctly for two's complement magnitude
  final length = val.bitLength;
  return (length + 7) ~/ 8; // integer division
}

/// Converts bytes (Uint8List) to a non-negative integer.
/// Replaces dart's `bytes_to_int`.
/// Supports 'big' and 'little' endianness.
int bytesToInt(Uint8List val, {Endian endian = Endian.big}) {
  if (val.isEmpty) {
    return 0;
  }

  // Using BigInt for intermediate calculation to handle large numbers safely,
  // then converting back to int (which is arbitrary precision in Dart).
  BigInt result = BigInt.zero;
  if (endian == Endian.big) {
    for (int i = 0; i < val.length; i++) {
      result = (result << 8) | BigInt.from(val[i]);
    }
  } else if (endian == Endian.little) {
    for (int i = val.length - 1; i >= 0; i--) {
      result = (result << 8) | BigInt.from(val[i]);
    }
  } else {
    throw ArgumentError("Endian must be Endian.big or Endian.little");
  }
  // Dart int handles arbitrary precision
  return result.toInt();
}

/// Converts a non-negative integer to bytes (Uint8List).
/// Replaces dart's `int_to_bytes`.
/// Supports 'big' and 'little' endianness.
/// If `length` is null, the minimum number of bytes is used.
Uint8List intToBytes(int val, {int? length, Endian endian = Endian.big}) {
  if (val < 0) {
    // Decide how to handle negative numbers - two's complement? error?
    throw ArgumentError(
        "Negative values not directly supported by this simple conversion.");
  }

  final BigInt bigVal =
      BigInt.from(val); // Use BigInt for reliable bitwise operations
  final int bytesLength = length ?? (bigVal.bitLength + 7) ~/ 8;

  if (bytesLength == 0 && val == 0) {
    // Handle zero value, return single byte 0 if length is null or 0
    if (length == null || length == 0) return Uint8List(1); // Return [0]
    if (length > 0) return Uint8List(length); // Return list of zeros
  }
  if (bytesLength == 0 && val != 0) {
    // Should not happen if bitLength is correct, but as safety
    throw StateError("Calculated zero byte length for non-zero value $val");
  }
  if (length != null && bigVal.bitLength > length * 8) {
    throw ArgumentError("Value $val too large to fit in $length bytes");
  }

  final resultBytes = Uint8List(bytesLength);
  BigInt tempVal = bigVal;
  final BigInt mask = BigInt.from(0xFF);

  if (endian == Endian.big) {
    for (int i = bytesLength - 1; i >= 0; i--) {
      resultBytes[i] = (tempVal & mask).toInt();
      tempVal = tempVal >> 8;
    }
  } else if (endian == Endian.little) {
    for (int i = 0; i < bytesLength; i++) {
      resultBytes[i] = (tempVal & mask).toInt();
      tempVal = tempVal >> 8;
    }
  } else {
    throw ArgumentError("Endian must be Endian.big or Endian.little");
  }

  if (tempVal != BigInt.zero) {
    // This might happen if length was provided and was too small,
    // though the earlier check should catch it. Sanity check.
    throw StateError("Value conversion failed, remaining value: $tempVal");
  }

  return resultBytes;
}

// --- Miscellaneous ---

/// Formats an error and its stack trace into a string.
/// Replaces dart's `formatExceptionTrace`.
String formatExceptionTrace(Object error, StackTrace stackTrace) {
  // Customize formatting as needed
  return 'Error: $error\nStackTrace:\n$stackTrace';
}

/// Returns a high-resolution timestamp in seconds (as double).
/// Uses Stopwatch for monotonic time measurement.
/// Similar intent to dart's time.perf_counter() or time.clock().
double highResTimeStamp() {
  // Note: This starts measuring from an arbitrary point.
  // If you need time since epoch, use DateTime.now().microsecondsSinceEpoch
  // final stopwatch = Stopwatch()..start();
  // To actually *use* it for timing, you'd call start() earlier,
  // do work, then check stopwatch.elapsedMicroseconds.
  // This function as defined just returns the time taken to start the stopwatch.
  // A better way to provide a timestamp *source* might be:
  // return DateTime.now().microsecondsSinceEpoch / 1000000.0; // Wall clock time
  // Or return a reference to a running stopwatch if measuring intervals
  // Let's return wall clock time as seconds double for closer parity to general usage
  return DateTime.now().microsecondsSinceEpoch / 1000000.0;
}

/// Alternative: Get elapsed time from a common start point using Stopwatch
final Stopwatch _appStopwatch = Stopwatch()..start();
double elapsedSeconds() {
  return _appStopwatch.elapsedMicroseconds / 1000000.0;
}

/// Removes all whitespace characters from the input string.
/// Replaces dart's `remove_whitespace`.
String removeWhitespace(String text) {
  // RegExp r'\s+' matches one or more whitespace characters
  return text.replaceAll(RegExp(r'\s+'), '');
}
