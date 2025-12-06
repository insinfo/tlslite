import 'dart:typed_data';
import 'dart:convert';
import 'mathtls.dart' as mathtls;

/// Class for storing SRP password verifiers.
class VerifierDB {
  final Map<String, (BigInt, BigInt, Uint8List, BigInt)> _db = {};

  VerifierDB();

  /// Add a verifier entry to the database.
  ///
  /// [username] The username to associate the verifier with.
  /// Must be less than 256 characters in length.
  ///
  /// [verifierEntry] The verifier entry to add. Use [makeVerifier] to create one.
  void operator []=(String username, (BigInt, BigInt, Uint8List, BigInt) verifierEntry) {
    if (username.length >= 256) {
      throw ArgumentError('Username must be less than 256 characters');
    }
    _db[username] = verifierEntry;
  }

  /// Get a verifier entry from the database.
  (BigInt, BigInt, Uint8List, BigInt)? operator [](String username) {
    return _db[username];
  }

  /// Create a verifier entry.
  ///
  /// [username] The username.
  /// [password] The password.
  /// [bits] The size of the prime to use (1024, 1536, 2048, 3072, 4096, 6144, 8192).
  static (BigInt, BigInt, Uint8List, BigInt) makeVerifier(
      String username, String password, int bits) {
    return mathtls.makeVerifier(
        utf8.encode(username), utf8.encode(password), bits);
  }
}
