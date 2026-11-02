// Ported to Dart from tlslite-ng tlslite/utils/aes.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:typed_data';

typedef RawAesEncrypt = Uint8List Function(Uint8List block);



// Define constants for modes if their meaning is known (e.g., CBC, CTR, GCM)
// Based on standard libraries, 2 often corresponds to CBC.
// 6 might correspond to CTR or GCM, depending on the original library's intent.
// Let's assume 2 is CBC for validation clarity.
const int aesModeCbc = 2;
// Let's assume 6 is another common mode like CTR or GCM for the example.
const int aesModeCtrOrGcm = 6; // Or another specific mode constant

abstract class AES {
  /// The encryption key. Must be 16, 24, or 32 bytes long.
  final Uint8List key;

  /// The cipher mode (e.g., CBC, CTR, GCM).
  /// Based on the original code, only modes 2 and 6 are supported.
  final int mode;

  /// The Initialization Vector (IV) or Nonce.
  /// Length requirements depend on the mode.
  Uint8List iv;

  /// Reference to the specific underlying implementation (e.g., platform-specific).
  /// The type 'Object' is used for generality; replace with a more specific
  /// type if the implementation details are known.
  final Object implementation;

  /// Indicates if this cipher operates on fixed-size blocks. Always true for AES.
  final bool isBlockCipher = true;

  /// Indicates if this cipher provides Authenticated Encryption with Associated Data.
  /// Set to false based on the original code for this base class.
  /// Concrete implementations (like GCM) would override this.
  final bool isAEAD = false;

  /// The block size in bytes. Always 16 for AES.
  final int blockSize = 16;

  /// The algorithm name (e.g., "aes128", "aes192", "aes256").
  /// Determined by the key length.
  final String name;

  /// Creates an instance of an AES cipher configuration.
  ///
  /// Throws [ArgumentError] if the key length, mode, or IV length is invalid.
  ///
  /// - [key]: The encryption key (16, 24, or 32 bytes).
  /// - [mode]: The cipher mode (must be 2 or 6 in this context).
  /// - [iv]: The Initialization Vector. Must be 16 bytes for mode 2 (CBC).
  ///         Must be <= 16 bytes for mode 6.
  /// - [implementation]: An object representing the specific cryptographic implementation.
  AES(Uint8List key, this.mode, Uint8List iv, this.implementation)
      // Initialize final fields, calculating 'name' based on key length.
      : this.key = key,
        this.iv = iv,
        name = _calculateName(key.length) {
    // Validate key length
    if (!const [16, 24, 32].contains(key.length)) {
      throw ArgumentError(
          'Invalid key length: ${key.length}. Must be 16, 24, or 32 bytes.');
    }

    // Validate mode
    // Using constants for clarity if modes are known (e.g., aesModeCBC)
    if (mode != aesModeCbc && mode != aesModeCtrOrGcm) {
      throw ArgumentError('Invalid mode: $mode. Supported modes are 2 and 6.');
    }

    // Validate IV length based on mode
    if (mode == aesModeCbc) {
      // Assuming mode 2 is CBC
      if (iv.length != blockSize) {
        // CBC IV must match block size
        throw ArgumentError(
            'Invalid IV length for mode $mode (CBC): ${iv.length}. Must be $blockSize bytes.');
      }
    } else if (mode == aesModeCtrOrGcm) {
      // Assuming mode 6 needs IV <= block size
      if (iv.length > blockSize) {
        // Some modes like CTR/GCM might use variable nonce lengths, but the
        // original code restricts it to <= 16.
        throw ArgumentError(
            'Invalid IV length for mode $mode: ${iv.length}. Must be less than or equal to $blockSize bytes.');
      }
      // Note: Mode 6 might allow zero-length IVs depending on the specific mode/implementation.
      // The original code allowed len(IV) <= 16.
    }
    // No need to explicitly initialize fields like isBlockCipher, isAEAD, blockSize
    // as they are assigned default values directly in their declaration.
    // The 'name' field is initialized in the initializer list.
  }

  /// Helper function to determine AES variant name from key length.
  static String _calculateName(int keyLength) {
    switch (keyLength) {
      case 16:
        return "aes128";
      case 24:
        return "aes192";
      case 32:
        return "aes256";
      default:
        // This should be unreachable due to constructor validation
        throw StateError(
            'Internal error: Invalid key length ($keyLength) encountered.');
    }
  }

  /// Encrypts the given [plaintext].
  ///
  /// Concrete implementations must override this method.
  /// The plaintext length typically needs to adhere to block size requirements
  /// or padding rules depending on the mode of operation (e.g., multiple of
  /// block size for CBC with padding).
  ///
  /// The original code included an assertion: `assert(len(plaintext) % 16 == 0)`
  /// which implies padding should be handled before calling encrypt in CBC mode.
  /// Implementations should clarify padding requirements.
  ///
  /// Returns the ciphertext as a [Uint8List].
  Uint8List encrypt(Uint8List plaintext);

  /// Decrypts the given [ciphertext].
  ///
  /// Concrete implementations must override this method.
  /// The ciphertext length typically needs to be a multiple of the block size,
  /// depending on the mode (e.g., for CBC).
  ///
  /// The original code included an assertion: `assert(len(ciphertext) % 16 == 0)`.
  /// Implementations should clarify length requirements.
  ///
  /// Returns the plaintext as a [Uint8List]. May include padding that needs removal.
  Uint8List decrypt(Uint8List ciphertext);
}
