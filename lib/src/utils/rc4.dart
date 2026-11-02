// Ported to Dart from tlslite-ng tlslite/utils/rc4.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:typed_data';

/// Abstract representation of the RC4 stream cipher.
///
/// This class defines the basic structure and properties expected of an RC4
/// implementation, but does not contain the encryption logic itself, which
/// must be provided by concrete subclasses.
abstract class RC4 {
  /// Whether this is a block cipher. Always `false` for RC4.
  final bool isBlockCipher = false;

  /// Whether it provides authenticated encryption with associated data (AEAD).
  /// Always `false` for standard RC4.
  final bool isAEAD = false;

  /// Cipher name.
  final String name = "rc4";

  /// Reference to the underlying concrete implementation.
  /// The [Object] type is used for generality; replace it with a more
  /// specific type if the implementation details are known.
  final Object implementation;

  /// Sets up the RC4 cipher.
  ///
  /// Throws an [ArgumentError] if the length of [keyBytes] is not between
  /// 16 and 256 bytes (inclusive).
  ///
  /// - [keyBytes]: the key bytes for the RC4 cipher.
  /// - [implementation]: the concrete implementation instance.
  RC4(Uint8List keyBytes, this.implementation) {
    // Validate the key length
    if (keyBytes.length < 16 || keyBytes.length > 256) {
      throw ArgumentError(
          'RC4 key length must be between 16 and 256 bytes, inclusive. '
          'Got: ${keyBytes.length}');
    }
    // Note: the key itself (keyBytes) is not stored in this abstract class.
    // The concrete subclass or the 'implementation' is expected to manage it.
  }

  /// Encrypts [plaintext].
  ///
  /// Returns the ciphertext as a [Uint8List].
  Uint8List encrypt(Uint8List plaintext);

  /// Decrypts [ciphertext].
  ///
  /// For RC4, the operation is typically identical to encryption.
  /// Returns the plaintext as a [Uint8List].
  Uint8List decrypt(Uint8List ciphertext);
}