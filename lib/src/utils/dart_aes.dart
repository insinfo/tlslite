// Ported to Dart from tlslite-ng tlslite/utils/python_aes.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:typed_data';
import 'dart:math';
import 'aes.dart'; // Contains the AES base class
import 'rijndael_slow.dart'; // Contains the Rijndael/AES block implementation
import 'cryptomath.dart'; // Contains bytesToNumber and numberToByteArray

/// Factory function to create a new dart AES cipher instance.
///
/// - [key]: The secret key for the cipher.
/// - [mode]: The cipher mode (2 for CBC, 6 for CTR).
/// - [iv]: The initialization vector (CBC) or nonce (CTR).
AES newAES(Uint8List key, int mode, Uint8List iv) {
  if (mode == aesModeCbc) {
    // Mode 2
    return DartAes(key, mode, iv);
  } else if (mode == aesModeCtrOrGcm) {
    // Mode 6
    return DartAesCtr(key, mode, iv);
  } else {
    throw UnimplementedError(
        "AES mode $mode not implemented in dart_aes.dart");
  }
}

/// Pure Dart implementation of AES in CBC mode.
class DartAes extends AES {
  late final Rijndael _rijndael;
  // Assumes the AES base class has 'Uint8List iv'.
  // The IV here represents the *current* state of the chaining vector.

  DartAes(Uint8List key, int mode, Uint8List iv)
      // mode is always CBC (2) for this class
      : super(key, aesModeCbc, iv, "dart") {
    // Copy the key so the caller's input is never modified
    final internalKey = Uint8List.fromList(key);
    _rijndael =
        Rijndael(internalKey, blockSize: 16); // AES block size is 16 bytes
    // The base class has already stored the initial IV.
    // No separate copy is needed here since the base class keeps it.
    // this.iv = Uint8List.fromList(iv); // Unnecessary since the base stores it
  }

  @override
  Uint8List encrypt(Uint8List plaintext) {
    if (plaintext.lengthInBytes % 16 != 0) {
      throw ArgumentError(
          "Plaintext length must be a multiple of 16 bytes for CBC");
    }

    // Make a mutable copy of the plaintext to hold the ciphertext
    final ciphertextBytes = Uint8List.fromList(plaintext);
    // Make a mutable copy of the current IV for chaining
    // Reads 'iv' from the base class
    var chainBytes = Uint8List.fromList(iv);

    // CBC mode: for each block...
    for (int i = 0; i < ciphertextBytes.lengthInBytes; i += 16) {
      final currentBlockOffset = i;

      // Take the current plaintext block (directly from the buffer being modified)
      // Uint8List plaintextBlock = ciphertextBytes.buffer.asUint8List(ciphertextBytes.offsetInBytes + currentBlockOffset, 16);

      // XOR with the previous chaining block
      for (int j = 0; j < 16; j++) {
        ciphertextBytes[currentBlockOffset + j] ^= chainBytes[j];
      }

      // Encrypt the XORed block (directly from the modified buffer)
      // A copy or view has to be passed to rijndael.encrypt
      final blockToEncrypt = Uint8List.view(ciphertextBytes.buffer,
          ciphertextBytes.offsetInBytes + currentBlockOffset, 16);
      final encryptedBlock = _rijndael.encrypt(blockToEncrypt);

      // Overwrite the original block with the encrypted block
      ciphertextBytes.setRange(
          currentBlockOffset, currentBlockOffset + 16, encryptedBlock);

      // Set the next chaining block (the freshly produced ciphertext)
      // Copy it to avoid problems if encryptedBlock is a view
      chainBytes = Uint8List.fromList(encryptedBlock);
    }

    // Update the instance IV with the last ciphertext block for the next call
    // (standard CBC mode behaviour)
    iv = chainBytes; // Updates the iv stored in the base class

    return ciphertextBytes;
  }

  @override
  Uint8List decrypt(Uint8List ciphertext) {
    if (ciphertext.lengthInBytes % 16 != 0) {
      throw ArgumentError(
          "Ciphertext length must be a multiple of 16 bytes for CBC");
    }

    // Make a mutable copy of the ciphertext to hold the plaintext
    final plaintextBytes = Uint8List.fromList(ciphertext);
    // Make a mutable copy of the current IV for chaining
    var chainBytes = Uint8List.fromList(iv);

    // CBC mode: for each block...
    for (int i = 0; i < plaintextBytes.lengthInBytes; i += 16) {
      final currentBlockOffset = i;

      // Keep the *original* ciphertext block for the next chaining step
      final originalCipherBlock = Uint8List.fromList(
          plaintextBytes.sublist(currentBlockOffset, currentBlockOffset + 16));

      // Decrypt the current block
      final decryptedBlock = _rijndael.decrypt(originalCipherBlock);

      // XOR with the previous chaining block
      for (int j = 0; j < 16; j++) {
        decryptedBlock[j] ^= chainBytes[j];
      }

      // Overwrite the original block (now plaintextBytes) with the decrypted, XORed block
      plaintextBytes.setRange(
          currentBlockOffset, currentBlockOffset + 16, decryptedBlock);

      // Set the next chaining block (the original ciphertext block)
      chainBytes = originalCipherBlock;
    }

    // Update the instance IV with the last original *ciphertext* block
    iv = chainBytes;

    return plaintextBytes;
  }
}

/// Pure Dart implementation of AES in CTR mode.
class DartAesCtr extends AES {
  late final Rijndael _rijndael;
  // The base class 'iv' stores the initial nonce
  late Uint8List _counter; // The full counter block (nonce + counter)
  late final int
      _counterBytesLength; // Number of bytes dedicated to the actual counter

  DartAesCtr(Uint8List key, int mode, Uint8List nonce)
      // mode is always CTR (6) for this class
      : super(key, aesModeCtrOrGcm, nonce, "dart") {
    if (nonce.length > 16) {
      throw ArgumentError(
          "Nonce (IV) length must be at most 16 bytes for CTR mode");
    }
    final internalKey = Uint8List.fromList(key);
    _rijndael = Rijndael(internalKey, blockSize: 16);
    _counterBytesLength = 16 - nonce.length;

    // Initialize the counter block
    _counter = Uint8List(16);
    _counter.setRange(0, nonce.length, nonce); // Copy the nonce
    // The rest is already zero-initialized by Uint8List(16).
  }

  /// Gets the current value of the full counter block (nonce + counter value).
  Uint8List get counter => _counter;

  /// Sets the full counter block value. Used carefully, mainly for testing or specific state restoration.
  set counter(Uint8List newCounter) {
    if (newCounter.length != 16) {
      throw ArgumentError("Counter block must be 16 bytes long");
    }
    _counter = Uint8List.fromList(newCounter); // Make a copy
  }

  /// Increments the counter part of the counter block.
  /// Throws StateError on overflow.
  void _counterUpdate() {
    // Convert the whole block to a BigInt
    BigInt counterInt = bytesToNumber(_counter);

    // Increment
    counterInt += BigInt.one;

    // Convert back to a 16-byte Uint8List
    Uint8List newCounterBytes;
    try {
      newCounterBytes = numberToByteArray(counterInt, howManyBytes: 16);
    } catch (e) {
      // numberToByteArray may fail if the number is too large for 16 bytes
      throw StateError("CTR counter overflowed during conversion: $e");
    }

    // Check for overflow of the *counter* part specifically
    // (the counter part reached FF..FF and wrapped to 00..00,
    // meaning the next increment would spill into the nonce part).
    // A real overflow (> 2^128-1) would already have failed in the BigInt->bytes conversion.
    // This check is about CTR *logic*: the *counter* part must not overflow
    // and wrap back to zero, because that would reuse keystream.
    // The simplest way is to check whether the *last* _counterBytesLength
    // bytes of the *new* counter are all 0, which indicates that a carry
    // went past the last counter byte.

    bool counterPartIsZero = true;
    for (int i = 16 - _counterBytesLength; i < 16; i++) {
      if (newCounterBytes[i] != 0) {
        counterPartIsZero = false;
        break;
      }
    }

    // If the counter part became zero AND _counterBytesLength > 0, a LOGICAL overflow occurred.
    // (If _counterBytesLength == 0, the counter never changes, so there is no overflow.)
    if (_counterBytesLength > 0 && counterPartIsZero) {
      // A stricter check would be to see whether the counter bytes BEFORE
      // the increment were all 0xFF. Checking whether they became 0 after
      // the increment covers the logical overflow case.
      throw StateError("CTR counter part overflowed (would reuse keystream)");
    }

    _counter = newCounterBytes; // Update the instance counter
  }

  @override
  Uint8List encrypt(Uint8List plaintext) {
    final resultBytes = Uint8List(
        plaintext.lengthInBytes); // Output buffer, filled block by block
    //final maskBuilder = BytesBuilder(copy: false);

    int bytesToProcess = plaintext.lengthInBytes;
    int processedBytes = 0;

    while (processedBytes < bytesToProcess) {
      // Encrypt the current counter to get the next keystream block
      final keystreamBlock = _rijndael.encrypt(_counter);

      // Work out how many bytes of this keystream block are needed
      final needed = bytesToProcess - processedBytes;
      final bytesToUse = min(16, needed); // Use at most 16 bytes

      // XOR the plaintext bytes with the keystream bytes
      for (int i = 0; i < bytesToUse; i++) {
        resultBytes[processedBytes + i] =
            plaintext[processedBytes + i] ^ keystreamBlock[i];
      }

      processedBytes += bytesToUse;
      // Increment the counter for the next block, even if this was the last one.
      // The counter is advanced after each keystream block is generated,
      // so that subsequent calls continue from the correct position.
      try {
        _counterUpdate();
      } on StateError catch (e) {
        throw StateError("CTR counter overflow during operation: $e");
      }
    }

    return resultBytes;
  }

  @override
  Uint8List decrypt(Uint8List ciphertext) {
    // The CTR operation is the same for encryption and decryption.
    // IMPORTANT: if the same object is used to decrypt after encrypting,
    // the counter state must be reset or managed correctly!
    // This implementation continues the counter from where it stopped.
    // To decrypt independently, the counter has to be reinitialized
    // with the original nonce before calling encrypt.
    // E.g.: Dart_AES_CTR cipher = ...; cipher.decrypt(data); // OK if it is the first op
    //     cipher.encrypt(data2); // Continues the counter
    //     cipher.decrypt(data3); // Continues the counter again
    return encrypt(ciphertext);
  }
}
