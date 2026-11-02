// Ported to Dart from tlslite-ng tlslite/utils/chacha.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:typed_data';
import 'dart:math';

/// Pure Dart implementation of the ChaCha stream cipher (RFC 7539).
class ChaCha {
  /// ChaCha "expand 32-byte k" constants.
  static const List<int> _constants = [
    0x61707865,
    0x3320646e,
    0x79622d32,
    0x6b206574
  ];

  /// Internal state: key words (8 uint32).
  final List<int> _keyWords;

  /// Internal state: nonce words (3 uint32).
  final List<int> _nonceWords;

  /// Initial counter value.
  final int initialCounter;

  /// Number of rounds (normally 20).
  final int rounds;

  /// Performs a 32-bit left rotation.
  /// Keeps the result within the unsigned 32-bit range.
  static int _rotl32(int v, int c) {
    // Mask v to 32 bits before shifting, since Dart ints may be wider
    final v32 = v & 0xFFFFFFFF;
    final left = (v32 << c) & 0xFFFFFFFF;
    // Uses a plain right shift (>>). If v could be negative,
    // >>> would be safer, but the inputs here are masked.
    final right = v32 >> (32 - c);
    return (left | right) & 0xFFFFFFFF;
  }

  /// Performs a ChaCha quarter round on the state `x`.
  /// Modifies the list `x` in place.
  /// The indices a, b, c, d are the state words being mixed.
  static void quarterRound(List<int> x, int a, int b, int c, int d) {
    // Keep unsigned 32-bit semantics for every operation
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF;
    x[d] = x[d] ^ x[a];
    x[d] = _rotl32(x[d], 16);

    x[c] = (x[c] + x[d]) & 0xFFFFFFFF;
    x[b] = x[b] ^ x[c];
    x[b] = _rotl32(x[b], 12);

    x[a] = (x[a] + x[b]) & 0xFFFFFFFF;
    x[d] = x[d] ^ x[a];
    x[d] = _rotl32(x[d], 8);

    x[c] = (x[c] + x[d]) & 0xFFFFFFFF;
    x[b] = x[b] ^ x[c];
    x[b] = _rotl32(x[b], 7);
  }

  // Indices for the double round operations (column rounds, then diagonal rounds)
  static const List<List<int>> _roundMixupBox = [
    // Column rounds
    [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15],
    // Diagonal rounds
    [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]
  ];

  /// Performs two rounds (one double round) of the ChaCha cipher on the state `x`.
  /// Modifies the list `x` in place.
  static void _doubleRound(List<int> x) {
    // Note: this duplicates the quarter round logic inline.
    // Calling quarterRound would be cleaner, but this matches the original
    // implementation.
    for (final mixup in _roundMixupBox) {
      final a = mixup[0];
      final b = mixup[1];
      final c = mixup[2];
      final d = mixup[3];

      // Quarter round logic copied here
      x[a] = (x[a] + x[b]) & 0xFFFFFFFF;
      x[d] = x[d] ^ x[a];
      x[d] = _rotl32(x[d], 16);

      x[c] = (x[c] + x[d]) & 0xFFFFFFFF;
      x[b] = x[b] ^ x[c];
      x[b] = _rotl32(x[b], 12);

      x[a] = (x[a] + x[b]) & 0xFFFFFFFF;
      x[d] = x[d] ^ x[a];
      x[d] = _rotl32(x[d], 8);

      x[c] = (x[c] + x[d]) & 0xFFFFFFFF;
      x[b] = x[b] ^ x[c];
      x[b] = _rotl32(x[b], 7);
    }
  }

  /// Generates the keystream block for the given key, counter and nonce.
  /// Returns a list of 16 unsigned 32-bit integers.
  static List<int> _chachaBlock(
      List<int> keyWords, int counter, List<int> nonceWords, int rounds) {
    if (keyWords.length != 8)
      throw ArgumentError("Key must be 8 words (256 bits)");
    if (nonceWords.length != 3)
      throw ArgumentError("Nonce must be 3 words (96 bits)");

    // Initialize the state: constants + key + counter + nonce
    // The counter is treated as an unsigned 32-bit value
    final state = List<int>.filled(16, 0);
    state.setRange(0, 4, _constants); // constants[0..3]
    state.setRange(4, 12, keyWords); // key[0..7]
    state[12] = counter & 0xFFFFFFFF; // counter
    state.setRange(13, 16, nonceWords); // nonce[0..2]

    // Copy the initial state to work on
    final workingState = List<int>.from(state, growable: false);

    // Apply the rounds
    final numDoubleRounds = rounds ~/ 2; // Integer division
    for (int i = 0; i < numDoubleRounds; i++) {
      _doubleRound(workingState);
    }

    // Add the initial state to the final working state (modulo 2^32)
    for (int i = 0; i < 16; i++) {
      workingState[i] = (workingState[i] + state[i]) & 0xFFFFFFFF;
    }

    return workingState;
  }

  /// Converts a state (list of 16 uint32 words) to a little-endian
  /// byte stream (Uint8List).
  static Uint8List _wordListToBytes(List<int> state) {
    if (state.length != 16)
      throw ArgumentError("State must be 16 words");
    final byteData = ByteData(64); // 16 words * 4 bytes/word
    for (int i = 0; i < 16; i++) {
      byteData.setUint32(i * 4, state[i], Endian.little);
    }
    // Return the underlying byte buffer as a Uint8List
    return byteData.buffer.asUint8List();
  }

  /// Converts a byte array (Uint8List) to a list of 32-bit words (little-endian).
  static List<int> _bytesToWordList(Uint8List data) {
    if (data.length % 4 != 0)
      throw ArgumentError("Data length must be a multiple of 4");
    final words = <int>[];
    // Use a ByteData view for efficient reads
    final byteData =
        ByteData.view(data.buffer, data.offsetInBytes, data.lengthInBytes);
    for (int i = 0; i < data.lengthInBytes; i += 4) {
      words.add(byteData.getUint32(i, Endian.little));
    }
    return words;
  }

  /// Sets up the initial state for the ChaCha cipher.
  ///
  /// - `key`: 32-byte (256-bit) key as a Uint8List.
  /// - `nonce`: 12-byte (96-bit) nonce as a Uint8List.
  /// - `initialCounter`: initial block counter (defaults to 0).
  /// - `rounds`: number of ChaCha rounds (defaults to 20).
  ChaCha(Uint8List key, Uint8List nonce,
      {this.initialCounter = 0, this.rounds = 20})
      : _keyWords = _bytesToWordList(key),
        _nonceWords = _bytesToWordList(nonce) {
    if (key.length != 32) {
      throw ArgumentError(
          "Key must be 32 bytes (256 bits) long");
    }
    if (nonce.length != 12) {
      throw ArgumentError("Nonce must be 12 bytes (96 bits) long");
    }
    // The conversion to words happens in the initializer list
  }

  /// Encrypts the given plaintext.
  /// Returns the ciphertext as a Uint8List.
  Uint8List encrypt(Uint8List plaintext) {
    // BytesBuilder is an efficient way to build the result
    final ciphertextBuilder = BytesBuilder(copy: false);
    const blockSize = 64; // ChaCha block size in bytes

    for (int i = 0; i < plaintext.length; i += blockSize) {
      // Compute the counter for this block
      // The counter arithmetic wraps around on overflow
      final currentBlockCounter =
          (initialCounter + (i ~/ blockSize)) & 0xFFFFFFFF; // Integer division

      // Generate the keystream block (16 words)
      final keyStreamWords =
          _chachaBlock(_keyWords, currentBlockCounter, _nonceWords, rounds);

      // Convert the keystream words to bytes (64 bytes)
      final keyStreamBytes = _wordListToBytes(keyStreamWords);

      // Determine the portion of the plaintext for this block
      final blockEnd = min(i + blockSize, plaintext.length);
      final plainTextBlockLength = blockEnd - i;

      // XOR the keystream with the plaintext block
      final encryptedBlock = Uint8List(plainTextBlockLength);
      for (int j = 0; j < plainTextBlockLength; j++) {
        encryptedBlock[j] = keyStreamBytes[j] ^ plaintext[i + j];
      }

      ciphertextBuilder.add(encryptedBlock);
    }

    return ciphertextBuilder.toBytes();
  }

  /// Decrypts the given ciphertext.
  /// ChaCha decryption is the same operation as encryption.
  /// Returns the plaintext as a Uint8List.
  Uint8List decrypt(Uint8List ciphertext) {
    // Decryption is identical to encryption for stream ciphers like ChaCha
    return encrypt(ciphertext);
  }
}
