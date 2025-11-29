import 'dart:typed_data';

import 'package:meta/meta.dart';

const int tripleDesModeCBC = 2;

/// Abstract base class for Triple DES implementations.
///
/// Mirrors the Python tlslite.utils.tripledes interface by validating
/// parameters and exposing metadata shared across concrete backends.
abstract class TripleDES {
  TripleDES(
    Uint8List key,
    this.mode,
    Uint8List iv,
    this.implementation,
  )   : key = Uint8List.fromList(key),
        iv = Uint8List.fromList(iv) {
    if (key.length != 16 && key.length != 24) {
      throw ArgumentError(
        '3DES key must be either 16 or 24 bytes (got ${key.length})',
      );
    }
    if (mode != tripleDesModeCBC) {
      throw ArgumentError('Only CBC mode (value 2) is supported.');
    }
    if (iv.length != blockSize) {
      throw ArgumentError('3DES IV must be exactly $blockSize bytes.');
    }
  }

  /// Raw key material (16 or 24 bytes).
  final Uint8List key;

  /// CBC mode identifier. Fixed to [tripleDesModeCBC].
  final int mode;

  /// Current feedback value (updated by CBC processing).
  @protected
  Uint8List iv;

  /// Human readable implementation label (e.g. "python").
  final String implementation;

  /// Triple DES always operates on 8-byte blocks.
  static const int blockSize = 8;

  /// Cipher metadata for consumers mirroring the Python object API.
  final bool isBlockCipher = true;
  final bool isAEAD = false;
  final String name = '3des';

  @protected
  void ensureBlockMultiple(Uint8List data) {
    if (data.length % blockSize != 0) {
      throw ArgumentError(
        'Data length (${data.length}) must be a multiple of $blockSize bytes',
      );
    }
  }

  Uint8List encrypt(Uint8List plaintext);

  Uint8List decrypt(Uint8List ciphertext);
}
