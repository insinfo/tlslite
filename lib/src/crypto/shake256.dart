/// SHAKE256 implementation based on Keccak.
///
/// SHAKE256 is a Keccak-based XOF (eXtendable Output Function) defined in FIPS 202.
/// Parameters: rate = 1088 bits (136 bytes), capacity = 512 bits
library shake256;

import 'dart:typed_data';

/// SHAKE256 extendable output function.
///
/// SHAKE256 is based on Keccak with capacity 512 (rate 1088).
Uint8List shake256(List<int> input, int outputLength) {
  return _Keccak.shake256(Uint8List.fromList(input), outputLength);
}

/// Keccak implementation for SHAKE256.
class _Keccak {
  // Keccak-f[1600] parameters
  static const int _stateSize = 25; // 5x5 state of 64-bit words
  static const int _rounds = 24;
  
  // Round constants
  static final List<int> _rc = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
    0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
  ];
  
  // Rotation offsets
  static const List<List<int>> _rotationOffsets = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
  ];
  
  /// SHAKE256 (rate = 1088 bits = 136 bytes)
  static Uint8List shake256(Uint8List input, int outputLength) {
    const rate = 136; // bytes (1088 bits)
    return _sponge(input, outputLength, rate, 0x1F); // SHAKE domain separator
  }
  
  /// Core sponge construction
  static Uint8List _sponge(Uint8List input, int outputLength, int rate, int domainSeparator) {
    // Initialize state (25 x 64-bit words = 1600 bits)
    final state = List<int>.filled(_stateSize, 0);
    
    // Absorb phase
    // Pad the message: append domain separator byte and 10*1 padding
    final padded = _pad(input, rate, domainSeparator);
    
    // Process each rate-sized block
    for (var offset = 0; offset < padded.length; offset += rate) {
      // XOR block into state
      for (var i = 0; i < rate ~/ 8; i++) {
        final word = _bytesToWord(padded, offset + i * 8);
        state[i] ^= word;
      }
      // Apply permutation
      _keccakF(state);
    }
    
    // Squeeze phase
    final output = Uint8List(outputLength);
    var outputOffset = 0;
    
    while (outputOffset < outputLength) {
      final toCopy = (outputLength - outputOffset < rate) 
          ? outputLength - outputOffset 
          : rate;
      
      // Extract rate bytes from state
      for (var i = 0; i < toCopy; i++) {
        final wordIndex = i ~/ 8;
        final byteIndex = i % 8;
        output[outputOffset + i] = (state[wordIndex] >> (byteIndex * 8)) & 0xFF;
      }
      
      outputOffset += toCopy;
      
      if (outputOffset < outputLength) {
        _keccakF(state);
      }
    }
    
    return output;
  }
  
  /// Pad message with SHAKE domain separator and 10*1 padding
  static Uint8List _pad(Uint8List input, int rate, int domainSeparator) {
    // Calculate padded length (next multiple of rate)
    final padLen = rate - (input.length % rate);
    final padded = Uint8List(input.length + padLen);
    
    // Copy input
    padded.setRange(0, input.length, input);
    
    // Add domain separator (0x1F for SHAKE, 0x06 for SHA3)
    padded[input.length] = domainSeparator;
    
    // Add final bit (0x80) at the end of the block
    padded[padded.length - 1] |= 0x80;
    
    return padded;
  }
  
  /// Convert 8 bytes to a 64-bit word (little-endian)
  static int _bytesToWord(Uint8List bytes, int offset) {
    if (offset + 8 > bytes.length) {
      // Handle partial word
      var word = 0;
      for (var i = 0; i < bytes.length - offset && i < 8; i++) {
        word |= bytes[offset + i] << (i * 8);
      }
      return word;
    }
    
    return bytes[offset] |
        (bytes[offset + 1] << 8) |
        (bytes[offset + 2] << 16) |
        (bytes[offset + 3] << 24) |
        (bytes[offset + 4] << 32) |
        (bytes[offset + 5] << 40) |
        (bytes[offset + 6] << 48) |
        (bytes[offset + 7] << 56);
  }
  
  /// Keccak-f[1600] permutation
  static void _keccakF(List<int> state) {
    for (var round = 0; round < _rounds; round++) {
      _theta(state);
      _rhoPi(state);
      _chi(state);
      _iota(state, round);
    }
  }
  
  /// θ (theta) step
  static void _theta(List<int> state) {
    final c = List<int>.filled(5, 0);
    final d = List<int>.filled(5, 0);
    
    // Compute column parities
    for (var x = 0; x < 5; x++) {
      c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    
    // Compute D
    for (var x = 0; x < 5; x++) {
      d[x] = c[(x + 4) % 5] ^ _rotl64(c[(x + 1) % 5], 1);
    }
    
    // Apply D to state
    for (var x = 0; x < 5; x++) {
      for (var y = 0; y < 5; y++) {
        state[x + y * 5] ^= d[x];
      }
    }
  }
  
  /// ρ (rho) and π (pi) steps combined
  static void _rhoPi(List<int> state) {
    final temp = List<int>.filled(_stateSize, 0);
    
    for (var x = 0; x < 5; x++) {
      for (var y = 0; y < 5; y++) {
        final newX = y;
        final newY = (2 * x + 3 * y) % 5;
        temp[newX + newY * 5] = _rotl64(state[x + y * 5], _rotationOffsets[x][y]);
      }
    }
    
    for (var i = 0; i < _stateSize; i++) {
      state[i] = temp[i];
    }
  }
  
  /// χ (chi) step
  static void _chi(List<int> state) {
    for (var y = 0; y < 5; y++) {
      final temp = List<int>.filled(5, 0);
      for (var x = 0; x < 5; x++) {
        temp[x] = state[x + y * 5];
      }
      for (var x = 0; x < 5; x++) {
        state[x + y * 5] = temp[x] ^ ((~temp[(x + 1) % 5]) & temp[(x + 2) % 5]);
      }
    }
  }
  
  /// ι (iota) step
  static void _iota(List<int> state, int round) {
    state[0] ^= _rc[round];
  }
  
  /// 64-bit left rotation
  static int _rotl64(int x, int n) {
    n = n % 64;
    if (n == 0) return x;
    return ((x << n) | (x >>> (64 - n)));
  }
}
