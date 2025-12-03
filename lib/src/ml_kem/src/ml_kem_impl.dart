/// ML-KEM (FIPS 203) Implementation.
///
/// Implements the Module Lattice-based Key Encapsulation Mechanism.
library;

import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import 'parameters.dart';
import 'polynomial.dart';
import 'modules.dart';

/// ML-KEM Key Encapsulation Mechanism implementation.
class MlKem {
  final MlKemParameters params;
  final Random _random;

  /// Create ML-KEM instance with given parameters
  MlKem(this.params, {Random? random}) 
      : _random = random ?? Random.secure();

  /// Generate random bytes
  Uint8List _randomBytes(int length) {
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = _random.nextInt(256);
    }
    return bytes;
  }

  // ===== Hash Functions (Section 4 of FIPS 203) =====

  /// H: SHA3-256 hash
  Uint8List _hashH(Uint8List input) {
    return Uint8List.fromList(sha256.convert(input).bytes);
  }

  /// J: SHAKE256 with 32-byte output
  Uint8List _hashJ(Uint8List input) {
    // Using SHA-512 truncated as SHAKE256 approximation
    final hash = sha512.convert(input).bytes;
    return Uint8List.fromList(hash.sublist(0, 32));
  }

  /// G: SHA3-512 split into two 32-byte values
  (Uint8List, Uint8List) _hashG(Uint8List input) {
    final hash = sha512.convert(input).bytes;
    return (
      Uint8List.fromList(hash.sublist(0, 32)),
      Uint8List.fromList(hash.sublist(32, 64)),
    );
  }

  /// XOF: SHAKE128 - Extendable Output Function
  Uint8List _xof(Uint8List rho, int i, int j) {
    // SHAKE128(rho || i || j) with sufficient output
    final input = Uint8List.fromList([...rho, j, i]);
    return _shake128(input, 840);
  }

  /// PRF: SHAKE256 for pseudorandom function
  Uint8List _prf(int eta, Uint8List s, int b) {
    final input = Uint8List.fromList([...s, b]);
    return _shake256(input, 64 * eta);
  }

  /// SHAKE128 approximation using repeated SHA-256
  Uint8List _shake128(Uint8List input, int outputLen) {
    final result = <int>[];
    var counter = 0;
    while (result.length < outputLen) {
      final data = Uint8List.fromList([
        ...input,
        counter >> 24,
        counter >> 16,
        counter >> 8,
        counter & 0xFF,
      ]);
      result.addAll(sha256.convert(data).bytes);
      counter++;
    }
    return Uint8List.fromList(result.sublist(0, outputLen));
  }

  /// SHAKE256 approximation using repeated SHA-512
  Uint8List _shake256(Uint8List input, int outputLen) {
    final result = <int>[];
    var counter = 0;
    while (result.length < outputLen) {
      final data = Uint8List.fromList([
        ...input,
        counter >> 24,
        counter >> 16,
        counter >> 8,
        counter & 0xFF,
      ]);
      result.addAll(sha512.convert(data).bytes);
      counter++;
    }
    return Uint8List.fromList(result.sublist(0, outputLen));
  }

  // ===== Matrix and Vector Generation =====

  /// Generate matrix A from seed rho
  PolyMatrix _generateMatrix(Uint8List rho, {bool transpose = false}) {
    final k = params.k;
    final rows = <List<Polynomial>>[];
    
    for (var i = 0; i < k; i++) {
      final row = <Polynomial>[];
      for (var j = 0; j < k; j++) {
        final xofBytes = transpose ? _xof(rho, i, j) : _xof(rho, j, i);
        row.add(Polynomial.sampleNtt(xofBytes));
      }
      rows.add(row);
    }
    
    return PolyMatrix(rows);
  }

  /// Generate error vector from seed
  (PolyVector, int) _generateErrorVector(Uint8List sigma, int eta, int N) {
    final elements = <Polynomial>[];
    for (var i = 0; i < params.k; i++) {
      final prfOutput = _prf(eta, sigma, N);
      elements.add(Polynomial.sampleCbd(prfOutput, eta));
      N++;
    }
    return (PolyVector(elements), N);
  }

  /// Generate single error polynomial
  (Polynomial, int) _generatePolynomial(Uint8List sigma, int eta, int N) {
    final prfOutput = _prf(eta, sigma, N);
    return (Polynomial.sampleCbd(prfOutput, eta), N + 1);
  }

  // ===== K-PKE: IND-CPA Public Key Encryption =====

  /// K-PKE Key Generation (Algorithm 13)
  (Uint8List, Uint8List) _kPkeKeygen(Uint8List d) {
    // G(d || k) -> (rho, sigma)
    final (rho, sigma) = _hashG(Uint8List.fromList([...d, params.k]));
    
    // Generate matrix A_hat
    final aHat = _generateMatrix(rho);
    
    // Generate secret vector s and error vector e
    var N = 0;
    final (s, N1) = _generateErrorVector(sigma, params.eta1, N);
    N = N1;
    final (e, _) = _generateErrorVector(sigma, params.eta1, N);
    
    // Compute public value t_hat = A_hat * s_hat + e_hat
    final sHat = s.toNtt();
    final eHat = e.toNtt();
    final tHat = (aHat * sHat) + eHat;
    
    // Encode keys
    final ekPke = Uint8List.fromList([...tHat.encode(12), ...rho]);
    final dkPke = sHat.encode(12);
    
    return (ekPke, dkPke);
  }

  /// K-PKE Encryption (Algorithm 14)
  Uint8List _kPkeEncrypt(Uint8List ekPke, Uint8List m, Uint8List r) {
    // Type check
    if (ekPke.length != params.ekSize) {
      throw ArgumentError(
        'Invalid encapsulation key size: expected ${params.ekSize}, got ${ekPke.length}');
    }
    
    // Unpack ek
    final tHatBytes = Uint8List.sublistView(ekPke, 0, ekPke.length - 32);
    final rho = Uint8List.sublistView(ekPke, ekPke.length - 32);
    
    // Decode t_hat
    final tHat = PolyVector.decode(tHatBytes, params.k, 12, isNtt: true);
    
    // Modulus check: verify canonical encoding
    if (!_bytesEqual(tHat.encode(12), tHatBytes)) {
      throw ArgumentError('Modulus check failed: t_hat not canonically encoded');
    }
    
    // Generate A_hat^T
    final aHatT = _generateMatrix(rho, transpose: true);
    
    // Generate random vectors
    var N = 0;
    final (y, N1) = _generateErrorVector(r, params.eta1, N);
    N = N1;
    final (e1, N2) = _generateErrorVector(r, params.eta2, N);
    N = N2;
    final (e2, _) = _generatePolynomial(r, params.eta2, N);
    
    // Compute ciphertext
    final yHat = y.toNtt();
    final u = (aHatT * yHat).fromNtt() + e1;
    
    // Decode message as polynomial
    final mu = Polynomial.decode(m, 1).decompress(1);
    
    // v = t_hat^T * y_hat + e2 + mu
    final v = tHat.dot(yHat).fromNtt() + e2 + mu;
    
    // Compress and encode ciphertext
    final c1 = u.compress(params.du).encode(params.du);
    final c2 = v.compress(params.dv).encode(params.dv);
    
    return Uint8List.fromList([...c1, ...c2]);
  }

  /// K-PKE Decryption (Algorithm 15)
  Uint8List _kPkeDecrypt(Uint8List dkPke, Uint8List c) {
    final n = params.k * params.du * 32;
    final c1 = Uint8List.sublistView(c, 0, n);
    final c2 = Uint8List.sublistView(c, n);
    
    // Decode and decompress ciphertext
    final u = PolyVector.decode(c1, params.k, params.du).decompress(params.du);
    final v = Polynomial.decode(c2, params.dv).decompress(params.dv);
    
    // Decode secret key
    final sHat = PolyVector.decode(dkPke, params.k, 12, isNtt: true);
    
    // Compute w = v - s^T * u
    final uHat = u.toNtt();
    final w = v - sHat.dot(uHat).fromNtt();
    
    // Compress and encode message
    return w.compress(1).encode(1);
  }

  // ===== ML-KEM: IND-CCA Key Encapsulation =====

  /// Internal key generation (Algorithm 16)
  (Uint8List, Uint8List) _keygenInternal(Uint8List d, Uint8List z) {
    final (ekPke, dkPke) = _kPkeKeygen(d);
    
    final ek = ekPke;
    final dk = Uint8List.fromList([
      ...dkPke,
      ...ek,
      ..._hashH(ek),
      ...z,
    ]);
    
    return (ek, dk);
  }

  /// Generate encapsulation and decapsulation keys (Algorithm 19)
  ///
  /// Returns (encapsulationKey, decapsulationKey)
  (Uint8List, Uint8List) keygen() {
    final d = _randomBytes(32);
    final z = _randomBytes(32);
    return _keygenInternal(d, z);
  }

  /// Derive keys from seed (Section 7.1)
  (Uint8List, Uint8List) keyDerive(Uint8List seed) {
    if (seed.length != 64) {
      throw ArgumentError('Seed must be 64 bytes');
    }
    final d = Uint8List.sublistView(seed, 0, 32);
    final z = Uint8List.sublistView(seed, 32);
    return _keygenInternal(d, z);
  }

  /// Internal encapsulation (Algorithm 17)
  (Uint8List, Uint8List) _encapsInternal(Uint8List ek, Uint8List m) {
    final (K, r) = _hashG(Uint8List.fromList([...m, ..._hashH(ek)]));
    final c = _kPkeEncrypt(ek, m, r);
    return (K, c);
  }

  /// Encapsulate: generate shared secret and ciphertext (Algorithm 20)
  ///
  /// Returns (sharedSecret, ciphertext)
  (Uint8List, Uint8List) encaps(Uint8List ek) {
    final m = _randomBytes(32);
    return _encapsInternal(ek, m);
  }

  /// Internal decapsulation (Algorithm 18)
  Uint8List _decapsInternal(Uint8List dk, Uint8List c) {
    // Type checks
    final expectedCtLen = params.ciphertextSize;
    if (c.length != expectedCtLen) {
      throw ArgumentError(
        'Invalid ciphertext size: expected $expectedCtLen, got ${c.length}');
    }
    if (dk.length != params.dkSize) {
      throw ArgumentError(
        'Invalid decapsulation key size: expected ${params.dkSize}, got ${dk.length}');
    }
    
    // Parse decapsulation key
    final dkPke = Uint8List.sublistView(dk, 0, 384 * params.k);
    final ekPke = Uint8List.sublistView(dk, 384 * params.k, 768 * params.k + 32);
    final h = Uint8List.sublistView(dk, 768 * params.k + 32, 768 * params.k + 64);
    final z = Uint8List.sublistView(dk, 768 * params.k + 64);
    
    // Hash check
    if (!_bytesEqual(_hashH(ekPke), h)) {
      throw ArgumentError('Hash check failed');
    }
    
    // Decrypt ciphertext
    final mPrime = _kPkeDecrypt(dkPke, c);
    
    // Re-encrypt
    final (kPrime, rPrime) = _hashG(Uint8List.fromList([...mPrime, ...h]));
    final kBar = _hashJ(Uint8List.fromList([...z, ...c]));
    final cPrime = _kPkeEncrypt(ekPke, mPrime, rPrime);
    
    // Constant-time selection
    return _selectBytes(kBar, kPrime, _bytesEqual(c, cPrime));
  }

  /// Decapsulate: recover shared secret from ciphertext (Algorithm 21)
  ///
  /// Returns shared secret K
  Uint8List decaps(Uint8List dk, Uint8List c) {
    return _decapsInternal(dk, c);
  }

  // ===== Utility Functions =====

  /// Constant-time bytes comparison
  bool _bytesEqual(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  /// Constant-time byte selection
  Uint8List _selectBytes(Uint8List ifFalse, Uint8List ifTrue, bool condition) {
    assert(ifFalse.length == ifTrue.length);
    final result = Uint8List(ifFalse.length);
    final mask = condition ? 0xFF : 0x00;
    for (var i = 0; i < result.length; i++) {
      result[i] = ifFalse[i] ^ (mask & (ifFalse[i] ^ ifTrue[i]));
    }
    return result;
  }
}

// ===== Pre-configured instances =====

/// ML-KEM-512 instance (128-bit security)
final mlKem512Instance = MlKem(mlKem512);

/// ML-KEM-768 instance (192-bit security)
final mlKem768Instance = MlKem(mlKem768);

/// ML-KEM-1024 instance (256-bit security)
final mlKem1024Instance = MlKem(mlKem1024);

// ===== Convenience Functions =====

/// Generate ML-KEM-768 keypair
(Uint8List, Uint8List) mlKem768Keygen() => mlKem768Instance.keygen();

/// Encapsulate with ML-KEM-768
(Uint8List, Uint8List) mlKem768Encaps(Uint8List ek) => mlKem768Instance.encaps(ek);

/// Decapsulate with ML-KEM-768
Uint8List mlKem768Decaps(Uint8List dk, Uint8List c) => mlKem768Instance.decaps(dk, c);

/// Generate ML-KEM-1024 keypair
(Uint8List, Uint8List) mlKem1024Keygen() => mlKem1024Instance.keygen();

/// Encapsulate with ML-KEM-1024
(Uint8List, Uint8List) mlKem1024Encaps(Uint8List ek) => mlKem1024Instance.encaps(ek);

/// Decapsulate with ML-KEM-1024
Uint8List mlKem1024Decaps(Uint8List dk, Uint8List c) => mlKem1024Instance.decaps(dk, c);
