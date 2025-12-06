/// ML-KEM (FIPS 203) Implementation.
///
/// Implements the Module Lattice-based Key Encapsulation Mechanism.
library;

import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/digests/sha3.dart';
import 'package:pointycastle/digests/shake.dart';
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

  int get _polyVectorBytes => params.k * 32 * 12;
  int get _ciphertextUBytes => params.k * params.du * 32;
  int get _ciphertextVBytes => 32 * params.dv;

  // ===== Hash Functions (Section 4 of FIPS 203) =====

  /// H: SHA3-256 hash (FIPS 203 Section 4)
  Uint8List _hashH(Uint8List input) {
    final digest = SHA3Digest(256);
    final out = Uint8List(digest.digestSize);
    digest.update(input, 0, input.length);
    digest.doFinal(out, 0);
    return out;
  }

  /// J: SHAKE256 with 32-byte output
  Uint8List _hashJ(Uint8List input) {
    return _shake(256, input, 32);
  }

  /// G: SHA3-512 split into two 32-byte values
  (Uint8List, Uint8List) _hashG(Uint8List input) {
    final digest = SHA3Digest(512);
    final out = Uint8List(digest.digestSize);
    digest.update(input, 0, input.length);
    digest.doFinal(out, 0);
    return (
      Uint8List.sublistView(out, 0, 32),
      Uint8List.sublistView(out, 32, 64),
    );
  }

  /// XOF: SHAKE128 - Extendable Output Function
  /// Per FIPS 203 Section 4.9: XOF(rho, i, j) = SHAKE128(rho || i || j)
  Uint8List _xof(Uint8List rho, int i, int j) {
    // SHAKE128(rho || i || j) with sufficient output
    final input = Uint8List.fromList([...rho, i, j]);
    return _shake128(input, 840);
  }

  /// PRF: SHAKE256 for pseudorandom function
  Uint8List _prf(int eta, Uint8List s, int b) {
    final input = Uint8List.fromList([...s, b]);
    return _shake256(input, 64 * eta);
  }

  /// SHAKE128 XOF
  Uint8List _shake128(Uint8List input, int outputLen) {
    return _shake(128, input, outputLen);
  }

  /// SHAKE256 XOF
  Uint8List _shake256(Uint8List input, int outputLen) {
    return _shake(256, input, outputLen);
  }

  Uint8List _shake(int strength, Uint8List input, int outputLen) {
    final digest = SHAKEDigest(strength);
    digest.update(input, 0, input.length);
    final out = Uint8List(outputLen);
    digest.doFinalRange(out, 0, out.length);
    return out;
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

  // ===== Serialization Helpers (mirrors pack/unpack routines) =====

  Uint8List _packPublicKey(PolyVector t, Uint8List rho) {
    assert(rho.length == 32);
    final tBytes = t.encode(12);
    return Uint8List.fromList([...tBytes, ...rho]);
  }

  (PolyVector, Uint8List) _unpackPublicKey(Uint8List pk) {
    final tBytes = Uint8List.sublistView(pk, 0, _polyVectorBytes);
    final rho = Uint8List.sublistView(pk, _polyVectorBytes);
    // t_hat is stored in NTT domain
    final t = PolyVector.decode(tBytes, params.k, 12, isNtt: true);
    if (!_bytesEqual(t.encode(12), tBytes)) {
      throw ArgumentError('Modulus check failed: t_hat not canonically encoded');
    }
    return (t, rho);
  }

  Uint8List _packSecretKey(PolyVector s) {
    return s.encode(12);
  }

  PolyVector _unpackSecretKey(Uint8List sk) {
    // s_hat is stored in NTT domain
    return PolyVector.decode(sk, params.k, 12, isNtt: true);
  }

  Uint8List _packCiphertext(PolyVector u, Polynomial v) {
    final c1 = u.compress(params.du).encode(params.du);
    final c2 = v.compress(params.dv).encode(params.dv);
    return Uint8List.fromList([...c1, ...c2]);
  }

  (PolyVector, Polynomial) _unpackCiphertext(Uint8List c) {
    if (c.length != params.ciphertextSize) {
      throw ArgumentError(
        'Invalid ciphertext size: expected ${params.ciphertextSize}, got ${c.length}');
    }
    final c1 = Uint8List.sublistView(c, 0, _ciphertextUBytes);
    final c2 = Uint8List.sublistView(c, _ciphertextUBytes, _ciphertextUBytes + _ciphertextVBytes);
    final u = PolyVector.decode(c1, params.k, params.du).decompress(params.du);
    final v = Polynomial.decode(c2, params.dv).decompress(params.dv);
    return (u, v);
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

    // Note: ek_pke stores t_hat (NTT domain), dk_pke stores s_hat (NTT domain)
    // This matches FIPS 203 and kyber-py reference
    final ekPke = _packPublicKey(tHat, rho);
    final dkPke = _packSecretKey(sHat);
    
    return (ekPke, dkPke);
  }

  /// K-PKE Encryption (Algorithm 14)
  Uint8List _kPkeEncrypt(Uint8List ekPke, Uint8List m, Uint8List r) {
    // Type check
    if (ekPke.length != params.ekSize) {
      throw ArgumentError(
        'Invalid encapsulation key size: expected ${params.ekSize}, got ${ekPke.length}');
    }
    
    // Unpack ek - t_hat is already in NTT domain
    final (tHat, rho) = _unpackPublicKey(ekPke);
    
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
    final mu = Polynomial.fromMessage(m);
    
    // v = t_hat^T * y_hat + e2 + mu
    final v = tHat.dot(yHat).fromNtt() + e2 + mu;
    
    return _packCiphertext(u, v);
  }

  /// K-PKE Decryption (Algorithm 15)
  Uint8List _kPkeDecrypt(Uint8List dkPke, Uint8List c) {
    final (u, v) = _unpackCiphertext(c);
    // s_hat is already in NTT domain from keygen
    final sHat = _unpackSecretKey(dkPke);
    
    // Compute w = v - s^T * u
    final uHat = u.toNtt();
    final w = v - sHat.dot(uHat).fromNtt();
    
    // Convert back to 32-byte message
    return w.toMessage();
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
    final skLen = _polyVectorBytes;
    final ekLen = params.ekSize;
    final dkPke = Uint8List.sublistView(dk, 0, skLen);
    final ekPke = Uint8List.sublistView(dk, skLen, skLen + ekLen);
    final h = Uint8List.sublistView(dk, skLen + ekLen, skLen + ekLen + 32);
    final z = Uint8List.sublistView(dk, skLen + ekLen + 32);
    
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
