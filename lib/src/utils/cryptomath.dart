// Ported to Dart from tlslite-ng tlslite/utils/cryptomath.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

//cryptomath.dart

/// cryptomath module
///
/// This module has basic math/crypto code.
import 'dart:typed_data';
import 'dart:math' as math;
import 'dart:convert' show utf8;

import 'codec.dart'; 
import 'digest/digest.dart' as dg;

// --- Helper Functions ---

/// Converts a BigInt to a Uint8List (big-endian, unsigned).
///
/// [byteLength] is the desired output length; leading zeros are added if
/// needed. If the number does not fit, it is truncated (the most significant
/// bytes are dropped).
Uint8List bigIntToBytes(BigInt number, int byteLength, {bool signed = false}) {
  if (number == BigInt.zero) {
    return Uint8List(byteLength);
  }

  // Going through toRadixString(16) and string manipulation would work, but
  // is inefficient; bitwise operations are generally better.

  Uint8List bytes = Uint8List(byteLength);
  for (int i = 0; i < byteLength; i++) {
    bytes[byteLength - 1 - i] = (number & BigInt.from(0xff)).toInt();
    number = number >> 8;
  }

  // If the original number was larger than byteLength allows, `number` still
  // has bits left here; the loop above has already truncated it.
  // A signed (two's complement) representation would need different logic.
  // This function targets the unsigned representation, like most crypto code.

  return bytes;
}

/// Converts a Uint8List to a BigInt (big-endian, unsigned).
BigInt _bytesToBigInt(Uint8List bytes) {
  BigInt result = BigInt.zero;
  for (int i = 0; i < bytes.length; i++) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}

// **************************************************************************
// PRNG Functions
// **************************************************************************

/// Operating system CSPRNG (getrandom/arc4random/BCryptGenRandom).
final math.Random _secureRandom = math.Random.secure();

/// Returns [howMany] cryptographically secure random bytes.
Uint8List getRandomBytes(int howMany) {
  final bytes = Uint8List(howMany);
  var i = 0;
  for (; i + 4 <= howMany; i += 4) {
    final v = _secureRandom.nextInt(0x100000000);
    bytes[i] = v;
    bytes[i + 1] = v >>> 8;
    bytes[i + 2] = v >>> 16;
    bytes[i + 3] = v >>> 24;
  }
  for (; i < howMany; i++) {
    bytes[i] = _secureRandom.nextInt(256);
  }
  return bytes;
}

const String prngName = "Dart Random.secure";

// **************************************************************************
// Simple hash functions
// **************************************************************************

/// Returns the MD5 digest of [b].
Uint8List md5(Uint8List b) {
  return dg.md5Hash(b);
}

/// Returns the SHA-1 digest of [b].
Uint8List sha1(Uint8List b) {
  return dg.sha1Hash(b);
}

/// Returns the digest of [data] using [algorithm] (md5, sha1, sha224,
/// sha256, sha384, sha512, sha3_224, sha3_256, sha3_384, sha3_512).
Uint8List secureHash(Uint8List data, String algorithm) {
  return dg.hashBytes(algorithm, data);
}

/// Returns the HMAC of [b] keyed with [k] using [algorithm].
Uint8List secureHMAC(Uint8List k, Uint8List b, String algorithm) {
  return dg.hmac(algorithm, k, b);
}

Uint8List hmacMd5(Uint8List k, Uint8List b) {
  return secureHMAC(k, b, 'md5');
}

Uint8List hmacSha1(Uint8List k, Uint8List b) {
  return secureHMAC(k, b, 'sha1');
}

Uint8List hmacSha256(Uint8List k, Uint8List b) {
  return secureHMAC(k, b, 'sha256');
}

Uint8List hmacSha384(Uint8List k, Uint8List b) {
  return secureHMAC(k, b, 'sha384');
}

// Returns the digest size of [algorithm]
int _getDigestSize(String algorithm) {
  switch (algorithm.toLowerCase()) {
    case 'md5':
      return 16;
    case 'sha1':
      return 20;
    case 'sha256':
      return 32;
    case 'sha384':
      return 48;
    case 'sha512':
      return 64;
    default:
      return dg.createDigest(algorithm).digestSize;
  }
}

Uint8List hkdfExpand(Uint8List prk, Uint8List info, int L, String algorithm) {
  // Key the HMAC once; each block starts from a clone of that state.
  final prf = dg.createHmac(algorithm, prk);
  final digestSize = prf.digestSize;
  final N = (L + digestSize - 1) ~/ digestSize;
  final out = Uint8List(N * digestSize);
  final counter = Uint8List(1);
  Uint8List tIter = Uint8List(0);

  for (int i = 1; i <= N; i++) {
    // T(i) = HMAC(PRK, T(i-1) | info | i)
    counter[0] = i;
    tIter = (prf.clone()
          ..update(tIter)
          ..update(info)
          ..update(counter))
        .finish();
    out.setRange((i - 1) * digestSize, i * digestSize, tIter);
  }
  // Return the first L bytes
  return out.sublist(0, L);
}

/// PBKDF2 key derivation using HMAC with the requested [hashAlgorithm].
Uint8List pbkdf2(
  Uint8List password,
  Uint8List salt,
  int iterations,
  int derivedKeyLength,
  String hashAlgorithm,
) {
  if (iterations <= 0) {
    throw ArgumentError('iterations must be positive');
  }
  if (derivedKeyLength <= 0) {
    throw ArgumentError('derivedKeyLength must be positive');
  }
  // Key the HMAC once; each iteration starts from a clone of that state.
  final prf = dg.createHmac(hashAlgorithm, password);
  final hLen = prf.digestSize;
  final blocks = (derivedKeyLength + hLen - 1) ~/ hLen;
  final derived = BytesBuilder();
  for (var blockIndex = 1; blockIndex <= blocks; blockIndex++) {
    final counter = numberToByteArray(BigInt.from(blockIndex), howManyBytes: 4);
    var u = (prf.clone()
          ..update(salt)
          ..update(counter))
        .finish();
    final block = Uint8List.fromList(u);
    for (var i = 1; i < iterations; i++) {
      u = (prf.clone()..update(u)).finish();
      for (var j = 0; j < block.length; j++) {
        block[j] ^= u[j];
      }
    }
    derived.add(block);
  }
  final result = derived.toBytes();
  return Uint8List.fromList(result.sublist(0, derivedKeyLength));
}

/// TLS 1.3 key derivation function (HKDF-Expand-Label).
Uint8List hkdfExpandLabel(Uint8List secret, Uint8List label,
    Uint8List hashValue, int length, String algorithm) {
  final hkdfLabel = Writer();
  hkdfLabel.addTwo(length);
  // Prepend "tls13 " to the label
  final labelPrefix = utf8.encode("tls13 ");
  final fullLabel = Uint8List.fromList(labelPrefix + label);
  hkdfLabel.addVarSeq(
      fullLabel, 1, 1); // addVarSeq accepts a Uint8List
  hkdfLabel.addVarSeq(
      hashValue, 1, 1); // addVarSeq accepts a Uint8List

  return hkdfExpand(secret, hkdfLabel.bytes, length, algorithm);
}

/// TLS 1.3 key derivation function (Derive-Secret).
///
/// [handshakeHashes] may be `null` (hash of the empty string is used), the
/// transcript hash itself as a `Uint8List`/`List<int>`, or an object with a
/// `digest(String algorithm)` method returning a `Uint8List`, such as
/// HandshakeHashes.
Uint8List deriveSecret(Uint8List secret, Uint8List label,
    dynamic /*HandshakeHashes?*/ handshakeHashes, String algorithm) {
  Uint8List hsHash;
  if (handshakeHashes == null) {
    hsHash = secureHash(Uint8List(0), algorithm);
  } else if (handshakeHashes is Uint8List) {
    hsHash = handshakeHashes;
  } else if (handshakeHashes is List<int>) {
    hsHash = Uint8List.fromList(handshakeHashes);
  } else {
    // Expect an object with a digest(algorithm) method
    hsHash = handshakeHashes.digest(algorithm) as Uint8List;
  }

  final digestSize = _getDigestSize(algorithm);
  return hkdfExpandLabel(secret, label, hsHash, digestSize, algorithm);
}

// **************************************************************************
// Converter Functions
// **************************************************************************

/// Converts a number stored in a Uint8List to a BigInt.
///
/// Big-endian encoding is assumed by default; pass `endian: "little"` for
/// little-endian.
BigInt bytesToNumber(Uint8List b, {String endian = "big"}) {
  if (endian.toLowerCase() == "little") {
    // Little-endian
    BigInt result = BigInt.zero;
    for (int i = 0; i < b.length; i++) {
      result |= BigInt.from(b[i]) << (8 * i);
    }
    return result;
  } else {
    // Big-endian (default)
    return _bytesToBigInt(b);
  }
}

/// Converts a BigInt to a Uint8List, zero-padded to [howManyBytes].
///
/// The result is never longer than [howManyBytes]: a number that does not fit
/// is truncated. Uses big- or little-endian encoding; big-endian is the
/// default.
Uint8List numberToByteArray(BigInt n,
    {int? howManyBytes, String endian = "big"}) {
  if (n < BigInt.zero) {
    // The original implementation assumes non-negative numbers. Converting a
    // negative BigInt would need two's complement logic, so it is rejected.
    throw ArgumentError("Number must be non-negative for this conversion.");
  }
  if (n == BigInt.zero) {
    return Uint8List(howManyBytes ?? 1); // [0] or a list of zeros
  }

  int length = (n.bitLength + 7) ~/ 8; // Minimum number of bytes
  int targetLength =
      howManyBytes ?? length; // howManyBytes if given, else the minimum

  Uint8List bytes = Uint8List(targetLength);
  BigInt tempN = n;

  if (endian.toLowerCase() == "little") {
    for (int i = 0; i < targetLength; i++) {
      if (tempN == BigInt.zero) break; // Stop once the number is exhausted
      bytes[i] = (tempN & BigInt.from(0xff)).toInt();
      tempN >>= 8;
    }
    // Truncation: if howManyBytes was smaller than 'length', the most
    // significant bytes were skipped by the loop bound (targetLength).
  } else {
    // Big-endian
    int startIdx =
        targetLength - length; // Where to start filling the output array
    if (startIdx < 0) {
      // The number is larger than howManyBytes and must be truncated:
      // drop its most significant bytes
      tempN >>= ((-startIdx) * 8);
      startIdx = 0;
    }

    for (int i = targetLength - 1; i >= startIdx; i--) {
      bytes[i] = (tempN & BigInt.from(0xff)).toInt();
      tempN >>= 8;
      if (tempN == BigInt.zero && i > startIdx)
        break; // Optimization: stop if the rest is zero
    }
    // Zero padding: bytes before startIdx are already zero from the Uint8List
    // allocation. Truncation: handled by startIdx and the shift of tempN.
  }

  return bytes;
}

/// Converts an MPI (OpenSSL bignum string) to a BigInt.
BigInt mpiToNumber(Uint8List mpi) {
  // MPI format: 4-byte length (big-endian) followed by the number bytes (big-endian)
  if (mpi.length < 4) {
    throw ArgumentError("Invalid MPI format: too short");
  }
  // The length prefix is ignored; the actual data length is used instead
  // int length = (mpi[0] << 24) | (mpi[1] << 16) | (mpi[2] << 8) | mpi[3];

  final dataBytes = mpi.sublist(4);

  // Check the sign bit (the original checked the first data byte)
  if (dataBytes.isNotEmpty && (dataBytes[0] & 0x80) != 0) {
    // The original implementation rejects negative numbers as well. An MPI
    // may carry an extra leading 0x00 byte to mark a positive value whose
    // next byte has its top bit set; supporting negatives would need two's
    // complement logic. Keep the original restriction:
    throw ArgumentError("Input must be a positive integer (MPI sign bit set)");
  }
  return bytesToNumber(dataBytes); // Big-endian by default
}

/// Converts a BigInt to an MPI (OpenSSL bignum string).
Uint8List numberToMPI(BigInt n) {
  if (n < BigInt.zero) {
    throw ArgumentError(
        "Cannot convert negative number to MPI format (in this implementation)");
  }

  Uint8List b = numberToByteArray(n, endian: "big"); // Number bytes

  // Strip leading zeros, except for a lone [0] byte
  int firstNonZero = 0;
  while (firstNonZero < b.length - 1 && b[firstNonZero] == 0) {
    firstNonZero++;
  }
  if (firstNonZero > 0) {
    b = b.sublist(firstNonZero);
  }

  bool prependZero = false;
  // If the top bit of the first byte is set, prepend an extra zero byte to
  // mark the value as positive.
  if (b.isNotEmpty && (b[0] & 0x80) != 0) {
    prependZero = true;
  }
  if (n == BigInt.zero && b.isEmpty) {
    // Special case for the number 0
    b = Uint8List(1); // Encoded as a single 0 byte
    // prependZero stays false
  }

  int length = b.length + (prependZero ? 1 : 0);

  // Build the result: 4-byte length + [optional 0x00] + number bytes
  final result = Uint8List(4 + length);

  // Write the length (big-endian)
  result[0] = (length >> 24) & 0xFF;
  result[1] = (length >> 16) & 0xFF;
  result[2] = (length >> 8) & 0xFF;
  result[3] = length & 0xFF;

  int dataOffset = 4;
  if (prependZero) {
    result[dataOffset] = 0x00;
    dataOffset++;
  }

  // Copy the number bytes
  result.setRange(dataOffset, dataOffset + b.length, b);

  return result;
}

// **************************************************************************
// Misc. Utility Functions
// **************************************************************************

/// Returns the number of bits needed to represent [n].
int numBits(BigInt n) {
  return n.bitLength;
}

/// Returns the number of bytes needed to represent [n].
int numBytes(BigInt n) {
  if (n == BigInt.zero) return 1;
  return (n.bitLength + 7) ~/ 8;
}

// **************************************************************************
// Big Number Math
// **************************************************************************

/// Returns a random BigInt in the range [low, high).
BigInt getRandomNumber(BigInt low, BigInt high) {
  assert(low < high);

  BigInt range = high - low;
  int bits = range.bitLength;
  int bytes = (bits + 7) ~/ 8;

  BigInt result;
  do {
    Uint8List randomBytes = getRandomBytes(bytes);
    result = _bytesToBigInt(randomBytes); // Big-endian unsigned

    // Rejection sampling: if the candidate is not below range, discard it and
    // draw again. This keeps the distribution uniform (no modulo bias).
    // E.g. range = 10 (0-9), bits = 4: a draw of 1111 (15) is rejected.
  } while (result >= range);

  return low + result;
}

/// Greatest common divisor.
BigInt gcd(BigInt a, BigInt b) {
  return a.gcd(b);
}

/// Least common multiple.
BigInt lcm(BigInt a, BigInt b) {
  if (a == BigInt.zero || b == BigInt.zero) return BigInt.zero;
  return (a * b).abs() ~/ a.gcd(b);
}

/// Returns the inverse of [a] mod [b], or zero if it does not exist.
BigInt invMod(BigInt a, BigInt b) {
  try {
    // modInverse throws RangeError if a == 0 or no inverse exists (gcd != 1)
    if (a == BigInt.zero || b <= BigInt.zero) return BigInt.zero;
    if (a.gcd(b) != BigInt.one) return BigInt.zero; // No inverse
    return a.modInverse(b);
  } catch (e) {
    // RangeError means gcd != 1
    if (e is RangeError) {
      return BigInt.zero;
    }
    // Rethrow any other unexpected error
    rethrow;
  }
}

/// Computes (base^power) % modulus.
BigInt powMod(BigInt base, BigInt power, BigInt modulus) {
  return base.modPow(power, modulus);
}

/// Integer division rounded up.
BigInt divceil(BigInt dividend, BigInt divisor) {
  if (divisor == BigInt.zero) throw ArgumentError("Division by zero");
  // (dividend + divisor - 1) / divisor, valid for positive integers;
  // negative operands are not handled
  if (dividend == BigInt.zero) return BigInt.zero;
  final one = BigInt.one;
  return (dividend + divisor - one) ~/ divisor;
}

// Returns the primes below n (sieve of Eratosthenes):
List<int> makeSieve(int n) {
  if (n < 2) return [];
  List<int?> sieve = List<int?>.generate(n, (i) => i); // null marks composites
  sieve[0] = null;
  sieve[1] = null;

  int limit = math.sqrt(n).toInt();
  for (int count = 2; count <= limit; count++) {
    if (sieve[count] == null) {
      continue;
    }
    // Mark multiples
    for (int x = count * 2; x < n; x += count) {
      sieve[x] = null;
    }
  }
  // Keep the non-null entries as a List<int>
  return sieve.whereType<int>().toList();
}

// Default sieve for isPrime (primes < 1000)
final List<int> _defaultSieve = makeSieve(1000);

/// Tests whether [n] is prime using trial division and Miller-Rabin.
bool isPrime(BigInt n,
    {int iterations = 5, bool display = false, List<int>? sieve}) {
  sieve ??= _defaultSieve;

  if (n <= BigInt.one) return false;
  if (n <= BigInt.from(3)) return true; // 2 and 3 are prime
  if (n.isEven) return false; // Even numbers above 2 are not prime

  // Trial division by the sieve primes
  for (int x in sieve) {
    BigInt bx = BigInt.from(x);
    if (bx >= n) break; // Stop once the sieve prime is >= n
    if (n % bx == BigInt.zero) return false; // Divisible: not prime
  }

  // Trial division passed; continue with Miller-Rabin
  if (display) print("*"); // Python: print("*", end=' ')

  // Compute s, t for Miller-Rabin: n-1 = 2^t * s, with s odd
  BigInt s = n - BigInt.one;
  int t = 0;
  while (s.isEven) {
    s = s >> 1; // Fast division by 2
    t++;
  }

  // Run Miller-Rabin 'iterations' times
  for (int count = 0; count < iterations; count++) {
    // Pick a random base 'a'; the first iteration uses a=2 for speed
    // (as the original does)
    BigInt a = (count == 0)
        ? BigInt.two
        : getRandomNumber(
            BigInt.two, n - BigInt.one); // a in the range [2, n-2]

    BigInt v = powMod(a, s, n); // v = a^s mod n

    if (v == BigInt.one || v == n - BigInt.one) {
      continue; // Probably prime; try the next base
    }

    bool possiblePrime = false;
    for (int i = 1; i < t; i++) {
      // Loop from 1 to t-1
      v = powMod(v, BigInt.two, n); // v = v^2 mod n
      if (v == n - BigInt.one) {
        possiblePrime = true; // Miller-Rabin condition met
        break;
      }
      if (v == BigInt.one) {
        return false; // Non-trivial square root of 1 mod n: composite
      }
    }

    if (!possiblePrime) {
      return false; // Base 'a' is a Miller-Rabin witness: composite
    }
  }

  return true; // Passed every iteration: probably prime
}

/// Returns a random prime of [bits] bits.
///
/// The result is at least (2^(bits-1) * 3) / 2 and less than 2^bits.
BigInt getRandomPrime(int bits, {bool display = false}) {
  assert(bits >= 10);

  // Make sure the two most significant bits are set.
  // low = floor(1.5 * 2^(bits-1)) = floor(3 * 2^(bits-2))
  BigInt low = (BigInt.from(3) << (bits - 2));
  // high = 2^bits
  BigInt high = BigInt.one << bits;

  while (true) {
    if (display) print(".");

    // Random candidate in the range [low, high)
    BigInt candP = getRandomNumber(low, high);

    // Make it odd
    if (candP.isEven) {
      candP += BigInt.one;
      // Adding 1 can (rarely) push candP to high; just draw a new number.
      if (candP >= high) continue;
    }

    // Primality test with a reasonable number of iterations
    // (more iterations give more confidence)
    if (isPrime(candP, iterations: 15, display: display)) {
      return candP;
    }
  }
}

/// Returns a random safe prime p of [bits] bits.
///
/// Both p and q = (p-1)/2 are prime.
BigInt getRandomSafePrime(int bits, {bool display = false}) {
  assert(bits >= 10);

  // Pick q from a range such that p = 2q+1 has 'bits' bits.
  // If p ~ 2^bits, then q ~ 2^(bits-1).
  // The range for q mirrors the one used by getRandomPrime.
  BigInt qLow = (BigInt.from(3) << (bits - 3)); // For q ~ 2^(bits-1)
  BigInt qHigh = BigInt.one << (bits - 1);

  while (true) {
    if (display) print(".");

    // Candidate for q
    BigInt q = getRandomNumber(qLow, qHigh);

    // q must be odd (required for p=2q+1 to be a prime > 3)
    if (q.isEven) {
      q += BigInt.one;
      if (q >= qHigh) continue;
    }

    // Test q first (cheaper to fail here), with fewer iterations;
    // p gets more iterations once q looks prime
    if (isPrime(q, iterations: 5, display: display)) {
      BigInt p = (q * BigInt.two) + BigInt.one;

      // Check that p has the requested bit length; if q was close to the
      // upper bound, p may have bits+1 bits.
      if (p.bitLength != bits) {
        continue; // Try another q
      }

      // Test p more rigorously
      if (isPrime(p, iterations: 15, display: display)) {
        // Re-test q more rigorously as well (optional, but safer)
        if (isPrime(q, iterations: 15, display: display)) {
          return p; // Found a safe prime
        }
      }
    }
  }
}
