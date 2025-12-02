import 'dart:typed_data';
import 'dart:math' as math;
import 'package:crypto/crypto.dart';

import 'constants.dart';
import 'utils/cryptomath.dart';
import 'utils/tlshmac.dart';
import 'ffdhe_groups.dart';

// TODO(port): Missing createHMAC/createMAC_SSL functions

/// Return approximate security level in bits for DH/DSA/RSA parameters.
int paramStrength(BigInt param) {
  final size = numBits(param);
  if (size < 512) return 48;
  if (size < 768) return 56;
  if (size < 816) return 64;
  if (size < 1023) return 72;
  if (size < 1535) return 80; // NIST SP 800-57
  if (size < 2047) return 88;
  if (size < 3071) return 112; // NIST SP 800-57
  if (size < 4095) return 128; // NIST SP 800-57
  if (size < 6144) return 152;
  if (size < 7679) return 168;
  if (size < 15359) return 192; // NIST SP 800-57
  return 256; // NIST SP 800-57
}

/// Internal P_hash function for TLS PRF calculation.
Uint8List pHash(String macName, List<int> secret, List<int> seed, int length) {
  final ret = Uint8List(length);
  final seedBytes = Uint8List.fromList(seed);
  var A = seedBytes;
  var index = 0;

  final mac = TlsHmac(secret, digestmod: macName);

  while (index < length) {
    final aFun = mac.copy();
    aFun.update(A);
    A = aFun.digest();

    final outFun = mac.copy();
    outFun.update(A);
    outFun.update(seedBytes);
    final output = outFun.digest();

    final howMany = math.min(length - index, output.length);
    ret.setRange(index, index + howMany, output);
    index += howMany;
  }
  return ret;
}

/// TLS 1.0/1.1 PRF (uses both MD5 and SHA1).
Uint8List prf(List<int> secret, List<int> label, List<int> seed, int length) {
  final secretLen = secret.length;
  final halfLen = (secretLen / 2).ceil();

  // Split secret into two halves (may share a byte if odd length)
  final s1 = secret.sublist(0, halfLen);
  final s2 = secret.sublist((secretLen / 2).floor());

  // Run left half through P_MD5 and right half through P_SHA1
  final pMd5 = pHash('md5', s1, [...label, ...seed], length);
  final pSha1 = pHash('sha1', s2, [...label, ...seed], length);

  // XOR the outputs
  for (var i = 0; i < length; i++) {
    pMd5[i] ^= pSha1[i];
  }
  return pMd5;
}

/// TLS 1.2 PRF using SHA256.
Uint8List prf12(List<int> secret, List<int> label, List<int> seed, int length) {
  return pHash('sha256', secret, [...label, ...seed], length);
}

/// TLS 1.2 PRF using SHA384 (for certain cipher suites).
Uint8List prf12Sha384(
  List<int> secret,
  List<int> label,
  List<int> seed,
  int length,
) {
  return pHash('sha384', secret, [...label, ...seed], length);
}

/// SSL 3.0 PRF.
Uint8List prfSsl(List<int> secret, List<int> seed, int length) {
  final bytes = Uint8List(length);
  var index = 0;

  for (var x = 0; x < 26; x++) {
    final charCode = 'A'.codeUnitAt(0) + x;
    final A = Uint8List(x + 1)..fillRange(0, x + 1, charCode);
    final combined = Uint8List.fromList([...A, ...secret, ...seed]);
    final input = Uint8List.fromList([...secret, ...SHA1(combined)]);
    final output = MD5(input);

    for (final c in output) {
      if (index >= length) return bytes;
      bytes[index++] = c;
    }
  }
  return bytes;
}

/// Calculate Extended Master Secret from premaster and handshake hashes.
/// 
/// Deprecated: Use [calcKey] instead.
Uint8List calcExtendedMasterSecret(
  List<int> version,
  int cipherSuite,
  List<int> premasterSecret,
  dynamic handshakeHashes, // HandshakeHashes object
) {
  assert(version[0] == 3 && version[1] >= 1 && version[1] <= 3);

  if (version[1] == 1 || version[1] == 2) {
    // TLS 1.0/1.1
    final md5 = handshakeHashes.digest('md5');
    final sha1 = handshakeHashes.digest('sha1');
    return prf(
      premasterSecret,
      'extended master secret'.codeUnits,
      [...md5, ...sha1],
      48,
    );
  } else {
    // TLS 1.2
    if (CipherSuite.sha384PrfSuites.contains(cipherSuite)) {
      final sha384 = handshakeHashes.digest('sha384');
      return prf12Sha384(
        premasterSecret,
        'extended master secret'.codeUnits,
        sha384,
        48,
      );
    } else {
      final sha256 = handshakeHashes.digest('sha256');
      return prf12(
        premasterSecret,
        'extended master secret'.codeUnits,
        sha256,
        48,
      );
    }
  }
}

/// Derive Master Secret from premaster secret and random values.
/// 
/// Deprecated: Use [calcKey] instead.
Uint8List calcMasterSecret(
  List<int> version,
  int cipherSuite,
  List<int> premasterSecret,
  List<int> clientRandom,
  List<int> serverRandom,
) {
  if (version[0] == 3 && version[1] == 0) {
    // SSL 3.0
    return prfSsl(premasterSecret, [...clientRandom, ...serverRandom], 48);
  } else if (version[0] == 3 && (version[1] == 1 || version[1] == 2)) {
    // TLS 1.0/1.1
    return prf(
      premasterSecret,
      'master secret'.codeUnits,
      [...clientRandom, ...serverRandom],
      48,
    );
  } else if (version[0] == 3 && version[1] == 3) {
    // TLS 1.2
    if (CipherSuite.sha384PrfSuites.contains(cipherSuite)) {
      return prf12Sha384(
        premasterSecret,
        'master secret'.codeUnits,
        [...clientRandom, ...serverRandom],
        48,
      );
    } else {
      return prf12(
        premasterSecret,
        'master secret'.codeUnits,
        [...clientRandom, ...serverRandom],
        48,
      );
    }
  } else {
    throw AssertionError('Unsupported TLS version: $version');
  }
}

/// Calculate the Handshake protocol Finished value.
/// 
/// Deprecated: Use [calcKey] instead.
Uint8List calcFinished(
  List<int> version,
  List<int> masterSecret,
  int cipherSuite,
  dynamic handshakeHashes, // HandshakeHashes object
  bool isClient,
) {
  assert(version[0] == 3 && version[1] >= 0 && version[1] <= 3);

  if (version[0] == 3 && version[1] == 0) {
    // SSL 3.0
    final senderStr = isClient
        ? Uint8List.fromList([0x43, 0x4C, 0x4E, 0x54]) // "CLNT"
        : Uint8List.fromList([0x53, 0x52, 0x56, 0x52]); // "SRVR"
    return handshakeHashes.digestSSL(masterSecret, senderStr);
  } else {
    // TLS 1.0+
    final label = isClient ? 'client finished'.codeUnits : 'server finished'.codeUnits;

    if (version[1] == 1 || version[1] == 2) {
      // TLS 1.0/1.1
      final handshakeHash = handshakeHashes.digest();
      return prf(masterSecret, label, handshakeHash, 12);
    } else {
      // TLS 1.2
      if (CipherSuite.sha384PrfSuites.contains(cipherSuite)) {
        final handshakeHash = handshakeHashes.digest('sha384');
        return prf12Sha384(masterSecret, label, handshakeHash, 12);
      } else {
        final handshakeHash = handshakeHashes.digest('sha256');
        return prf12(masterSecret, label, handshakeHash, 12);
      }
    }
  }
}

/// Universal key calculation method for TLS.
///
/// Can calculate: finished value, master secret, extended master secret, or key expansion.
///
/// - [version]: TLS protocol version tuple (e.g., [3, 3] for TLS 1.2)
/// - [secret]: Master secret or premaster secret
/// - [cipherSuite]: Negotiated cipher suite
/// - [label]: Key derivation label (e.g., 'master secret', 'key expansion')
/// - [handshakeHashes]: Running hash of handshake messages (for finished/EMS)
/// - [clientRandom]: Client random (for master secret/key expansion)
/// - [serverRandom]: Server random (for master secret/key expansion)
/// - [outputLength]: Number of output bytes (defaults based on label)
Uint8List calcKey(
  List<int> version,
  List<int> secret,
  int cipherSuite,
  List<int> label, {
  dynamic handshakeHashes,
  List<int>? clientRandom,
  List<int>? serverRandom,
  int? outputLength,
}) {
  // SSL 3.0 special cases
  if (version[0] == 3 && version[1] == 0) {
    if (String.fromCharCodes(label) == 'client finished') {
      final senderStr = Uint8List.fromList([0x43, 0x4C, 0x4E, 0x54]);
      return handshakeHashes.digestSSL(secret, senderStr);
    } else if (String.fromCharCodes(label) == 'server finished') {
      final senderStr = Uint8List.fromList([0x53, 0x52, 0x56, 0x52]);
      return handshakeHashes.digestSSL(secret, senderStr);
    } else {
      // key expansion or master secret
      assert(clientRandom != null && serverRandom != null);
      return prfSsl(secret, [...clientRandom!, ...serverRandom!], outputLength ?? 48);
    }
  }

  // TLS 1.0/1.1
  else if (version[0] == 3 && (version[1] == 1 || version[1] == 2)) {
    List<int> seed;
    if (String.fromCharCodes(label) == 'extended master secret') {
      final md5 = handshakeHashes.digest('md5');
      final sha1 = handshakeHashes.digest('sha1');
      seed = [...md5, ...sha1];
    } else if (String.fromCharCodes(label).endsWith('finished')) {
      seed = handshakeHashes.digest();
    } else {
      // key expansion or master secret
      assert(clientRandom != null && serverRandom != null);
      seed = [...clientRandom!, ...serverRandom!];
    }
    return prf(secret, label, seed, outputLength ?? 48);
  }

  // TLS 1.2
  else if (version[0] == 3 && version[1] == 3) {
    final useSha384 = CipherSuite.sha384PrfSuites.contains(cipherSuite);
    List<int> seed;

    if (String.fromCharCodes(label) == 'extended master secret') {
      seed = handshakeHashes.digest(useSha384 ? 'sha384' : 'sha256');
    } else if (String.fromCharCodes(label).endsWith('finished')) {
      seed = handshakeHashes.digest(useSha384 ? 'sha384' : 'sha256');
    } else {
      // key expansion or master secret
      assert(clientRandom != null && serverRandom != null);
      seed = [...clientRandom!, ...serverRandom!];
    }

    if (useSha384) {
      return prf12Sha384(secret, label, seed, outputLength ?? 48);
    } else {
      return prf12(secret, label, seed, outputLength ?? 48);
    }
  }

  // TLS 1.3 (future)
  else {
    throw UnimplementedError('TLS 1.3 key derivation not yet implemented');
  }
}

// ============================================================================
// SRP (Secure Remote Password) Helpers
// ============================================================================

/// Calculate the SRP 'x' value from salt, username, and password.
/// x = SHA1(salt | SHA1(username | ":" | password))
BigInt makeX(List<int> salt, List<int> username, List<int> password) {
  if (username.length >= 256) {
    throw ArgumentError('username too long');
  }
  if (salt.length >= 256) {
    throw ArgumentError('salt too long');
  }
  
  final innerHash = Uint8List.fromList(
    sha1.convert([...username, 58, ...password]).bytes // 58 = ':'
  );
  final outerHash = Uint8List.fromList(
    sha1.convert([...salt, ...innerHash]).bytes
  );
  return bytesToNumber(outerHash);
}

/// Create an SRP verifier for the given username and password.
/// Returns (N, g, salt, verifier) tuple.
/// 
/// [bits] must be one of: 1024, 1536, 2048, 3072, 4096, 6144, or 8192.
(BigInt, BigInt, Uint8List, BigInt) makeVerifier(
    List<int> username, List<int> password, int bits) {
  // Map bit sizes to goodGroupParameters indices
  final bitsIndex = {
    1024: 0, 1536: 1, 2048: 2, 3072: 3, 
    4096: 4, 6144: 5, 8192: 6
  }[bits];
  
  if (bitsIndex == null) {
    throw ArgumentError('Invalid bits value: $bits');
  }
  
  final group = goodGroupParameters[bitsIndex];
  final g = group.generator;
  final N = group.prime;
  final salt = Uint8List.fromList(getRandomBytes(16));
  final x = makeX(salt, username, password);
  final verifier = powMod(g, x, N);
  
  return (N, g, salt, verifier);
}

/// Pad a number to the same byte length as N.
Uint8List pad(BigInt n, BigInt x) {
  final nLength = numberToByteArray(n).length;
  final b = numberToByteArray(x);
  if (b.length < nLength) {
    return Uint8List.fromList([...List<int>.filled(nLength - b.length, 0), ...b]);
  }
  return b;
}

/// Calculate SRP 'u' value: u = SHA1(PAD(N, A) | PAD(N, B))
BigInt makeU(BigInt N, BigInt A, BigInt B) {
  final paddedA = pad(N, A);
  final paddedB = pad(N, B);
  return bytesToNumber(
    Uint8List.fromList(sha1.convert([...paddedA, ...paddedB]).bytes)
  );
}

/// Calculate SRP 'k' value: k = SHA1(N | PAD(N, g))
BigInt makeK(BigInt N, BigInt g) {
  final nBytes = numberToByteArray(N);
  final paddedG = pad(N, g);
  return bytesToNumber(
    Uint8List.fromList(sha1.convert([...nBytes, ...paddedG]).bytes)
  );
}

/// Well-known SRP group parameters from RFC 5054.
/// Each entry is a tuple of (generator, prime).
final List<FfdheGroup> goodGroupParameters = [
  // RFC 5054, 1, 1024-bit Group
  FfdheGroup(
    BigInt.from(2),
    BigInt.parse(
      'EEAF0AB9ADB38DD69C33F80AFA8FC5E860726187'
      '75FF3C0B9EA2314C9C256576D674DF7496EA81D3'
      '383B4813D692C6E0E0D5D8E250B98BE48E495C1D'
      '6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D49'
      '82559B297BCF1885C529F566660E57EC68EDBC3C'
      '05726CC02FD4CBF4976EAA9AFD5138FE8376435B'
      '9FC61D2FC0EB06E3',
      radix: 16,
    ),
    'RFC5054 1024-bit',
  ),
  // RFC 5054, 2, 1536-bit Group
  FfdheGroup(
    BigInt.from(2),
    BigInt.parse(
      '9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF4'
      '99AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE'
      '51C6A94BE4607A291558903BA0D0F84380B655BB'
      '9A22E8DCDF028A7CEC67F0D08134B1C8B9798914'
      '9B609E0BE3BAB63D475483819DBC5B1FC764E3F4B'
      '53DD9DA1158BFD3E2B9C8CF56EDF019539349627'
      'DB2FD53D24B7C48665772E437D6C7F8CE442734A'
      'F7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E'
      '5A021FFF5E91479E8CE7A28C2442C6F315180F93'
      '499A234DCF76E3FED135F9BB',
      radix: 16,
    ),
    'RFC5054 1536-bit',
  ),
  // RFC 5054, 3, 2048-bit Group
  FfdheGroup(
    BigInt.from(2),
    BigInt.parse(
      'AC6BDB41324A9A9BF166DE5E1389582FAF72B665'
      '1987EE07FC3192943DB56050A37329CBB4A099ED'
      '8193E0757767A13DD52312AB4B03310DCD7F48A9'
      'DA04FD50E8083969EDB767B0CF6095179A163AB3'
      '661A05FBD5FAAAE82918A9962F0B93B855F97993'
      'EC975EEAA80D740ADBF4FF747359D041D5C33EA7'
      '1D281E446B14773BCA97B43A23FB801676BD207A'
      '436C6481F1D2B9078717461A5B9D32E688F87748'
      '544523B524B0D57D5EA77A2775D2ECFA032CFBDB'
      'F52FB37861602790104E57AE6AF874E7303CE5329'
      '9CCC041C7BC308D82A5698F3A8D0C38271AE35F8'
      'E9DBFBB694B5C803D89F7AE435DE236D525F5475'
      '9B65E372FCD68EF20FA7111F9E4AFF73',
      radix: 16,
    ),
    'RFC5054 2048-bit',
  ),
  // RFC 5054, 4, 3072-bit Group
  FfdheGroup(
    BigInt.from(5),
    rfc3526Group15.prime, // Same as RFC 3526 group 15
    'RFC5054 3072-bit',
  ),
  // RFC 5054, 5, 4096-bit Group
  FfdheGroup(
    BigInt.from(5),
    rfc3526Group16.prime, // Same as RFC 3526 group 16
    'RFC5054 4096-bit',
  ),
  // RFC 5054, 6, 6144-bit Group
  FfdheGroup(
    BigInt.from(5),
    rfc3526Group17.prime, // Same as RFC 3526 group 17
    'RFC5054 6144-bit',
  ),
  // RFC 5054, 7, 8192-bit Group
  FfdheGroup(
    BigInt.from(5),
    rfc3526Group18.prime, // Same as RFC 3526 group 18
    'RFC5054 8192-bit',
  ),
];
