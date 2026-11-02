/// Package ed25519 implements the Ed25519 signature algorithm. See
/// https://ed25519.cr.yp.to/.
///
/// These functions are also compatible with the “Ed25519” function defined in
/// RFC 8032. However, unlike RFC 8032's formulation, this package's private key
/// representation includes a public key suffix to make multiple signing
/// operations with the same key more efficient. This package refers to the RFC
/// 8032 private key as the “seed”.

library edwards25519;

import 'dart:typed_data';
import '../utils/digest/digest.dart' show Sha512, sha512Hash;
import 'src/edwards25519.dart';
import 'src/util.dart';

/// PublicKeySize is the size, in bytes, of public keys as used in this package.
const publicKeySize = 32;

/// PrivateKeySize is the size, in bytes, of private keys as used in this package.
const privateKeySize = 64;

/// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
const signatureSize = 64;

/// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
const seedSize = 32;

/// PublicKey is the type of Ed25519 public keys.
class PublicKey {
  List<int> bytes;

  PublicKey(this.bytes);
}

/// PrivateKey is the type of Ed25519 private keys.
class PrivateKey {
  List<int> bytes;

  PrivateKey(this.bytes);
}

/// KeyPair is the type of Ed25519 public/private key pair.
class KeyPair {
  final PrivateKey privateKey;

  final PublicKey publicKey;

  KeyPair(this.privateKey, this.publicKey);

  @override
  int get hashCode => publicKey.hashCode;

  @override
  bool operator ==(other) =>
      other is KeyPair &&
      publicKey == other.publicKey &&
      privateKey == other.privateKey;
}

/// public returns the PublicKey corresponding to PrivateKey.
PublicKey public(PrivateKey privateKey) {
  var publicKey = privateKey.bytes.sublist(32, 32 + publicKeySize);
  return PublicKey(publicKey);
}

/// Seed returns the private key seed corresponding to priv. It is provided for
/// interoperability with RFC 8032. RFC 8032's private keys correspond to seeds
/// in this package.
Uint8List seed(PrivateKey privateKey) {
  var seed = privateKey.bytes.sublist(0, seedSize);
  return seed as Uint8List;
}

/// GenerateKey generates a public/private key pair using entropy from secure random.
KeyPair generateKey() {
  var seed = Uint8List(32);
  fillBytesWithSecureRandomNumbers(seed);
  var privateKey = newKeyFromSeed(seed);
  var publicKey = privateKey.bytes.sublist(32, privateKeySize);
  return KeyPair(privateKey, PublicKey(publicKey));
}

/// NewKeyFromSeed calculates a private key from a seed. It will throw
/// ArgumentError if seed.length is not SeedSize.
/// This function is provided for interoperability with RFC 8032.
/// RFC 8032's private keys correspond to seeds in this package.
PrivateKey newKeyFromSeed(Uint8List seed) {
  if (seed.length != seedSize) {
    throw ArgumentError('ed25519: bad seed length ${seed.length}');
  }
  var digest = sha512Hash(seed).sublist(0, 32);
  digest[0] &= 248;
  digest[31] &= 127;
  digest[31] |= 64;

  var A = ExtendedGroupElement();
  var hBytes = digest.sublist(0);
  geScalarMultBase(A, hBytes);
  var publicKeyBytes = Uint8List(32);
  A.toBytes(publicKeyBytes);

  var privateKey = Uint8List(privateKeySize);
  arrayCopy(seed, 0, privateKey, 0, 32);
  arrayCopy(publicKeyBytes, 0, privateKey, 32, 32);
  return PrivateKey(privateKey);
}

/// Sign signs the message with privateKey and returns a signature. It will
/// throw ArumentError if privateKey.bytes.length is not PrivateKeySize.
Uint8List sign(PrivateKey privateKey, Uint8List message) {
  if (privateKey.bytes.length != privateKeySize) {
    throw ArgumentError(
        'ed25519: bad privateKey length ${privateKey.bytes.length}');
  }
  var digest1 = sha512Hash(privateKey.bytes.sublist(0, 32));
  var expandedSecretKey = digest1.sublist(0, 32);
  expandedSecretKey[0] &= 248;
  expandedSecretKey[31] &= 63;
  expandedSecretKey[31] |= 64;

  var messageDigest = (Sha512()
        ..update(digest1, 32)
        ..update(message))
      .finish();

  var messageDigestReduced = Uint8List(32);
  scReduce(messageDigestReduced, messageDigest);
  var R = ExtendedGroupElement();
  geScalarMultBase(R, messageDigestReduced);

  var encodedR = Uint8List(32);
  R.toBytes(encodedR);

  var hramDigest = (Sha512()
        ..update(encodedR)
        ..update(privateKey.bytes, 32)
        ..update(message))
      .finish();
  var hramDigestReduced = Uint8List(32);
  scReduce(hramDigestReduced, hramDigest);

  var s = Uint8List(32);
  scMulAdd(s, hramDigestReduced, expandedSecretKey, messageDigestReduced);

  var signature = Uint8List(signatureSize);
  arrayCopy(encodedR, 0, signature, 0, 32);
  arrayCopy(s, 0, signature, 32, 32);

  return signature;
}

/// Verify reports whether sig is a valid signature of message by publicKey. It
/// will throw ArgumentError if publicKey.bytes.length is not PublicKeySize.
bool verify(PublicKey publicKey, Uint8List message, Uint8List sig) {
  if (publicKey.bytes.length != publicKeySize) {
    throw ArgumentError(
        'ed25519: bad publicKey length ${publicKey.bytes.length}');
  }
  if (sig.length != signatureSize || sig[63] & 224 != 0) {
    return false;
  }

  var A = ExtendedGroupElement();
  var publicKeyBytes = Uint8List.fromList(publicKey.bytes);
  if (!A.fromBytes(publicKeyBytes)) {
    return false;
  }
  feNeg(A.X, A.X);
  feNeg(A.T, A.T);

  var digest = (Sha512()
        ..update(sig, 0, 32)
        ..update(publicKeyBytes)
        ..update(message))
      .finish();

  var hReduced = Uint8List(32);
  scReduce(hReduced, digest);

  var R = ProjectiveGroupElement();
  var s = sig.sublist(32);

  if (!scMinimal(s)) {
    return false;
  }

  geDoubleScalarMultVartime(R, hReduced, A, s);

  var checkR = Uint8List(32);
  R.toBytes(checkR);
  return _listEquals(sig.sublist(0, 32), checkR);
}

bool _listEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
