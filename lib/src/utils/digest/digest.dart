/// Pure-Dart hash functions: MD5, SHA-1, SHA-2, SHA-3/SHAKE and HMAC.
library;

import 'dart:typed_data';

import 'hmac.dart';
import 'keccak.dart';
import 'md5.dart';
import 'message_digest.dart';
import 'sha1.dart';
import 'sha256.dart';
import 'sha512.dart';

export 'hmac.dart';
export 'keccak.dart';
export 'md5.dart';
export 'message_digest.dart';
export 'sha1.dart';
export 'sha256.dart';
export 'sha512.dart';

/// Creates a fresh digest for [algorithm] (case-insensitive): `md5`, `sha1`,
/// `sha224`, `sha256`, `sha384`, `sha512`, `sha3_224`, `sha3_256`,
/// `sha3_384`, `sha3_512`. Throws [ArgumentError] otherwise.
MessageDigest createDigest(String algorithm) {
  final digest = tryCreateDigest(algorithm);
  if (digest == null) {
    throw ArgumentError('Unsupported hash algorithm: $algorithm');
  }
  return digest;
}

/// Like [createDigest] but returns null for unknown names.
MessageDigest? tryCreateDigest(String algorithm) {
  switch (algorithm.toLowerCase()) {
    case 'md5':
      return Md5();
    case 'sha1':
      return Sha1();
    case 'sha224':
      return Sha224();
    case 'sha256':
      return Sha256();
    case 'sha384':
      return Sha384();
    case 'sha512':
      return Sha512();
    case 'sha3_224':
      return Sha3(224);
    case 'sha3_256':
      return Sha3(256);
    case 'sha3_384':
      return Sha3(384);
    case 'sha3_512':
      return Sha3(512);
    default:
      return null;
  }
}

/// One-shot hash of `data[start..end)` with [algorithm].
Uint8List hashBytes(String algorithm, List<int> data,
        [int start = 0, int? end]) =>
    (createDigest(algorithm)..update(data, start, end)).finish();

/// One-shot MD5.
Uint8List md5Hash(List<int> data) => (Md5()..update(data)).finish();

/// One-shot SHA-1.
Uint8List sha1Hash(List<int> data) => (Sha1()..update(data)).finish();

/// One-shot SHA-224.
Uint8List sha224Hash(List<int> data) => (Sha224()..update(data)).finish();

/// One-shot SHA-256.
Uint8List sha256Hash(List<int> data) => (Sha256()..update(data)).finish();

/// One-shot SHA-384.
Uint8List sha384Hash(List<int> data) => (Sha384()..update(data)).finish();

/// One-shot SHA-512.
Uint8List sha512Hash(List<int> data) => (Sha512()..update(data)).finish();

/// Creates an HMAC for [algorithm] keyed with [key].
Hmac createHmac(String algorithm, List<int> key) =>
    Hmac(createDigest(algorithm), key);

/// One-shot HMAC of [data] under [key] with [algorithm].
Uint8List hmac(String algorithm, List<int> key, List<int> data) =>
    (Hmac(createDigest(algorithm), key)..update(data)).finish();
