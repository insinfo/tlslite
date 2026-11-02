/// ECDSA (ANSI X9.62 / FIPS 186-4) over the curves of `ec_curve.dart`, with
/// deterministic nonces as specified by RFC 6979 (HMAC-DRBG).
///
/// The message digest is supplied by the caller (it is not hashed again).
/// Hashing and HMAC go through tlslite's own `secureHMAC`.
library;

import 'dart:typed_data';

import '../cryptomath.dart' show secureHMAC;
import 'ec_curve.dart';

/// An ECDSA signature (r, s).
class EcdsaSignature {
  const EcdsaSignature(this.r, this.s);
  final BigInt r;
  final BigInt s;

  @override
  bool operator ==(Object other) =>
      other is EcdsaSignature && other.r == r && other.s == s;

  @override
  int get hashCode => Object.hash(r, s);

  @override
  String toString() =>
      'EcdsaSignature(r: 0x${r.toRadixString(16)}, s: 0x${s.toRadixString(16)})';
}

/// Converts a digest to an integer as in SEC 1 / RFC 6979 `bits2int`:
/// the leftmost `orderBits` bits of [digest] (no reduction modulo n).
BigInt ecdsaBits2Int(EcCurve curve, List<int> digest) {
  var v = ecBytesToBigInt(digest);
  final excess = digest.length * 8 - curve.orderBits;
  if (excess > 0) v >>= excess;
  return v;
}

/// RFC 6979 section 3.2 deterministic nonce generator (HMAC-DRBG).
class Rfc6979Nonce {
  /// [secret] is the private scalar, [digest] the already hashed message and
  /// [hashAlg] the HMAC hash ('sha1', 'sha256', ...).
  Rfc6979Nonce(this.curve, BigInt secret, List<int> digest, this.hashAlg) {
    final rlen = curve.orderBytes;
    final x = ecBigIntToBytes(secret, rlen);
    var z = ecdsaBits2Int(curve, digest);
    if (z >= curve.n) z -= curve.n;
    final h = ecBigIntToBytes(z, rlen);
    // Probe the HMAC output length.
    final hlen = secureHMAC(Uint8List(1), Uint8List(0), hashAlg).length;
    _v = Uint8List(hlen)..fillRange(0, hlen, 0x01);
    _k = Uint8List(hlen);
    _k = _mac(_k, [
      _v,
      const [0x00],
      x,
      h
    ]);
    _v = _mac(_k, [_v]);
    _k = _mac(_k, [
      _v,
      const [0x01],
      x,
      h
    ]);
    _v = _mac(_k, [_v]);
  }

  final EcCurve curve;
  final String hashAlg;
  late Uint8List _k;
  late Uint8List _v;
  bool _first = true;

  Uint8List _mac(Uint8List key, List<List<int>> parts) {
    var total = 0;
    for (final part in parts) {
      total += part.length;
    }
    final data = Uint8List(total);
    var off = 0;
    for (final part in parts) {
      data.setRange(off, off + part.length, part);
      off += part.length;
    }
    return secureHMAC(key, data, hashAlg);
  }

  /// Returns the next candidate nonce in [1, n-1] (step 3.2.h).
  BigInt next() {
    if (!_first) {
      _k = _mac(_k, [
        _v,
        const [0x00]
      ]);
      _v = _mac(_k, [_v]);
    }
    _first = false;
    final rlen = curve.orderBytes;
    while (true) {
      final t = Uint8List(rlen);
      var tOff = 0;
      while (tOff < rlen) {
        _v = _mac(_k, [_v]);
        final take = rlen - tOff < _v.length ? rlen - tOff : _v.length;
        t.setRange(tOff, tOff + take, _v);
        tOff += take;
      }
      final k = ecdsaBits2Int(curve, t);
      if (k > BigInt.zero && k < curve.n) return k;
      _k = _mac(_k, [
        _v,
        const [0x00]
      ]);
      _v = _mac(_k, [_v]);
    }
  }
}

/// Signs [digest] with the private scalar [secret] using an RFC 6979 nonce
/// derived with HMAC-[hashAlg].
EcdsaSignature ecdsaSign(
  EcCurve curve,
  BigInt secret,
  List<int> digest,
  String hashAlg,
) {
  final n = curve.n;
  if (secret <= BigInt.zero || secret >= n) {
    throw ArgumentError('ECDSA private key out of range');
  }
  final e = ecdsaBits2Int(curve, digest) % n;
  final nonces = Rfc6979Nonce(curve, secret, digest, hashAlg);
  while (true) {
    final k = nonces.next();
    final sig = ecdsaSignWithNonce(curve, secret, e, k);
    if (sig != null) return sig;
  }
}

/// Signs with an explicit nonce [k] and the integer [e] (digest already
/// converted with [ecdsaBits2Int]). Returns `null` when r or s is zero.
EcdsaSignature? ecdsaSignWithNonce(
  EcCurve curve,
  BigInt secret,
  BigInt e,
  BigInt k,
) {
  final n = curve.n;
  final point = curve.mulBaseSecret(k);
  if (point.isInfinity) return null;
  final r = point.x! % n;
  if (r == BigInt.zero) return null;
  final kInv = curve.invModOrder(k);
  final s = (kInv * ((e + secret * r) % n)) % n;
  if (s == BigInt.zero) return null;
  return EcdsaSignature(r, s);
}

/// Verifies signature (r, s) of [digest] under the public point [publicKey].
bool ecdsaVerify(
  EcPoint publicKey,
  List<int> digest,
  BigInt r,
  BigInt s,
) {
  final curve = publicKey.curve;
  final n = curve.n;
  if (publicKey.isInfinity || !publicKey.isValid) return false;
  if (r <= BigInt.zero || r >= n || s <= BigInt.zero || s >= n) return false;
  final e = ecdsaBits2Int(curve, digest) % n;
  final w = s.modInverse(n);
  final u1 = (e * w) % n;
  final u2 = (r * w) % n;
  final point = curve.mulDoublePublic(u1, publicKey, u2);
  if (point.isInfinity) return false;
  return point.x! % n == r;
}
