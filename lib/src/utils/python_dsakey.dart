part of 'dsakey.dart';

class PythonDSAKey extends DSAKey {
  PythonDSAKey({
    required BigInt p,
    required BigInt q,
    required BigInt g,
    BigInt? x,
    BigInt? y,
  })  : _p = p,
        _q = q,
        _g = g,
        _x = (x != null && x != BigInt.zero) ? x : null,
        _y = y ??
            ((x != null && x != BigInt.zero)
                ? powMod(g, x, p)
                : BigInt.zero) {
    if (_y == BigInt.zero) {
      throw ArgumentError('At least one of x or y must be provided');
    }
  }

  final BigInt _p;
  final BigInt _q;
  final BigInt _g;
  final BigInt? _x;
  final BigInt _y;

  @override
  BigInt get p => _p;

  @override
  BigInt get q => _q;

  @override
  BigInt get g => _g;

  @override
  BigInt get y => _y;

  @override
  BigInt? get x => _x;

  @override
  bool hasPrivateKey() => _x != null;

  @override
  Uint8List sign(Uint8List hash) {
    final priv = _x;
    if (priv == null) {
      throw StateError('Private key required for signing');
    }
    final digest = _truncateDigest(hash);
    while (true) {
      final k = getRandomNumber(BigInt.one, _q);
      final r = powMod(_g, k, _p) % _q;
      if (r == BigInt.zero) {
        continue;
      }
      final kInv = invMod(k, _q);
      if (kInv == BigInt.zero) {
        continue;
      }
      final s = (kInv * (digest + priv * r)) % _q;
      if (s == BigInt.zero) {
        continue;
      }
      return derEncodeSequence([
        derEncodeInteger(r),
        derEncodeInteger(s),
      ]);
    }
  }

  @override
  bool verify(Uint8List signature, Uint8List hashData) {
    if (signature.isEmpty) {
      return false;
    }
    final parsed = _tryDerDecode(signature);
    if (parsed == null) {
      return false;
    }
    final r = parsed.r;
    final s = parsed.s;
    if (r <= BigInt.zero || r >= _q) {
      return false;
    }
    if (s <= BigInt.zero || s >= _q) {
      return false;
    }
    final digest = _truncateDigest(hashData);
    final w = invMod(s, _q);
    if (w == BigInt.zero) {
      return false;
    }
    final u1 = (digest * w) % _q;
    final u2 = (r * w) % _q;
    final v = ((powMod(_g, u1, _p) * powMod(_y, u2, _p)) % _p) % _q;
    return v == r;
  }

  BigInt _truncateDigest(Uint8List hash) {
    if (hash.isEmpty) {
      return BigInt.zero;
    }
    BigInt digest = bytesToNumber(hash);
    final digestBits = hash.length * 8;
    final qBits = numBits(_q);
    if (digestBits > qBits) {
      digest = digest >> (digestBits - qBits);
    }
    return digest;
  }

  ({BigInt r, BigInt s})? _tryDerDecode(Uint8List signature) {
    try {
      final result = derDecodeSignature(signature);
      final canonical = derEncodeSequence([
        derEncodeInteger(result.r),
        derEncodeInteger(result.s),
      ]);
      if (!_bytesEqual(signature, canonical)) {
        return null;
      }
      return result;
    } on FormatException {
      return null;
    }
  }

  bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) {
      return false;
    }
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }
}
