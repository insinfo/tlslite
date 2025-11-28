part of 'rsakey.dart';

class PythonRSAKey extends RSAKey {
  PythonRSAKey({
    BigInt? n,
    BigInt? e,
    BigInt? d,
    BigInt? p,
    BigInt? q,
    BigInt? dP,
    BigInt? dQ,
    BigInt? qInv,
    String keyType = 'rsa',
  })  : _d = d ?? BigInt.zero,
        _p = p ?? BigInt.zero,
        _q = q ?? BigInt.zero,
        _dP = dP ?? BigInt.zero,
        _dQ = dQ ?? BigInt.zero,
        _qInv = qInv ?? BigInt.zero,
        _blinder = BigInt.zero,
        _unblinder = BigInt.zero,
        super(modulus: n, exponent: e, keyTypeValue: keyType) {
    if ((this.n != BigInt.zero && this.e == BigInt.zero) ||
        (this.e != BigInt.zero && this.n == BigInt.zero)) {
      throw ArgumentError('Both modulus and exponent must be provided');
    }
    if ((_p == BigInt.zero) != (_q == BigInt.zero)) {
      throw ArgumentError('p and q must be set together');
    }
    if (_d == BigInt.zero && _p != BigInt.zero && _q != BigInt.zero) {
      final t = lcm(_p - BigInt.one, _q - BigInt.one);
      _d = invMod(this.e, t);
    }
    if (_p != BigInt.zero && _dP == BigInt.zero) {
      _dP = _d % (_p - BigInt.one);
    }
    if (_q != BigInt.zero && _dQ == BigInt.zero) {
      _dQ = _d % (_q - BigInt.one);
    }
    if (_q != BigInt.zero && _qInv == BigInt.zero) {
      _qInv = invMod(_q, _p);
    }
  }

  BigInt _d;
  BigInt _p;
  BigInt _q;
  BigInt _dP;
  BigInt _dQ;
  BigInt _qInv;
  BigInt _blinder;
  BigInt _unblinder;

  @override
  BigInt? get privateExponent => hasPrivateKey() ? _d : null;

  @override
  bool hasPrivateKey() => _d != BigInt.zero;

  @override
  BigInt _rawPrivateKeyOp(BigInt message) {
    if (!hasPrivateKey()) {
      throw ArgumentError('Private key not available');
    }
    BigInt result;
    // The math is quick enough that we can skip actual locking; Dart code
    // runs on a single isolate unless explicitly parallelised.
    if (_blinder == BigInt.zero) {
      _unblinder = getRandomNumber(BigInt.two, n);
      _blinder = powMod(invMod(_unblinder, n), e, n);
    }
    final blinder = _blinder;
    final unblinder = _unblinder;
    _blinder = (blinder * blinder) % n;
    _unblinder = (unblinder * unblinder) % n;

    final blinded = (message * blinder) % n;
    final cipher = _rawPrivateKeyOpHelper(blinded);
    result = (cipher * unblinder) % n;
    return result;
  }

  BigInt _rawPrivateKeyOpHelper(BigInt message) {
    if (_p == BigInt.zero || _q == BigInt.zero) {
      return powMod(message, _d, n);
    }
    final s1 = powMod(message, _dP, _p);
    final s2 = powMod(message, _dQ, _q);
    final h = ((s1 - s2) * _qInv) % _p;
    return s2 + _q * h;
  }

  @override
  BigInt _rawPublicKeyOp(BigInt ciphertext) {
    return powMod(ciphertext, e, n);
  }

  @override
  bool acceptsPassword() => false;

  @override
  String write({String? password}) {
    throw UnimplementedError('PEM serialization not yet ported');
  }

  static PythonRSAKey generate(int bits, {String keyType = 'rsa'}) {
    while (true) {
      final p = getRandomPrime(bits ~/ 2);
      final q = getRandomPrime(bits ~/ 2);
      final t = lcm(p - BigInt.one, q - BigInt.one);
      if (gcd(t, BigInt.from(65537)) == BigInt.one) {
        final n = p * q;
        final e = BigInt.from(65537);
        final d = invMod(e, t);
        final dP = d % (p - BigInt.one);
        final dQ = d % (q - BigInt.one);
        final qInv = invMod(q, p);
        return PythonRSAKey(
          n: n,
          e: e,
          d: d,
          p: p,
          q: q,
          dP: dP,
          dQ: dQ,
          qInv: qInv,
          keyType: keyType,
        );
      }
    }
  }

  @override
  String toString() => 'PythonRSAKey(len=${bitLength})';
}