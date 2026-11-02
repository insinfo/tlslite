import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart' as pc;
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/ecc/api.dart' as pce;
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:test/test.dart';
import 'package:tlslite/src/constants.dart';
import 'package:tlslite/src/errors.dart';
import 'package:tlslite/src/keyexchange.dart';
import 'package:tlslite/src/utils/cryptomath.dart' show secureHash;
import 'package:tlslite/src/utils/dart_ecdsakey.dart';
import 'package:tlslite/src/utils/der.dart';
import 'package:tlslite/src/utils/ec/ec_curve.dart';
import 'package:tlslite/src/utils/ec/ec_curves.dart';
import 'package:tlslite/src/utils/ec/ecdsa.dart';
import 'package:tlslite/src/utils/ecc.dart';

/// Name of the same curve in pointycastle's registry.
String _pcName(EcCurve c) => c.name.toLowerCase();

final _rnd = Random(0xEC);

BigInt _randomScalar(BigInt n) {
  final bytes = (n.bitLength + 7) ~/ 8 + 8;
  var v = BigInt.zero;
  for (var i = 0; i < bytes; i++) {
    v = (v << 8) | BigInt.from(_rnd.nextInt(256));
  }
  return v % (n - BigInt.one) + BigInt.one;
}

Uint8List _randomBytes(int len) =>
    Uint8List.fromList(List<int>.generate(len, (_) => _rnd.nextInt(256)));

BigInt _hex(String s) => BigInt.parse(s, radix: 16);

pce.ECPoint _toPc(pce.ECDomainParameters d, EcPoint p) =>
    d.curve.createPoint(p.x!, p.y!);

void _expectSame(EcPoint ours, pce.ECPoint? theirs) {
  expect(theirs, isNotNull);
  expect(ours.isInfinity, theirs!.isInfinity);
  if (!ours.isInfinity) {
    expect(ours.x, theirs.x!.toBigInteger());
    expect(ours.y, theirs.y!.toBigInteger());
  }
}

pc.Digest _pcDigest(String alg) {
  switch (alg) {
    case 'sha1':
      return SHA1Digest();
    case 'sha256':
      return SHA256Digest();
    case 'sha384':
      return SHA384Digest();
    case 'sha512':
      return SHA512Digest();
  }
  throw ArgumentError(alg);
}

int _pcBlock(String alg) => alg == 'sha384' || alg == 'sha512' ? 128 : 64;

String _hashFor(EcCurve c) {
  if (c.orderBits <= 256) return 'sha256';
  if (c.orderBits <= 384) return 'sha384';
  return 'sha512';
}

void main() {
  test('registry exposes expected curves and aliases', () {
    expect(allEcCurves.length, 14);
    expect(getCurveByName('prime256v1'), same(secp256r1));
    expect(getCurveByName('NISTP384'), same(secp384r1));
    expect(getCurveByName('brainpoolP256r1tls13'), same(brainpoolP256r1));
    expect(getCurveByName('brainpoolP512r1TLS13'), same(brainpoolP512r1));
    expect(ecCurveByOid(const [1, 2, 840, 10045, 3, 1, 7]), same(secp256r1));
    expect(() => getCurveByName('gostr3410_2001_cryptopro_a'),
        throwsArgumentError);
    expect(getPointByteSize(secp521r1), 66);
    expect(getPointByteSize(secp256r1.generator), 32);
  });

  for (final curve in allEcCurves) {
    group(curve.name, () {
      final dom = pce.ECDomainParameters(_pcName(curve));

      test('domain parameters match pointycastle and are consistent', () {
        expect(curve.p, (dom.curve as dynamic).q as BigInt);
        expect(curve.a, dom.curve.a!.toBigInteger());
        expect(curve.b, dom.curve.b!.toBigInteger());
        expect(curve.n, dom.n);
        _expectSame(curve.generator, dom.G);
        final g = curve.generator;
        expect(curve.isOnCurve(g.x!, g.y!), isTrue);
        // n*G = O, (n-1)*G = -G.
        expect(curve.mulBaseSecret(curve.n).isInfinity, isTrue);
        expect(curve.mulSecret(g, curve.n).isInfinity, isTrue);
        final nm1 = curve.mulSecret(g, curve.n - BigInt.one);
        expect(nm1, equals(-g));
        expect((nm1 + g).isInfinity, isTrue);
        expect(
            curve
                .mulDoublePublic(curve.n - BigInt.one, g, BigInt.one)
                .isInfinity,
            isTrue);
        expect(curve.mulBaseSecret(BigInt.zero).isInfinity, isTrue);
        expect(curve.mulBaseSecret(BigInt.one), equals(g));
        expect(curve.mulBaseSecret(BigInt.two), equals(g + g));
      });

      test('scalar multiplication matches pointycastle', () {
        for (var i = 0; i < 6; i++) {
          final k = _randomScalar(curve.n);
          final ours = curve.mulBaseSecret(k);
          _expectSame(ours, dom.G * k);
          expect(curve.mulSecret(curve.generator, k), equals(ours));
          final k2 = _randomScalar(curve.n);
          final q = curve.mulSecret(ours, k2);
          _expectSame(q, _toPc(dom, ours) * k2);
          // Double-scalar (verification path).
          final u1 = _randomScalar(curve.n);
          final u2 = _randomScalar(curve.n);
          final combined = curve.mulDoublePublic(u1, ours, u2);
          _expectSame(combined, (dom.G * u1)! + (_toPc(dom, ours) * u2));
        }
        // Small and edge scalars.
        for (final k in [
          BigInt.one,
          BigInt.two,
          BigInt.from(3),
          BigInt.from(15),
          BigInt.from(16),
          BigInt.from(17),
          curve.n - BigInt.two,
          curve.n + BigInt.from(5),
        ]) {
          _expectSame(curve.mulBaseSecret(k), dom.G * (k % curve.n));
        }
      });

      test('encode/decode round trips in both formats', () {
        for (var i = 0; i < 6; i++) {
          final pt = curve.mulBaseSecret(_randomScalar(curve.n));
          final pcPt = _toPc(dom, pt);
          final unc = pt.encode();
          final comp = pt.encode(compressed: true);
          expect(unc, equals(pcPt.getEncoded(false)));
          expect(comp, equals(pcPt.getEncoded(true)));
          expect(curve.decodePoint(unc), equals(pt));
          expect(curve.decodePoint(comp), equals(pt));
          expect(curve.decodePoint(pcPt.getEncoded(true)), equals(pt));
          // Decoding the negated point (other parity).
          final neg = -pt;
          expect(curve.decodePoint(neg.encode(compressed: true)), equals(neg));
        }
        expect(curve.decodePoint([0]).isInfinity, isTrue);
      });

      test('invalid encodings are rejected', () {
        final pt = curve.mulBaseSecret(_randomScalar(curve.n));
        final unc = pt.encode();
        // Off-curve: flip a bit of y.
        final bad = Uint8List.fromList(unc)..[unc.length - 1] ^= 1;
        expect(() => curve.decodePoint(bad), throwsFormatException);
        // Truncated / too long.
        expect(() => curve.decodePoint(unc.sublist(0, unc.length - 1)),
            throwsFormatException);
        expect(() => curve.decodePoint([...unc, 0]), throwsFormatException);
        // Hybrid and unknown prefixes.
        final hybrid = Uint8List.fromList(unc)..[0] = pt.y!.isOdd ? 7 : 6;
        expect(() => curve.decodePoint(hybrid), throwsFormatException);
        expect(() => curve.decodePoint([0x05, ...unc.sublist(1)]),
            throwsFormatException);
        expect(() => curve.decodePoint(const []), throwsFormatException);
        expect(() => curve.decodePoint(const [0, 0]), throwsFormatException);
        // x >= p in both encodings.
        final big = ecBigIntToBytes(curve.p, curve.fieldBytes);
        expect(() => curve.decodePoint([2, ...big]), throwsFormatException);
        expect(() => curve.decodePoint([4, ...big, ...big]),
            throwsFormatException);
        // Compressed x with no matching y.
        var x = BigInt.one;
        while (true) {
          final rhs = (x * x * x + curve.a * x + curve.b) % curve.p;
          if (curve.sqrtMod(rhs) == null) break;
          x += BigInt.one;
        }
        expect(
            () =>
                curve.decodePoint([2, ...ecBigIntToBytes(x, curve.fieldBytes)]),
            throwsFormatException);
        expect(() => curve.createPoint(pt.x!, pt.y! + BigInt.one),
            throwsArgumentError);
      });

      test('ECDH agreement matches pointycastle both ways', () {
        for (var i = 0; i < 3; i++) {
          final da = _randomScalar(curve.n);
          final db = _randomScalar(curve.n);
          final qa = curve.mulBaseSecret(da);
          final qb = curve.mulBaseSecret(db);
          final sAB = curve.mulSecret(qb, da);
          final sBA = curve.mulSecret(qa, db);
          expect(sAB, equals(sBA));
          _expectSame(sAB, _toPc(dom, qb) * da);
          // Peer key produced by pointycastle.
          final pcQ = dom.G * db;
          final decoded = curve.decodePoint(pcQ!.getEncoded(false));
          _expectSame(curve.mulSecret(decoded, da), pcQ * da);
        }
      });

      test('ECDSA interoperates with pointycastle', () {
        final hashAlg = _hashFor(curve);
        for (var i = 0; i < 3; i++) {
          final d = _randomScalar(curve.n);
          final q = curve.mulBaseSecret(d);
          final digest = secureHash(_randomBytes(40), hashAlg);
          final pcPriv = pce.ECPrivateKey(d, dom);
          final pcPub = pce.ECPublicKey(_toPc(dom, q), dom);

          // Ours -> pointycastle.
          final sig = ecdsaSign(curve, d, digest, hashAlg);
          final verifier = ECDSASigner()
            ..init(false, pc.PublicKeyParameter(pcPub));
          expect(
              verifier.verifySignature(digest, pce.ECSignature(sig.r, sig.s)),
              isTrue);
          expect(ecdsaVerify(q, digest, sig.r, sig.s), isTrue);

          // Deterministic signatures equal pointycastle's RFC 6979 mode.
          final detSigner =
              ECDSASigner(null, HMac(_pcDigest(hashAlg), _pcBlock(hashAlg)))
                ..init(true, pc.PrivateKeyParameter(pcPriv));
          final pcDet = detSigner.generateSignature(digest) as pce.ECSignature;
          expect(sig.r, pcDet.r);
          expect(sig.s, pcDet.s);

          // pointycastle (random k) -> ours.
          final rndSigner = ECDSASigner()
            ..init(
                true,
                pc.ParametersWithRandom(pc.PrivateKeyParameter(pcPriv),
                    _FixedRandom(_randomBytes(32))));
          final pcSig = rndSigner.generateSignature(digest) as pce.ECSignature;
          expect(ecdsaVerify(q, digest, pcSig.r, pcSig.s), isTrue);
          expect(
              ecdsaVerify(q, digest, pcSig.r, pcSig.s + BigInt.one), isFalse);
          final tampered = Uint8List.fromList(digest)..[0] ^= 0x80;
          expect(ecdsaVerify(q, tampered, pcSig.r, pcSig.s), isFalse);
          expect(ecdsaVerify(q, digest, BigInt.zero, pcSig.s), isFalse);
          expect(ecdsaVerify(q, digest, pcSig.r, curve.n), isFalse);
        }
      });

      test('DartECDSAKey sign/verify and DER encoding', () {
        final hashAlg = _hashFor(curve);
        final d = _randomScalar(curve.n);
        final key = DartECDSAKey(curveName: curve.name, secretMultiplier: d);
        final pub = DartECDSAKey(
          curveName: curve.name,
          pointX: key.publicPointX,
          pointY: key.publicPointY,
        );
        final data = _randomBytes(64);
        final sigDer = key.hashAndSign(data, hAlg: hashAlg);
        expect(pub.hashAndVerify(sigDer, data, hAlg: hashAlg), isTrue);
        expect(pub.hashAndVerify(sigDer, [...data, 1], hAlg: hashAlg), isFalse);
        final (r: r, s: s) = derDecodeSignature(sigDer);
        final digest = secureHash(data, hashAlg);
        final verifier = ECDSASigner()
          ..init(
              false,
              pc.PublicKeyParameter(pce.ECPublicKey(
                  dom.curve.createPoint(key.publicPointX, key.publicPointY),
                  dom)));
        expect(verifier.verifySignature(digest, pce.ECSignature(r, s)), isTrue);
        expect(key.bitLength, curve.orderBits);
      });
    });
  }

  group('RFC 6979 test vectors', () {
    void check(EcCurve curve, String x, String ux, String uy, String hashAlg,
        String msg, String k, String r, String s) {
      final d = _hex(x);
      final q = curve.mulBaseSecret(d);
      expect(q.x, _hex(ux));
      expect(q.y, _hex(uy));
      final digest = secureHash(Uint8List.fromList(msg.codeUnits), hashAlg);
      final nonce = Rfc6979Nonce(curve, d, digest, hashAlg);
      expect(nonce.next(), _hex(k));
      final sig = ecdsaSign(curve, d, digest, hashAlg);
      expect(sig.r, _hex(r));
      expect(sig.s, _hex(s));
      expect(ecdsaVerify(q, digest, sig.r, sig.s), isTrue);
    }

    const p256x =
        'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721';
    const p256ux =
        '60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6';
    const p256uy =
        '7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299';

    test('A.2.5 P-256 SHA-256 "sample"', () {
      check(
          secp256r1,
          p256x,
          p256ux,
          p256uy,
          'sha256',
          'sample',
          'A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60',
          'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716',
          'F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8');
    });

    test('A.2.5 P-256 SHA-256 "test"', () {
      check(
          secp256r1,
          p256x,
          p256ux,
          p256uy,
          'sha256',
          'test',
          'D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0',
          'F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367',
          '019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083');
    });

    const p384x =
        '6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D8'
        '96D5724E4C70A825F872C9EA60D2EDF5';
    const p384ux =
        'EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64'
        'DEF8F0EA9055866064A254515480BC13';
    const p384uy =
        '8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1'
        '288B231C3AE0D4FE7344FD2533264720';

    test('A.2.6 P-384 SHA-384 "sample"', () {
      check(
          secp384r1,
          p384x,
          p384ux,
          p384uy,
          'sha384',
          'sample',
          '94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA'
              '2907E3E83BA95368623B8C4686915CF9',
          '94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C'
              '81A648152E44ACF96E36DD1E80FABE46',
          '99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94F'
              'A329C145786E679E7B82C71A38628AC8');
    });

    test('A.2.6 P-384 SHA-384 "test"', () {
      check(
          secp384r1,
          p384x,
          p384ux,
          p384uy,
          'sha384',
          'test',
          '015EE46A5BF88773ED9123A5AB0807962D193719503C527B031B4C2D225092AD'
              'A71F4A459BC0DA98ADB95837DB8312EA',
          '8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB'
              '0542A7F0812998DA8F1DD3CA3CF023DB',
          'DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E0'
              '6A739F040649A667BF3B828246BAA5A5');
    });

    test('DartECDSAKey produces the RFC 6979 signature (DER)', () {
      final key =
          DartECDSAKey(curveName: 'secp256r1', secretMultiplier: _hex(p256x));
      final der = key.hashAndSign('sample'.codeUnits, hAlg: 'sha256');
      final (r: r, s: s) = derDecodeSignature(der);
      expect(
          r,
          _hex(
              'EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716'));
      expect(
          s,
          _hex(
              'F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8'));
      expect(
          der, derEncodeSequence([derEncodeInteger(r), derEncodeInteger(s)]));
    });

    test('SHA-1 digest with P-256 matches pointycastle deterministic mode', () {
      final d = _randomScalar(secp256r1.n);
      final digest = secureHash(_randomBytes(10), 'sha1');
      final dom = pce.ECDomainParameters('secp256r1');
      final signer = ECDSASigner(null, HMac(SHA1Digest(), 64))
        ..init(true, pc.PrivateKeyParameter(pce.ECPrivateKey(d, dom)));
      final pcSig = signer.generateSignature(digest) as pce.ECSignature;
      final sig = ecdsaSign(secp256r1, d, digest, 'sha1');
      expect(sig.r, pcSig.r);
      expect(sig.s, pcSig.s);
    });
  });

  group('ECDHKeyExchange', () {
    final groups = {
      GroupName.secp192r1: secp192r1,
      GroupName.secp224r1: secp224r1,
      GroupName.secp256k1: secp256k1,
      GroupName.secp256r1: secp256r1,
      GroupName.secp384r1: secp384r1,
      GroupName.secp521r1: secp521r1,
      GroupName.brainpoolP256r1: brainpoolP256r1,
      GroupName.brainpoolP384r1tls13: brainpoolP384r1,
      GroupName.brainpoolP512r1: brainpoolP512r1,
    };
    groups.forEach((group, curve) {
      test('agreement and pointycastle cross-check on ${curve.name}', () {
        final kex = ECDHKeyExchange(group, (3, 3));
        final priv = kex.getRandomPrivateKey() as BigInt;
        final pub = kex.calcPublicValue(priv);
        expect(pub.length, 1 + 2 * curve.fieldBytes);
        final dom = pce.ECDomainParameters(_pcName(curve));
        final peerD = _randomScalar(curve.n);
        final peerPub = (dom.G * peerD)!.getEncoded(false);
        final secret = kex.calcSharedKey(priv, peerPub);
        final expected = dom.curve.decodePoint(pub)! * peerD;
        expect(secret,
            ecBigIntToBytes(expected!.x!.toBigInteger()!, curve.fieldBytes));
        // Compressed public values when requested.
        final compressed = kex.calcPublicValue(priv, 'compressed');
        expect(compressed.length, 1 + curve.fieldBytes);
        expect(
            kex.calcSharedKey(
                peerD, compressed, {'uncompressed', 'compressed'}),
            secret);
      });
    });

    test('rejects invalid peer points', () {
      final kex = ECDHKeyExchange(GroupName.secp256r1, (3, 4));
      final priv = kex.getRandomPrivateKey();
      final good = kex.calcPublicValue(kex.getRandomPrivateKey());
      void reject(List<int> share, [Set<String>? formats]) {
        expect(
            () => kex.calcSharedKey(priv, Uint8List.fromList(share), formats),
            throwsA(isA<TLSIllegalParameterException>()));
      }

      reject([0]); // infinity
      reject(Uint8List.fromList(good)..[64] ^= 1); // off curve
      reject(good.sublist(0, 64)); // truncated
      reject([...good, 0]); // too long
      reject(Uint8List.fromList(good)..[0] = 6); // hybrid
      reject(List<int>.filled(65, 0)..[0] = 4); // (0, 0)
      final p = ecBigIntToBytes(secp256r1.p, 32);
      reject([4, ...p, ...good.sublist(33)]); // x >= p
      // Compressed point when compressed format was not negotiated.
      final pt = secp256r1.decodePoint(good);
      reject(pt.encode(compressed: true));
      // ... but accepted when negotiated.
      expect(
          kex.calcSharedKey(priv, pt.encode(compressed: true),
              {'uncompressed', 'compressed'}),
          kex.calcSharedKey(priv, good));
      // Point of a different curve (secp256k1 generator) on P-256.
      reject(secp256k1.generator.encode());
    });
  });
}

/// Minimal deterministic SecureRandom for pointycastle's random-k signer.
class _FixedRandom implements pc.SecureRandom {
  _FixedRandom(Uint8List seed)
      : _state = Random(seed.fold<int>(0, (a, b) => a * 31 + b));
  final Random _state;

  @override
  String get algorithmName => 'test';

  @override
  int nextUint8() => _state.nextInt(256);

  @override
  int nextUint16() => _state.nextInt(1 << 16);

  @override
  int nextUint32() => _state.nextInt(1 << 32);

  @override
  BigInt nextBigInteger(int bitLength) {
    var v = BigInt.zero;
    for (var i = 0; i < (bitLength + 7) ~/ 8; i++) {
      v = (v << 8) | BigInt.from(nextUint8());
    }
    return v >> (((bitLength + 7) ~/ 8) * 8 - bitLength);
  }

  @override
  Uint8List nextBytes(int count) =>
      Uint8List.fromList(List<int>.generate(count, (_) => nextUint8()));

  @override
  void seed(pc.CipherParameters params) {}
}
