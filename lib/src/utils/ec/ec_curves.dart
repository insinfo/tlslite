/// Named prime-field curves used by tlslite (TLS supported_groups, X.509
/// keys, ECDSA). Constants from SEC 2 v2 (secp*) and RFC 5639 (brainpool).
///
/// Every curve here has cofactor 1, which the complete addition formulas in
/// `ec_curve.dart` rely on.
library;

import 'ec_curve.dart';

BigInt _h(String hex) => BigInt.parse(hex, radix: 16);

final EcCurve secp160k1 = EcCurve(
  name: 'secp160k1',
  p: _h('fffffffffffffffffffffffffffffffeffffac73'),
  a: _h('0'),
  b: _h('7'),
  gx: _h('3b4c382ce37aa192a4019e763036f4f5dd4d7ebb'),
  gy: _h('938cf935318fdced6bc28286531733c3f03c4fee'),
  n: _h('100000000000000000001b8fa16dfab9aca16b6b3'),
  oid: const [1, 3, 132, 0, 9],
);

final EcCurve secp160r1 = EcCurve(
  name: 'secp160r1',
  p: _h('ffffffffffffffffffffffffffffffff7fffffff'),
  a: _h('ffffffffffffffffffffffffffffffff7ffffffc'),
  b: _h('1c97befc54bd7a8b65acf89f81d4d4adc565fa45'),
  gx: _h('4a96b5688ef573284664698968c38bb913cbfc82'),
  gy: _h('23a628553168947d59dcc912042351377ac5fb32'),
  n: _h('100000000000000000001f4c8f927aed3ca752257'),
  oid: const [1, 3, 132, 0, 8],
);

final EcCurve secp160r2 = EcCurve(
  name: 'secp160r2',
  p: _h('fffffffffffffffffffffffffffffffeffffac73'),
  a: _h('fffffffffffffffffffffffffffffffeffffac70'),
  b: _h('b4e134d3fb59eb8bab57274904664d5af50388ba'),
  gx: _h('52dcb034293a117e1f4ff11b30f7199d3144ce6d'),
  gy: _h('feaffef2e331f296e071fa0df9982cfea7d43f2e'),
  n: _h('100000000000000000000351ee786a818f3a1a16b'),
  oid: const [1, 3, 132, 0, 30],
);

final EcCurve secp192k1 = EcCurve(
  name: 'secp192k1',
  p: _h('fffffffffffffffffffffffffffffffffffffffeffffee37'),
  a: _h('0'),
  b: _h('3'),
  gx: _h('db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d'),
  gy: _h('9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d'),
  n: _h('fffffffffffffffffffffffe26f2fc170f69466a74defd8d'),
  oid: const [1, 3, 132, 0, 31],
);

final EcCurve secp192r1 = EcCurve(
  name: 'secp192r1',
  p: _h('fffffffffffffffffffffffffffffffeffffffffffffffff'),
  a: _h('fffffffffffffffffffffffffffffffefffffffffffffffc'),
  b: _h('64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1'),
  gx: _h('188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'),
  gy: _h('7192b95ffc8da78631011ed6b24cdd573f977a11e794811'),
  n: _h('ffffffffffffffffffffffff99def836146bc9b1b4d22831'),
  oid: const [1, 2, 840, 10045, 3, 1, 1],
);

final EcCurve secp224k1 = EcCurve(
  name: 'secp224k1',
  p: _h('fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d'),
  a: _h('0'),
  b: _h('5'),
  gx: _h('a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c'),
  gy: _h('7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5'),
  n: _h('10000000000000000000000000001dce8d2ec6184caf0a971769fb1f7'),
  oid: const [1, 3, 132, 0, 32],
);

final EcCurve secp224r1 = EcCurve(
  name: 'secp224r1',
  p: _h('ffffffffffffffffffffffffffffffff000000000000000000000001'),
  a: _h('fffffffffffffffffffffffffffffffefffffffffffffffffffffffe'),
  b: _h('b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4'),
  gx: _h('b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21'),
  gy: _h('bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34'),
  n: _h('ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d'),
  oid: const [1, 3, 132, 0, 33],
);

final EcCurve secp256k1 = EcCurve(
  name: 'secp256k1',
  p: _h('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'),
  a: _h('0'),
  b: _h('7'),
  gx: _h('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'),
  gy: _h('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'),
  n: _h('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
  oid: const [1, 3, 132, 0, 10],
);

final EcCurve secp256r1 = EcCurve(
  name: 'secp256r1',
  p: _h('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),
  a: _h('ffffffff00000001000000000000000000000000fffffffffffffffffffffffc'),
  b: _h('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
  gx: _h('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
  gy: _h('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),
  n: _h('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
  oid: const [1, 2, 840, 10045, 3, 1, 7],
);

final EcCurve secp384r1 = EcCurve(
  name: 'secp384r1',
  p: _h(
      'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff'),
  a: _h(
      'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc'),
  b: _h(
      'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef'),
  gx: _h(
      'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7'),
  gy: _h(
      '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f'),
  n: _h(
      'ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973'),
  oid: const [1, 3, 132, 0, 34],
);

final EcCurve secp521r1 = EcCurve(
  name: 'secp521r1',
  p: _h(
      '1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'),
  a: _h(
      '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc'),
  b: _h(
      '51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00'),
  gx: _h(
      'c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66'),
  gy: _h(
      '11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650'),
  n: _h(
      '1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409'),
  oid: const [1, 3, 132, 0, 35],
);

final EcCurve brainpoolP256r1 = EcCurve(
  name: 'brainpoolP256r1',
  p: _h('a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377'),
  a: _h('7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9'),
  b: _h('26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6'),
  gx: _h('8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262'),
  gy: _h('547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997'),
  n: _h('a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7'),
  oid: const [1, 3, 36, 3, 3, 2, 8, 1, 1, 7],
);

final EcCurve brainpoolP384r1 = EcCurve(
  name: 'brainpoolP384r1',
  p: _h(
      '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53'),
  a: _h(
      '7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826'),
  b: _h(
      '4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11'),
  gx: _h(
      '1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e'),
  gy: _h(
      '8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315'),
  n: _h(
      '8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565'),
  oid: const [1, 3, 36, 3, 3, 2, 8, 1, 1, 11],
);

final EcCurve brainpoolP512r1 = EcCurve(
  name: 'brainpoolP512r1',
  p: _h(
      'aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3'),
  a: _h(
      '7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca'),
  b: _h(
      '3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723'),
  gx: _h(
      '81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822'),
  gy: _h(
      '7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892'),
  n: _h(
      'aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069'),
  oid: const [1, 3, 36, 3, 3, 2, 8, 1, 1, 13],
);

/// Lookup table: lower-case name (including aliases) -> curve.
final Map<String, EcCurve> _curvesByName = {
  'secp160k1': secp160k1,
  'secp160r1': secp160r1,
  'secp160r2': secp160r2,
  'secp192k1': secp192k1,
  'secp192r1': secp192r1,
  'prime192v1': secp192r1,
  'nistp192': secp192r1,
  'secp224k1': secp224k1,
  'secp224r1': secp224r1,
  'nistp224': secp224r1,
  'secp256k1': secp256k1,
  'secp256r1': secp256r1,
  'prime256v1': secp256r1,
  'nistp256': secp256r1,
  'nist256p': secp256r1,
  'secp384r1': secp384r1,
  'nistp384': secp384r1,
  'nist384p': secp384r1,
  'secp521r1': secp521r1,
  'nistp521': secp521r1,
  'nist521p': secp521r1,
  'brainpoolp256r1': brainpoolP256r1,
  'brainpoolp384r1': brainpoolP384r1,
  'brainpoolp512r1': brainpoolP512r1,
  // RFC 8734: TLS 1.3 code points for the same brainpool curves.
  'brainpoolp256r1tls13': brainpoolP256r1,
  'brainpoolp384r1tls13': brainpoolP384r1,
  'brainpoolp512r1tls13': brainpoolP512r1,
};

/// Distinct curves implemented by this package.
final List<EcCurve> allEcCurves = List.unmodifiable([
  secp160k1,
  secp160r1,
  secp160r2,
  secp192k1,
  secp192r1,
  secp224k1,
  secp224r1,
  secp256k1,
  secp256r1,
  secp384r1,
  secp521r1,
  brainpoolP256r1,
  brainpoolP384r1,
  brainpoolP512r1,
]);

/// Every accepted curve name, including aliases (lower case).
Iterable<String> get ecCurveNames => _curvesByName.keys;

/// Returns the curve called [name] (case-insensitive) or `null`.
EcCurve? ecCurveByName(String name) => _curvesByName[name.toLowerCase()];

/// Returns the curve whose OID arcs equal [oid], or `null`.
EcCurve? ecCurveByOid(List<int> oid) {
  for (final curve in allEcCurves) {
    final curveOid = curve.oid;
    if (curveOid == null || curveOid.length != oid.length) continue;
    var same = true;
    for (var i = 0; i < oid.length; i++) {
      if (curveOid[i] != oid[i]) {
        same = false;
        break;
      }
    }
    if (same) return curve;
  }
  return null;
}
