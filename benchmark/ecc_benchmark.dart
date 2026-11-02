// Compares tlslite's pure-Dart EC implementation with pointycastle.
//
//   dart run benchmark/ecc_benchmark.dart [curve]
import 'dart:typed_data';

import 'package:pointycastle/api.dart' as pc;
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/ecc/api.dart' as pce;
import 'package:pointycastle/macs/hmac.dart';
import 'package:pointycastle/signers/ecdsa_signer.dart';
import 'package:tlslite/src/utils/cryptomath.dart' show secureHash;
import 'package:tlslite/src/utils/ec/ecdsa.dart';
import 'package:tlslite/src/utils/ecc.dart';

double _measure(String label, void Function() body, {int minMs = 1500}) {
  for (var i = 0; i < 3; i++) {
    body();
  }
  final sw = Stopwatch()..start();
  var iterations = 0;
  while (sw.elapsedMilliseconds < minMs) {
    body();
    iterations++;
  }
  final us = sw.elapsedMicroseconds / iterations;
  print('${label.padRight(44)} ${(us / 1000).toStringAsFixed(3)} ms/op');
  return us;
}

void main(List<String> args) {
  final name = args.isEmpty ? 'secp256r1' : args.first;
  final curve = getCurveByName(name);
  final dom = pce.ECDomainParameters(curve.name.toLowerCase());
  final hashAlg = curve.orderBits <= 256
      ? 'sha256'
      : (curve.orderBits <= 384 ? 'sha384' : 'sha512');
  pc.Digest pcDigest() => hashAlg == 'sha256'
      ? SHA256Digest()
      : (hashAlg == 'sha384' ? SHA384Digest() : SHA512Digest());
  final block = hashAlg == 'sha256' ? 64 : 128;

  final d =
      BigInt.parse('1234567890abcdef' * (curve.orderBytes ~/ 8), radix: 16) %
          curve.n;
  final peerD = (d * BigInt.from(31337) + BigInt.from(7)) % curve.n;
  final peer = curve.mulBaseSecret(peerD);
  final pcPeer = dom.curve.createPoint(peer.x!, peer.y!);
  final digest = secureHash(Uint8List.fromList('benchmark'.codeUnits), hashAlg);
  final q = curve.mulBaseSecret(d);
  final pcQ = dom.curve.createPoint(q.x!, q.y!);

  // Warm up the fixed-base table.
  curve.mulBaseSecret(BigInt.one);

  print('Curve: ${curve.name} (hash $hashAlg)');
  _measure('tlslite   key generation (k*G)', () => curve.mulBaseSecret(d));
  _measure('pointycastle key generation (k*G)', () => dom.G * d);
  _measure('tlslite   ECDHE shared secret (k*Q)',
      () => curve.mulSecret(curve.decodePoint(peer.encode()), d));
  _measure('pointycastle ECDHE shared secret (k*Q)',
      () => dom.curve.decodePoint(pcPeer.getEncoded(false))! * d);

  _measure('tlslite   ECDSA sign (RFC 6979)',
      () => ecdsaSign(curve, d, digest, hashAlg));
  final pcPriv = pc.PrivateKeyParameter(pce.ECPrivateKey(d, dom));
  _measure('pointycastle ECDSA sign (RFC 6979)', () {
    final signer = ECDSASigner(null, HMac(pcDigest(), block))
      ..init(true, pcPriv);
    signer.generateSignature(digest);
  });

  final sig = ecdsaSign(curve, d, digest, hashAlg);
  _measure(
      'tlslite   ECDSA verify', () => ecdsaVerify(q, digest, sig.r, sig.s));
  final pcPub = pc.PublicKeyParameter(pce.ECPublicKey(pcQ, dom));
  _measure('pointycastle ECDSA verify', () {
    final verifier = ECDSASigner()..init(false, pcPub);
    verifier.verifySignature(digest, pce.ECSignature(sig.r, sig.s));
  });
}
