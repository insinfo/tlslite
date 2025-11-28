import 'dart:typed_data';

import 'cryptomath.dart';
import 'der.dart';

part 'python_dsakey.dart';

/// Abstract base class for DSA keys matching tlslite-ng semantics.
abstract class DSAKey {
  BigInt get p;
  BigInt get q;
  BigInt get g;
  BigInt get y;
  BigInt? get x;

  int get bitLength => numBits(p);

  bool hasPrivateKey() => x != null && x != BigInt.zero;

  Uint8List hashAndSign(List<int> data, String hAlg) {
    final digest = secureHash(Uint8List.fromList(data), hAlg);
    return sign(digest);
  }

  Uint8List sign(Uint8List hash);

  bool hashAndVerify(List<int> signature, List<int> data,
      [String hAlg = 'sha1']) {
    final digest = secureHash(Uint8List.fromList(data), hAlg);
    return verify(Uint8List.fromList(signature), digest);
  }

  bool verify(Uint8List signature, Uint8List hashData);

  static DSAKey generate(int L, int N) {
    throw UnimplementedError('Implemented by concrete backends');
  }

  static ({BigInt p, BigInt q}) generateParams(int L, int N) {
    throw UnimplementedError('Implemented by concrete backends');
  }
}