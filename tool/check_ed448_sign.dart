import 'dart:typed_data';
import 'package:tlslite/src/ed448/ed448.dart' as ed448;

void main() {
  final seed = Uint8List.fromList(List<int>.generate(57, (i) => (i * 3 + 1) & 0xff));
  final legacy = ed448.Ed448PrivateKeyImpl.fromSeed(
    seed,
    generator: ed448.Ed448Generator.legacy,
  );
  final rfc = ed448.Ed448PrivateKeyImpl.fromSeed(
    seed,
    generator: ed448.Ed448Generator.rfc8032,
  );

  final legacyBytes = legacy.publicKeyBytes;
  final rfcBytes = rfc.publicKeyBytes;
  var equal = legacyBytes.length == rfcBytes.length;
  for (var i = 0; equal && i < legacyBytes.length; i++) {
    if (legacyBytes[i] != rfcBytes[i]) {
      equal = false;
    }
  }
  print('pk equal? $equal');

  final message = Uint8List.fromList([1, 2, 3, 4, 5]);
  final legacySig = legacy.sign(message);
  final legacyPk = legacy.publicKey;
  final rfcSig = rfc.sign(message);
  final rfcPk = rfc.publicKey;

  print('legacy verify default: ${legacyPk.verify(message, legacySig)}');
  print(
    'legacy verify strict: ${legacyPk.verify(message, legacySig, enableLegacyFallback: false)}',
  );
  print(
    'rfc verify strict: ${rfcPk.verify(message, rfcSig, enableLegacyFallback: false)}',
  );
}
