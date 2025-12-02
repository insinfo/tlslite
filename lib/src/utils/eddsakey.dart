import 'dart:typed_data';

import '../ed25519_edwards/ed25519_edwards.dart' as ed;

part 'python_eddsakey.dart';

/// Abstract base class for EdDSA keys (Ed25519 / Ed448).
abstract class EdDSAKey {
  int get bitLength;

  bool hasPrivateKey();

  Uint8List _hashAndSign(Uint8List data);

  bool _hashAndVerify(Uint8List signature, Uint8List data);

  Uint8List hashAndSign(List<int> data,
      {String? rsaScheme, String? hAlg, int? sLen}) {
    return _hashAndSign(Uint8List.fromList(data));
  }

  bool hashAndVerify(List<int> signature, List<int> data,
      {String? rsaScheme, String? hAlg, int? sLen}) {
    return _hashAndVerify(
        Uint8List.fromList(signature), Uint8List.fromList(data));
  }

  Uint8List sign(Uint8List bytes,
      {String? padding, String hashAlg = 'sha1', int? saltLen}) {
    throw UnsupportedError(
        'Pure EdDSA signatures do not support pre-hashed signing');
  }

  bool verify(Uint8List signature, Uint8List bytes,
      {String? padding, String? hashAlg, int? saltLen}) {
    throw UnsupportedError(
        'Pure EdDSA signatures do not support pre-hashed verification');
  }

  bool acceptsPassword();

  String write({String? password});

  static EdDSAKey generate(int bits) {
    throw UnimplementedError('Implemented by concrete backends');
  }
}

/// Placeholder for Ed448 public keys until full Ed448 support is ported.
class Ed448PublicKey extends EdDSAKey {
  Ed448PublicKey(Uint8List publicKeyBytes)
      : publicKeyBytes = Uint8List.fromList(publicKeyBytes);

  /// Raw Ed448 public key bytes (57 bytes).
  final Uint8List publicKeyBytes;

  @override
  int get bitLength => 456;

  @override
  bool hasPrivateKey() => false;

  @override
  Uint8List _hashAndSign(Uint8List data) {
    throw UnsupportedError('Ed448 signing is not implemented yet');
  }

  @override
  bool _hashAndVerify(Uint8List signature, Uint8List data) {
    throw UnsupportedError('Ed448 verification is not implemented yet');
  }

  @override
  bool acceptsPassword() => false;

  @override
  String write({String? password}) {
    throw UnsupportedError('Ed448 serialization is not implemented yet');
  }
}
