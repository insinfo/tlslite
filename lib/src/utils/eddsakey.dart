import 'dart:typed_data';

import '../ed25519_edwards/ed25519_edwards.dart' as ed;
import '../ed448/ed448.dart' as ed448;
import 'der.dart';
import 'pem.dart';
import 'pkcs8.dart';

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

/// Ed448 public key implementation.
class Ed448PublicKey extends EdDSAKey {
  Ed448PublicKey(Uint8List publicKeyBytes)
      : _publicKeyBytes = Uint8List.fromList(publicKeyBytes),
        _impl = ed448.Ed448PublicKeyImpl(publicKeyBytes) {
    if (_publicKeyBytes.length != _ed448KeyLength) {
      throw ArgumentError('Ed448 public key must be 57 bytes');
    }
  }

  final Uint8List _publicKeyBytes;
  final ed448.Ed448PublicKeyImpl _impl;

  Uint8List get publicKeyBytes => Uint8List.fromList(_publicKeyBytes);

  @override
  int get bitLength => 456;

  @override
  bool hasPrivateKey() => false;

  @override
  Uint8List _hashAndSign(Uint8List data) {
    throw StateError('Cannot sign with a public key');
  }

  @override
  bool _hashAndVerify(Uint8List signature, Uint8List data) {
    return _impl.verify(data, signature);
  }

  @override
  bool acceptsPassword() => false;

  @override
  String write({String? password}) {
    if (password != null) {
      throw StateError('Cannot encrypt public-only Ed448 key');
    }
    return pem(_encodeSpki(), 'PUBLIC KEY');
  }

  Uint8List _encodeSpki() {
    final algorithmIdentifier = derEncodeSequence([
      derEncodeObjectIdentifier(_ed448Oid),
    ]);
    final subjectPublicKey = derEncodeBitString(publicKeyBytes);
    return derEncodeSequence([algorithmIdentifier, subjectPublicKey]);
  }
}

/// Ed448 private key implementation.
class Ed448PrivateKey extends Ed448PublicKey {
  Ed448PrivateKey({
    required Uint8List privateKeyBytes,
    required Uint8List publicKeyBytes,
  })  : _privateKeyBytes = Uint8List.fromList(privateKeyBytes),
        _privateImpl = ed448.Ed448PrivateKeyImpl.fromSeed(privateKeyBytes),
        super(publicKeyBytes) {
    if (_privateKeyBytes.length != _ed448KeyLength) {
      throw ArgumentError('Ed448 private key must be 57 bytes');
    }
  }

  final Uint8List _privateKeyBytes;
  final ed448.Ed448PrivateKeyImpl _privateImpl;

  @override
  bool hasPrivateKey() => true;

  @override
  Uint8List _hashAndSign(Uint8List data) {
    return _privateImpl.sign(data);
  }

  @override
  bool acceptsPassword() => true;

  @override
  String write({String? password}) {
    final pkcs8 = encodePkcs8PrivateKey(
      algorithmOid: _ed448Oid,
      privateKeyDer: _privateKeyBytes,
      publicKeyBytes: publicKeyBytes,
    );
    if (password != null) {
      return encodeEncryptedPrivateKeyPem(pkcs8, password);
    }
    return pem(pkcs8, 'PRIVATE KEY');
  }
}

const int _ed448KeyLength = 57;
const List<int> _ed25519Oid = [1, 3, 101, 112];
const List<int> _ed448Oid = [1, 3, 101, 113];
