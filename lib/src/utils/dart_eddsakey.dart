part of 'eddsakey.dart';

class DartEdDSAKey extends EdDSAKey {
  DartEdDSAKey._({
    required String curveName,
    required ed.PublicKey publicKey,
    ed.PrivateKey? privateKey,
  })  : _curveName = curveName,
        _publicKey = publicKey,
        _privateKey = privateKey,
        _bitLength = curveName == 'Ed25519' ? 256 : 456;

  factory DartEdDSAKey.ed25519(
      {Uint8List? publicKey, Uint8List? privateKey}) {
    if (publicKey == null && privateKey == null) {
      throw ArgumentError(
          'At least one of publicKey or privateKey must be provided');
    }
    ed.PrivateKey? privObj;
    ed.PublicKey? pubObj;
    if (privateKey != null) {
      final normalized = _normalizePrivateKey(privateKey);
      privObj = ed.PrivateKey(normalized.toList());
      pubObj = ed.public(privObj);
    }
    if (pubObj == null) {
      if (publicKey == null) {
        throw StateError('Unable to derive Ed25519 public key');
      }
      if (publicKey.length != ed.PublicKeySize) {
        throw ArgumentError('Ed25519 public key must be 32 bytes long');
      }
      pubObj = ed.PublicKey(publicKey.toList());
    }
    return DartEdDSAKey._(
      curveName: 'Ed25519',
      publicKey: pubObj,
      privateKey: privObj,
    );
  }

  final String _curveName;
  final ed.PublicKey _publicKey;
  final ed.PrivateKey? _privateKey;
  final int _bitLength;

  @override
  int get bitLength => _bitLength;

  @override
  bool hasPrivateKey() => _privateKey != null;

  @override
  bool acceptsPassword() => hasPrivateKey();

  @override
  String write({String? password}) {
    _ensureSupportedCurve();
    if (password != null) {
      if (!hasPrivateKey()) {
        throw StateError('Cannot encrypt public-only EdDSA key');
      }
      final pkcs8 = _encodePkcs8();
      return encodeEncryptedPrivateKeyPem(pkcs8, password);
    }
    final derBytes = hasPrivateKey() ? _encodePkcs8() : _encodeSpki();
    final label = hasPrivateKey() ? 'PRIVATE KEY' : 'PUBLIC KEY';
    return pem(derBytes, label);
  }

  @override
  Uint8List _hashAndSign(Uint8List data) {
    final priv = _privateKey;
    if (priv == null) {
      throw StateError('Private key required for EdDSA signing');
    }
    _ensureSupportedCurve();
    return ed.sign(priv, data);
  }

  @override
  bool _hashAndVerify(Uint8List signature, Uint8List data) {
    if (signature.length != ed.SignatureSize) {
      return false;
    }
    _ensureSupportedCurve();
    try {
      return ed.verify(_publicKey, data, signature);
    } on ArgumentError {
      return false;
    }
  }

  void _ensureSupportedCurve() {
    if (_curveName != 'Ed25519') {
      throw UnsupportedError('$_curveName is not supported yet');
    }
  }

  static Uint8List _normalizePrivateKey(Uint8List key) {
    if (key.length == ed.PrivateKeySize) {
      return Uint8List.fromList(key);
    }
    if (key.length == ed.SeedSize) {
      final priv = ed.newKeyFromSeed(Uint8List.fromList(key));
      return Uint8List.fromList(priv.bytes);
    }
    throw ArgumentError(
        'Ed25519 private key must be a 32-byte seed or a 64-byte expanded key');
  }

  String get curveName => _curveName;

  Uint8List get publicKeyBytes => Uint8List.fromList(_publicKey.bytes);

  Uint8List _encodePkcs8() {
    final priv = _privateKey;
    if (priv == null) {
      throw StateError('Private key required for serialization');
    }
    final seed = Uint8List.fromList(priv.bytes.sublist(0, ed.SeedSize));
    return encodePkcs8PrivateKey(
      algorithmOid: _ed25519Oid,
      privateKeyDer: seed,
    );
  }

  Uint8List _encodeSpki() {
    final algorithmIdentifier = derEncodeSequence([
      derEncodeObjectIdentifier(_ed25519Oid),
    ]);
    final subjectPublicKey = derEncodeBitString(publicKeyBytes);
    return derEncodeSequence([algorithmIdentifier, subjectPublicKey]);
  }
}

