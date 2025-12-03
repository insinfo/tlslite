/// Handling of cryptographic operations for key exchange

import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart' show ECDomainParameters, ECPoint;

import 'constants.dart';
import 'errors.dart';
import 'ffdhe_groups.dart';
import 'handshake_hashes.dart';
import 'handshake_settings.dart';
import 'mathtls.dart';
import 'messages.dart' as tlsmsg;
import 'ml_kem/ml_kem.dart';
import 'tls_protocol.dart';
import 'utils/ecc.dart';
import 'utils/cryptomath.dart';
import 'utils/dsakey.dart';
import 'utils/ecdsakey.dart';
import 'utils/eddsakey.dart';
import 'utils/lists.dart';
import 'utils/rsakey.dart';
import 'utils/tlshashlib.dart' as tlshash;
import 'utils/x25519.dart';

/// Common API for calculating Premaster secret
///
/// Base class for all key exchange implementations
abstract class KeyExchange {
  KeyExchange(
    this.cipherSuite,
    this.clientHello,
    this.serverHello,
    this.privateKey,
  );
  final int cipherSuite;
  final dynamic clientHello;
  final dynamic serverHello;
  final dynamic privateKey;

  /// Calculate the byte string that must be signed in CertificateVerify.
  static Uint8List calcVerifyBytes(
    TlsProtocolVersion version,
    HandshakeHashes handshakeHashes,
    int signatureScheme, {
    Uint8List? premasterSecret,
    Uint8List? clientRandom,
    Uint8List? serverRandom,
    String? prfName,
    String peerTag = 'client',
    String keyType = 'rsa',
  }) {
    final versionTuple = (version.major, version.minor);

    if (versionTuple == (3, 0)) {
      if (premasterSecret == null || clientRandom == null || serverRandom == null) {
        throw TLSInternalError('SSL 3.0 verify bytes require premaster and randoms');
      }
      final masterSecret = calcKey(
        [version.major, version.minor],
        premasterSecret,
        0,
        'master secret'.codeUnits,
        clientRandom: clientRandom,
        serverRandom: serverRandom,
        outputLength: 48,
      );
      return handshakeHashes.digestSSL(masterSecret, Uint8List(0));
    }

    if (versionTuple == (3, 1) || versionTuple == (3, 2)) {
      if (keyType != 'ecdsa') {
        return handshakeHashes.digest();
      }
      return handshakeHashes.digest('sha1');
    }

    if (versionTuple == (3, 3)) {
      return _calcTls12VerifyBytes(handshakeHashes, signatureScheme);
    }

    if (versionTuple == (3, 4)) {
      return _calcTls13VerifyBytes(
        handshakeHashes,
        signatureScheme,
        prfName ?? 'sha256',
        peerTag,
      );
    }

    throw TLSInternalError(
      'Unsupported TLS version for CertificateVerify: $versionTuple',
    );
  }

  static Uint8List _calcTls12VerifyBytes(
    HandshakeHashes handshakeHashes,
    int signatureScheme,
  ) {
    final schemeName = SignatureScheme.toRepr(signatureScheme);
    final hashId = (signatureScheme >> 8) & 0xff;
    final sigId = signatureScheme & 0xff;

    String hashName;
    String? padding;

    final ed25519Value = SignatureScheme.valueOf('ed25519');
    final ed448Value = SignatureScheme.valueOf('ed448');
    if ((ed25519Value != null && signatureScheme == ed25519Value) ||
      (ed448Value != null && signatureScheme == ed448Value)) {
      hashName = 'intrinsic';
      padding = null;
    } else if (sigId == SignatureAlgorithm.dsa) {
      hashName = HashAlgorithm.toRepr(hashId) ??
          (throw TLSIllegalParameterException('Unknown hash id $hashId'));
      padding = null;
    } else if (sigId != SignatureAlgorithm.ecdsa) {
      if (schemeName == null) {
        hashName = HashAlgorithm.toRepr(hashId) ??
            (throw TLSIllegalParameterException('Unknown hash id $hashId'));
        padding = 'pkcs1';
      } else {
        hashName = SignatureScheme.getHash(schemeName);
        padding = SignatureScheme.getPadding(schemeName);
        if (padding.isEmpty) {
          padding = null;
        }
      }
    } else {
      padding = null;
      hashName = HashAlgorithm.toRepr(hashId) ??
          (throw TLSIllegalParameterException('Unknown hash id $hashId'));
    }

    final digest = handshakeHashes.digest(hashName);
    if (padding == 'pkcs1') {
      return RSAKey.addPKCS1Prefix(digest, hashName);
    }
    return digest;
  }

  static Uint8List _calcTls13VerifyBytes(
    HandshakeHashes handshakeHashes,
    int signatureScheme,
    String prfName,
    String peerTag,
  ) {
    final schemeName = SignatureScheme.toRepr(signatureScheme);
    final hashName = schemeName != null
        ? SignatureScheme.getHash(schemeName)
        : HashAlgorithm.toRepr((signatureScheme >> 8) & 0xff) ?? 'sha256';

    final prefix = Uint8List(64)..fillRange(0, 64, 0x20);
    final context = Uint8List.fromList([
      ...prefix,
      ...'TLS 1.3, '.codeUnits,
      ...peerTag.codeUnits,
      ...' CertificateVerify'.codeUnits,
      0x00,
    ]);
    final transcript = handshakeHashes.digest(prfName);
    final payload = Uint8List.fromList([...context, ...transcript]);
    if (hashName == 'intrinsic') {
      return payload;
    }
    return secureHash(payload, hashName);
  }

  /// Verify signature on the Server Key Exchange message.
  ///
  /// The only acceptable signature algorithms are specified by [validSigAlgs].
  static void verifyServerKeyExchange(
    tlsmsg.TlsServerKeyExchange serverKeyExchange,
    dynamic publicKey,
    Uint8List clientRandom,
    Uint8List serverRandom,
    List<(int, int)> validSigAlgs,
  ) {
    final version = serverKeyExchange.version;
    final versionTuple = version.length >= 2 ? (version[0], version[1]) : (3, 3);

    if (versionTuple.$1 < 3 || (versionTuple.$1 == 3 && versionTuple.$2 < 3)) {
      // Pre-TLS 1.2 verification
      final hashBytes = serverKeyExchange.signatureDigest(clientRandom, serverRandom);
      final sigBytes = Uint8List.fromList(serverKeyExchange.signature);
      if (sigBytes.isEmpty) {
        throw TLSIllegalParameterException('Empty signature');
      }
      if (!_verifySignature(publicKey, sigBytes, hashBytes)) {
        throw TLSDecryptionFailed('Server Key Exchange signature invalid');
      }
    } else {
      // TLS 1.2+ verification
      _tls12VerifySKE(serverKeyExchange, publicKey, clientRandom, serverRandom, validSigAlgs);
    }
  }

  static void _tls12VerifySKE(
    tlsmsg.TlsServerKeyExchange serverKeyExchange,
    dynamic publicKey,
    Uint8List clientRandom,
    Uint8List serverRandom,
    List<(int, int)> validSigAlgs,
  ) {
    final hashAlg = serverKeyExchange.hashAlg;
    final signAlg = serverKeyExchange.signAlg;

    final sigAlgTuple = (hashAlg, signAlg);
    if (!validSigAlgs.contains(sigAlgTuple)) {
      throw TLSIllegalParameterException('Server selected invalid signature algorithm');
    }

    // Check for EdDSA signatures
    final ed25519 = SignatureScheme.valueOf('ed25519');
    final ed448 = SignatureScheme.valueOf('ed448');
    if ((ed25519 != null && sigAlgTuple == ((ed25519 >> 8) & 0xff, ed25519 & 0xff)) ||
        (ed448 != null && sigAlgTuple == ((ed448 >> 8) & 0xff, ed448 & 0xff))) {
      _verifyEdDsaSKE(serverKeyExchange, publicKey, clientRandom, serverRandom);
      return;
    }

    // Check for ECDSA
    if (signAlg == SignatureAlgorithm.ecdsa) {
      _verifyEcdsaSKE(serverKeyExchange, publicKey, clientRandom, serverRandom);
      return;
    }

    // Check for DSA
    if (signAlg == SignatureAlgorithm.dsa) {
      _verifyDsaSKE(serverKeyExchange, publicKey, clientRandom, serverRandom);
      return;
    }

    // RSA verification
    final schemeId = (hashAlg << 8) | signAlg;
    final scheme = SignatureScheme.toRepr(schemeId);
    String hashName;
    String padding;
    int saltLen;

    if (scheme != null) {
      final keyType = SignatureScheme.getKeyType(scheme);
      if (keyType != 'rsa') {
        throw TLSInternalError('Non-RSA signature scheme with RSA algorithm ID');
      }
      hashName = SignatureScheme.getHash(scheme);
      padding = SignatureScheme.getPadding(scheme);
      saltLen = padding == 'pss' ? tlshash.newHash(hashName).digestSize : 0;
    } else {
      if (signAlg != SignatureAlgorithm.rsa) {
        throw TLSInternalError('Non-RSA sigs are not supported');
      }
      hashName = HashAlgorithm.toRepr(hashAlg) ??
          (throw TLSIllegalParameterException('Unknown hash ID: $hashAlg'));
      padding = 'pkcs1';
      saltLen = 0;
    }

    final hashBytes = serverKeyExchange.signatureDigest(clientRandom, serverRandom);
    final sigBytes = Uint8List.fromList(serverKeyExchange.signature);

    if (sigBytes.isEmpty) {
      throw TLSIllegalParameterException('Empty signature');
    }

    if (publicKey is! RSAKey) {
      throw TLSInternalError('Expected RSA key for RSA signature verification');
    }

    if (!publicKey.verify(sigBytes, hashBytes,
        padding: padding, hashAlg: hashName, saltLen: saltLen)) {
      throw TLSDecryptionFailed('Server Key Exchange signature invalid');
    }
  }

  static void _verifyEdDsaSKE(
    tlsmsg.TlsServerKeyExchange serverKeyExchange,
    dynamic publicKey,
    Uint8List clientRandom,
    Uint8List serverRandom,
  ) {
    final sigBytes = Uint8List.fromList(serverKeyExchange.signature);
    if (sigBytes.isEmpty) {
      throw TLSIllegalParameterException('Empty signature');
    }
    final hashBytes = serverKeyExchange.signatureDigest(clientRandom, serverRandom);

    if (publicKey is! EdDSAKey) {
      throw TLSInternalError('Expected EdDSA key for EdDSA signature verification');
    }

    if (!publicKey.hashAndVerify(sigBytes, hashBytes)) {
      throw TLSDecryptionFailed('Server Key Exchange signature invalid');
    }
  }

  static void _verifyEcdsaSKE(
    tlsmsg.TlsServerKeyExchange serverKeyExchange,
    dynamic publicKey,
    Uint8List clientRandom,
    Uint8List serverRandom,
  ) {
    final hashAlg = serverKeyExchange.hashAlg;
    final hashName = HashAlgorithm.toRepr(hashAlg) ??
        (throw TLSIllegalParameterException('Unknown hash algorithm'));

    var hashBytes = serverKeyExchange.signatureDigest(clientRandom, serverRandom);

    if (publicKey is! ECDSAKey) {
      throw TLSInternalError('Expected ECDSA key for ECDSA signature verification');
    }

    // Truncate hash to curve base length
    final curveLen = (publicKey.bitLength + 7) ~/ 8;
    if (hashBytes.length > curveLen) {
      hashBytes = Uint8List.fromList(hashBytes.sublist(0, curveLen));
    }

    final sigBytes = Uint8List.fromList(serverKeyExchange.signature);
    if (sigBytes.isEmpty) {
      throw TLSIllegalParameterException('Empty signature');
    }

    if (!publicKey.verify(sigBytes, hashBytes, hashAlg: hashName)) {
      throw TLSDecryptionFailed('Server Key Exchange signature invalid');
    }
  }

  static void _verifyDsaSKE(
    tlsmsg.TlsServerKeyExchange serverKeyExchange,
    dynamic publicKey,
    Uint8List clientRandom,
    Uint8List serverRandom,
  ) {
    final hashBytes = serverKeyExchange.signatureDigest(clientRandom, serverRandom);
    final sigBytes = Uint8List.fromList(serverKeyExchange.signature);

    if (sigBytes.isEmpty) {
      throw TLSIllegalParameterException('Empty signature');
    }

    if (publicKey is! DSAKey) {
      throw TLSInternalError('Expected DSA key for DSA signature verification');
    }

    if (!publicKey.verify(sigBytes, hashBytes)) {
      throw TLSDecryptionFailed('Server Key Exchange signature invalid');
    }
  }

  static bool _verifySignature(dynamic key, Uint8List signature, Uint8List data) {
    if (key is RSAKey) {
      return key.verify(signature, data);
    }
    if (key is ECDSAKey) {
      return key.verify(signature, data);
    }
    if (key is DSAKey) {
      return key.verify(signature, data);
    }
    if (key is EdDSAKey) {
      return key.hashAndVerify(signature, data);
    }
    return false;
  }

  List<int>? _clientVersionCache;
  List<int>? _serverVersionCache;
  Uint8List? _clientRandomCache;
  Uint8List? _serverRandomCache;

  /// Create a ServerKeyExchange object
  ///
  /// Returns a ServerKeyExchange object for the server's initial leg in the
  /// handshake. If the key exchange method does not send ServerKeyExchange
  /// (e.g. RSA), it returns null.
  dynamic makeServerKeyExchange({String? sigHash}) {
    throw UnimplementedError('makeServerKeyExchange');
  }

  /// Create a ClientKeyExchange object
  tlsmsg.TlsClientKeyExchange makeClientKeyExchange() =>
      tlsmsg.TlsClientKeyExchange(
        cipherSuite: cipherSuite,
        version: _serverVersion,
      );

  /// Process ClientKeyExchange and return premaster secret
  Uint8List processClientKeyExchange(dynamic clientKeyExchange) {
    throw UnimplementedError('processClientKeyExchange');
  }

  /// Process the server KEX and return premaster secret
  Uint8List processServerKeyExchange(
    dynamic srvPublicKey,
    dynamic serverKeyExchange,
  ) {
    throw UnimplementedError('processServerKeyExchange');
  }

  /// Sign a server key exchange using default or specified algorithm
  void signServerKeyExchange(
    dynamic serverKeyExchange, {
    String? sigHash,
  }) {
    if (serverKeyExchange is! tlsmsg.TlsServerKeyExchange) {
      throw TLSInternalError('ServerKeyExchange message required for signing');
    }
    final key = privateKey;
    if (!_supportsSigningKey(key)) {
      throw TLSInternalError('No private key available for ServerKeyExchange signing');
    }
    if (!_hasPrivateComponent(key!)) {
      throw TLSInternalError('Signing key does not carry private material');
    }

    final normalizedSigHash = sigHash?.toLowerCase();
    final version = _messageVersion(serverKeyExchange);
    if (_isTls12OrLater(version)) {
      _signTls12(serverKeyExchange, key, normalizedSigHash);
    } else {
      _signPreTls12(serverKeyExchange, key);
    }
  }

  List<int> get _clientVersion =>
      _clientVersionCache ??= _extractVersion(_tryGetClientVersion());

  List<int> get _serverVersion =>
      _serverVersionCache ??=
          _extractVersion(_tryGetServerVersion() ?? _tryGetClientVersion());

  (int, int) get _serverVersionTuple => (_serverVersion[0], _serverVersion[1]);

  Uint8List get _clientRandom =>
      _clientRandomCache ??= _extractRandom(clientHello, isClient: true);

  Uint8List get _serverRandom =>
      _serverRandomCache ??= _extractRandom(serverHello, isClient: false);

  dynamic _tryGetClientVersion() {
    final hello = clientHello;
    if (hello == null) return null;
    try {
      final value = hello.client_version;
      if (value != null) return value;
    } catch (_) {}
    try {
      final value = hello.clientVersion;
      if (value != null) return value;
    } catch (_) {}
    return null;
  }

  dynamic _tryGetServerVersion() {
    final hello = serverHello;
    if (hello == null) return null;
    try {
      final value = hello.server_version;
      if (value != null) return value;
    } catch (_) {}
    try {
      final value = hello.serverVersion;
      if (value != null) return value;
    } catch (_) {}
    try {
      final value = hello.selected_supported_version;
      if (value != null) return value;
    } catch (_) {}
    return null;
  }

  List<int> _extractVersion(dynamic version) {
    if (version == null) {
      return const [3, 3];
    }
    if (version is List<int>) {
      if (version.length < 2) {
        throw TLSInternalError('Malformed protocol version array');
      }
      return [version[0], version[1]];
    }
    if (version is Uint8List) {
      if (version.length < 2) {
        throw TLSInternalError('Malformed protocol version bytes');
      }
      return [version[0], version[1]];
    }
    if (version is (int, int)) {
      return [version.$1, version.$2];
    }
    if (version is TlsProtocolVersion) {
      return [version.major, version.minor];
    }
    throw TLSInternalError(
      'Unsupported protocol version representation: ${version.runtimeType}',
    );
  }

  Uint8List _extractRandom(dynamic hello, {required bool isClient}) {
    if (hello == null) {
      throw TLSInternalError(
        'Missing ${isClient ? 'client' : 'server'} hello for key exchange',
      );
    }
    dynamic value;
    try {
      value = hello.random;
    } catch (_) {}
    value ??= _tryAlternateRandom(hello);
    if (value is Uint8List) {
      return Uint8List.fromList(value);
    }
    if (value is List<int>) {
      return Uint8List.fromList(value);
    }
    throw TLSInternalError(
      'Missing ${isClient ? 'client' : 'server'} random for key exchange',
    );
  }

  dynamic _tryAlternateRandom(dynamic hello) {
    try {
      return hello.client_random;
    } catch (_) {}
    try {
      return hello.server_random;
    } catch (_) {}
    return null;
  }

  bool _supportsSigningKey(Object? key) {
    return key is RSAKey || key is ECDSAKey || key is DSAKey || key is EdDSAKey;
  }

  bool _hasPrivateComponent(Object key) {
    if (key is RSAKey) return key.hasPrivateKey();
    if (key is ECDSAKey) return key.hasPrivateKey();
    if (key is DSAKey) return key.hasPrivateKey();
    if (key is EdDSAKey) return key.hasPrivateKey();
    return false;
  }

  (int, int) _messageVersion(tlsmsg.TlsServerKeyExchange ske) {
    if (ske.version.length >= 2) {
      return (ske.version[0], ske.version[1]);
    }
    return _serverVersionTuple;
  }

  bool _isTls12OrLater((int, int) version) {
    return version.$1 > 3 || (version.$1 == 3 && version.$2 >= 3);
  }

  void _signPreTls12(
    tlsmsg.TlsServerKeyExchange ske,
    Object key,
  ) {
    final digest = ske.signatureDigest(_clientRandom, _serverRandom);
    Uint8List signature;
    if (key is RSAKey) {
      signature = key.sign(digest);
      if (!key.verify(signature, digest)) {
        throw TLSInternalError('Server Key Exchange signature invalid');
      }
    } else if (key is ECDSAKey) {
      signature = key.sign(digest, hashAlg: 'sha1');
      if (!key.verify(signature, digest, hashAlg: 'sha1')) {
        throw TLSInternalError('Server Key Exchange signature invalid');
      }
    } else if (key is DSAKey) {
      signature = key.sign(digest);
      if (!key.verify(signature, digest)) {
        throw TLSInternalError('Server Key Exchange signature invalid');
      }
    } else {
      throw TLSIllegalParameterException(
        'Unsupported key type for legacy ServerKeyExchange signatures',
      );
    }
    ske.signature = signature;
  }

  void _signTls12(
    tlsmsg.TlsServerKeyExchange ske,
    Object key,
    String? sigHash,
  ) {
    if (key is RSAKey) {
      _signTls12WithRsa(ske, key, sigHash);
      return;
    }
    if (key is ECDSAKey) {
      _signTls12WithEcdsa(ske, key, sigHash);
      return;
    }
    if (key is DSAKey) {
      _signTls12WithDsa(ske, key, sigHash);
      return;
    }
    if (key is EdDSAKey) {
      _signTls12WithEdDsa(ske, key, sigHash);
      return;
    }
    throw TLSIllegalParameterException(
      'Unsupported key type for TLS 1.2 ServerKeyExchange signatures',
    );
  }

  void _signTls12WithRsa(
    tlsmsg.TlsServerKeyExchange ske,
    RSAKey key,
    String? sigHash,
  ) {
    final schemeName = sigHash;
    final schemeHashId = schemeName != null
        ? SignatureScheme.hashIdFromName(schemeName)
        : null;
    final schemeSignId = schemeName != null
        ? SignatureScheme.signatureIdFromName(schemeName)
        : null;

    String padding;
    String hashName;
    var saltLen = 0;

    if (schemeHashId != null && schemeSignId != null) {
      final keyType = SignatureScheme.getKeyType(schemeName!);
      if (keyType != 'rsa') {
        throw TLSIllegalParameterException(
          'Signature scheme $schemeName incompatible with RSA keys',
        );
      }
      padding = SignatureScheme.getPadding(schemeName);
      hashName = SignatureScheme.getHash(schemeName);
      if (hashName == 'intrinsic') {
        throw TLSIllegalParameterException(
          'RSA schemes cannot rely on intrinsic hashing',
        );
      }
      saltLen = padding == 'pss'
          ? tlshash.newHash(hashName).digestSize
          : 0;
      ske.hashAlg = schemeHashId;
      ske.signAlg = schemeSignId;
    } else {
      final fallbackName = schemeName ?? 'sha256';
      final hashId = HashAlgorithm.fromName(fallbackName);
      if (hashId == null) {
        throw TLSIllegalParameterException(
          'Unknown RSA hash algorithm: ${sigHash ?? fallbackName}',
        );
      }
      ske.hashAlg = hashId;
      ske.signAlg = SignatureAlgorithm.rsa;
      padding = 'pkcs1';
      hashName = fallbackName;
    }

    if (key.keyType == 'rsa-pss' && padding != 'pss') {
      throw TLSIllegalParameterException('RSA-PSS keys must use PSS padding');
    }

    final digest = ske.signatureDigest(_clientRandom, _serverRandom);
    final signature = key.sign(
      digest,
      padding: padding,
      hashAlg: hashName,
      saltLen: saltLen,
    );
    final ok = key.verify(
      signature,
      digest,
      padding: padding,
      hashAlg: hashName,
      saltLen: saltLen,
    );
    if (!ok) {
      throw TLSInternalError('Server Key Exchange signature invalid');
    }
    ske.signature = signature;
  }

  void _signTls12WithEcdsa(
    tlsmsg.TlsServerKeyExchange ske,
    ECDSAKey key,
    String? sigHash,
  ) {
    final schemeName = sigHash;
    int? hashId;
    int? signId;
    String hashName;

    if (schemeName != null) {
      final schemeHash = SignatureScheme.hashIdFromName(schemeName);
      final schemeSign = SignatureScheme.signatureIdFromName(schemeName);
      if (schemeHash != null && schemeSign != null) {
        if (SignatureScheme.getKeyType(schemeName) != 'ecdsa') {
          throw TLSIllegalParameterException(
            'Signature scheme $schemeName incompatible with ECDSA keys',
          );
        }
        hashId = schemeHash;
        signId = schemeSign;
        hashName = SignatureScheme.getHash(schemeName);
      } else {
        final fallback = HashAlgorithm.fromName(schemeName);
        if (fallback == null) {
          throw TLSIllegalParameterException(
            'Unknown hash algorithm: $schemeName',
          );
        }
        hashId = fallback;
        signId = SignatureAlgorithm.ecdsa;
        hashName = schemeName;
      }
    } else {
      hashId = HashAlgorithm.sha256;
      signId = SignatureAlgorithm.ecdsa;
      hashName = 'sha256';
    }

    ske.hashAlg = hashId;
    ske.signAlg = signId;

    var digest = ske.signatureDigest(_clientRandom, _serverRandom);
    final maxBytes = (key.bitLength + 7) ~/ 8;
    if (digest.length > maxBytes) {
      digest = Uint8List.fromList(digest.sublist(0, maxBytes));
    }

    final signature = key.sign(digest, hashAlg: hashName);
    final ok = key.verify(signature, digest, hashAlg: hashName);
    if (!ok) {
      throw TLSInternalError('Server Key Exchange signature invalid');
    }
    ske.signature = signature;
  }

  void _signTls12WithDsa(
    tlsmsg.TlsServerKeyExchange ske,
    DSAKey key,
    String? sigHash,
  ) {
    final schemeName = sigHash;
    int? hashId;
    int? signId;

    if (schemeName != null) {
      final schemeHash = SignatureScheme.hashIdFromName(schemeName);
      final schemeSign = SignatureScheme.signatureIdFromName(schemeName);
      if (schemeHash != null && schemeSign != null) {
        if (SignatureScheme.getKeyType(schemeName) != 'dsa') {
          throw TLSIllegalParameterException(
            'Signature scheme $schemeName incompatible with DSA keys',
          );
        }
        hashId = schemeHash;
        signId = schemeSign;
      } else {
        final fallback = HashAlgorithm.fromName(schemeName);
        if (fallback == null) {
          throw TLSIllegalParameterException(
            'Unknown hash algorithm: $schemeName',
          );
        }
        hashId = fallback;
        signId = SignatureAlgorithm.dsa;
      }
    } else {
      hashId = HashAlgorithm.sha1;
      signId = SignatureAlgorithm.dsa;
    }

    ske.hashAlg = hashId;
    ske.signAlg = signId;

    final digest = ske.signatureDigest(_clientRandom, _serverRandom);
    final signature = key.sign(digest);
    if (!key.verify(signature, digest)) {
      throw TLSInternalError('Server Key Exchange signature invalid');
    }
    ske.signature = signature;
  }

  void _signTls12WithEdDsa(
    tlsmsg.TlsServerKeyExchange ske,
    EdDSAKey key,
    String? sigHash,
  ) {
    final schemeName = sigHash;
    if (schemeName == null) {
      throw TLSIllegalParameterException(
        'EdDSA signatures require an explicit signature scheme',
      );
    }
    final hashId = SignatureScheme.hashIdFromName(schemeName);
    final signId = SignatureScheme.signatureIdFromName(schemeName);
    if (hashId == null || signId == null) {
      throw TLSIllegalParameterException('Unknown signature scheme: $schemeName');
    }
    if (SignatureScheme.getKeyType(schemeName) != 'eddsa') {
      throw TLSIllegalParameterException(
        'Signature scheme $schemeName incompatible with EdDSA keys',
      );
    }
    ske.hashAlg = hashId;
    ske.signAlg = signId;

    final payload = ske.signatureDigest(_clientRandom, _serverRandom);
    final signature = key.hashAndSign(payload);
    if (!key.hashAndVerify(signature, payload)) {
      throw TLSInternalError('Server Key Exchange signature invalid');
    }
    ske.signature = signature;
  }
}

/// Handling of RSA key exchange
class RSAKeyExchange extends KeyExchange {
  RSAKeyExchange(
    super.cipherSuite,
    super.clientHello,
    super.serverHello,
    super.privateKey,
  );

  Uint8List? encPremasterSecret;

  @override
  dynamic makeServerKeyExchange({String? sigHash}) {
    // Don't create a server key exchange for RSA key exchange
    return null;
  }

  @override
  Uint8List processClientKeyExchange(dynamic clientKeyExchange) {
    // Decrypt client key exchange, return premaster secret
    var premasterSecret = privateKey.decrypt(
      clientKeyExchange.encryptedPreMasterSecret,
    );

    // On decryption failure randomize premaster secret to avoid
    // Bleichenbacher's "million message" attack
    final randomPreMasterSecret = getRandomBytes(48);
    if (premasterSecret == null || premasterSecret.isEmpty) {
      premasterSecret = randomPreMasterSecret;
    } else if (premasterSecret.length != 48) {
      premasterSecret = randomPreMasterSecret;
    } else {
      final versionCheck = (premasterSecret[0], premasterSecret[1]);
      if (versionCheck != clientHello.client_version) {
        // Tolerate buggy IE clients
        if (versionCheck != serverHello.server_version) {
          premasterSecret = randomPreMasterSecret;
        }
      }
    }
    return premasterSecret;
  }

  @override
  Uint8List processServerKeyExchange(
    dynamic srvPublicKey,
    dynamic serverKeyExchange,
  ) {
    // Generate premaster secret for server
    final premasterSecret = getRandomBytes(48);
    premasterSecret[0] = clientHello.client_version[0];
    premasterSecret[1] = clientHello.client_version[1];

    encPremasterSecret = srvPublicKey.encrypt(premasterSecret);
    return premasterSecret;
  }

  @override
  @override
  tlsmsg.TlsClientKeyExchange makeClientKeyExchange() {
    final secret = encPremasterSecret;
    if (secret == null || secret.isEmpty) {
      throw TLSInternalError('Client premaster secret not prepared');
    }
    return tlsmsg.TlsClientKeyExchange(
      cipherSuite: cipherSuite,
      version: _clientVersion,
      encryptedPreMasterSecret: secret,
    );
  }
}

/// Handling of anonymous Diffie-Hellman Key exchange
///
/// FFDHE without signing serverKeyExchange useful for anonymous DH
class ADHKeyExchange extends KeyExchange {
  ADHKeyExchange(
    super.cipherSuite,
    super.clientHello,
    super.serverHello,
    super.privateKey, {
    this.dhParams,
    this.dhGroups,
    this.settings,
  });

  final (BigInt, BigInt)? dhParams;
  final List<int>? dhGroups;
  final HandshakeSettings? settings;

  BigInt? dhXs;
  BigInt? dhYc;
  late BigInt dhG;
  late BigInt dhP;

  @override
  tlsmsg.TlsServerKeyExchange makeServerKeyExchange({String? sigHash}) {
    _selectDhParameters();
    final kex = FFDHKeyExchange(0, _serverVersionTuple, generator: dhG, prime: dhP);
    dhXs = kex.getRandomPrivateKey();
    final dhYsBytes = kex.calcPublicValue(dhXs);

    return tlsmsg.TlsServerKeyExchange(
      cipherSuite: cipherSuite,
      version: _serverVersion,
      dhP: dhP,
      dhG: dhG,
      dhYs: bytesToNumber(dhYsBytes),
    );
  }

  @override
  Uint8List processClientKeyExchange(dynamic clientKeyExchange) {
    final dhValue = clientKeyExchange.dhYc as BigInt?;
    if (dhValue == null || dhValue == BigInt.zero) {
      throw TLSDecodeError('Missing client DH key share');
    }

    final kex = FFDHKeyExchange(0, _serverVersionTuple, generator: dhG, prime: dhP);
    return kex.calcSharedKey(dhXs!, numberToByteArray(dhValue));
  }

  @override
  Uint8List processServerKeyExchange(
    dynamic srvPublicKey,
    dynamic serverKeyExchange,
  ) {
    final dhP = serverKeyExchange.dhP as BigInt;
    final keyBits = numBits(dhP);
    final (minBits, maxBits) = _dhKeySizeBounds();
    if (keyBits < minBits) {
      throw TLSInsufficientSecurity('DH prime too small');
    }
    if (keyBits > maxBits) {
      throw TLSInsufficientSecurity('DH prime too large');
    }
    final dhG = serverKeyExchange.dhG as BigInt;
    final dhYs = serverKeyExchange.dhYs as BigInt;

    final kex = FFDHKeyExchange(0, _serverVersionTuple, generator: dhG, prime: dhP);

    final dhXc = kex.getRandomPrivateKey();
    final publicShare = kex.calcPublicValue(dhXc);
    dhYc = bytesToNumber(publicShare);
    return kex.calcSharedKey(dhXc, numberToByteArray(dhYs));
  }

  @override
  tlsmsg.TlsClientKeyExchange makeClientKeyExchange() {
    return tlsmsg.TlsClientKeyExchange(
      cipherSuite: cipherSuite,
      version: _serverVersion,
      dhYc: dhYc ?? BigInt.zero,
    );
  }

  (int, int) _dhKeySizeBounds() {
    final cfg = settings;
    if (cfg == null) {
      return (1023, 8193);
    }
    final minBits = cfg.minKeySize;
    final maxBits = cfg.maxKeySize;
    if (minBits <= maxBits) {
      return (minBits, maxBits);
    }
    return (maxBits, maxBits);
  }

  void _selectDhParameters() {
    if (dhParams != null) {
      dhG = dhParams!.$1;
      dhP = dhParams!.$2;
      return;
    }

    final defaultGroup = goodGroupParameters[2];
    if (dhGroups == null || dhGroups!.isEmpty) {
      dhG = defaultGroup.generator;
      dhP = defaultGroup.prime;
      return;
    }

    final clientGroups = _clientSupportedFfdheGroups();
    if (clientGroups == null || clientGroups.isEmpty) {
      final preferred = rfc7919GroupMap[dhGroups!.first];
      if (preferred != null) {
        dhG = preferred.generator;
        dhP = preferred.prime;
        return;
      }
      dhG = defaultGroup.generator;
      dhP = defaultGroup.prime;
      return;
    }

    final commonGroup = getFirstMatching(clientGroups, dhGroups);
    if (commonGroup != null) {
      final params = rfc7919GroupMap[commonGroup];
      if (params == null) {
        throw TLSInternalError('Server selected unknown DH group $commonGroup');
      }
      dhG = params.generator;
      dhP = params.prime;
      return;
    }

    final clientOfferedFfdhe = clientGroups.any(
      (group) => group >= GroupName.ffdhe2048 && group < 512,
    );
    if (clientOfferedFfdhe) {
      throw TLSInternalError(
        'DHE attempted without mutual RFC 7919 group agreement',
      );
    }

    final fallback = rfc7919GroupMap[dhGroups!.first];
    if (fallback != null) {
      dhG = fallback.generator;
      dhP = fallback.prime;
      return;
    }

    dhG = defaultGroup.generator;
    dhP = defaultGroup.prime;
  }

  List<int>? _clientSupportedFfdheGroups() {
    try {
      final propGroups = clientHello.supportedGroups;
      if (propGroups is List && propGroups.isNotEmpty) {
        return propGroups.cast<int>().toList(growable: false);
      }
    } catch (_) {
      // Ignore property lookup errors and fall back to extension parsing.
    }
    try {
      final ext = clientHello.getExtension(ExtensionType.supported_groups);
      if (ext == null) {
        return null;
      }
      final groups = ext.groups;
      if (groups is List<int>) {
        return List<int>.from(groups);
      }
      if (groups is List) {
        return groups.cast<int>();
      }
    } catch (_) {
      // Ignore – fall back to defaults
    }
    return null;
  }
}

/// Helper class for conducting DHE_RSA key exchange
class DHE_RSAKeyExchange extends ADHKeyExchange {
  DHE_RSAKeyExchange(
    super.cipherSuite,
    super.clientHello,
    super.serverHello,
    super.privateKey, {
    this.dhParams,
    this.dhGroups,
    HandshakeSettings? settings,
  }) : super(
          settings: settings,
        );

  @override
  final (BigInt, BigInt)? dhParams;

  @override
  final List<int>? dhGroups;

  @override
  BigInt? dhXs;

  @override
  BigInt? dhYc;

  @override
  late BigInt dhG;

  @override
  late BigInt dhP;

  @override
  tlsmsg.TlsServerKeyExchange makeServerKeyExchange({String? sigHash}) {
    final ske = super.makeServerKeyExchange(sigHash: sigHash);
    signServerKeyExchange(ske, sigHash: sigHash);
    return ske;
  }
}

/// Handling of anonymous ECDH Key exchange
class AECDHKeyExchange extends KeyExchange {
  AECDHKeyExchange(
    super.cipherSuite,
    super.clientHello,
    super.serverHello,
    super.privateKey, {
    this.acceptedCurves,
    this.defaultCurve = GroupName.secp256r1,
  });

  final List<int>? acceptedCurves;
  final int defaultCurve;

  dynamic ecdhXs;
  int? groupId;
  Uint8List? ecdhYc;

  @override
  @override
  tlsmsg.TlsServerKeyExchange makeServerKeyExchange({String? sigHash}) {
    final advertisedGroups = _extractSupportedGroups(clientHello);
    List<int> clientCurves;

    if (advertisedGroups == null) {
      // In case there is no extension, we can pick any curve
      clientCurves = [defaultCurve];
    } else if (advertisedGroups.isEmpty) {
      throw TLSInternalError("Can't do ECDHE with no client curves");
    } else {
      clientCurves = advertisedGroups;
    }

    // Pick first client preferred group we support
    groupId = _getFirstMatching(clientCurves, acceptedCurves);
    if (groupId == null) {
      throw TLSInsufficientSecurity('No mutual groups');
    }

    final kex = ECDHKeyExchange(groupId!, _serverVersionTuple);
    ecdhXs = kex.getRandomPrivateKey();

    final extNegotiated = _negotiateEcPointFormat();
    final ecdhYs = kex.calcPublicValue(ecdhXs, extNegotiated);

    return tlsmsg.TlsServerKeyExchange(
      cipherSuite: cipherSuite,
      version: _serverVersion,
      curveType: ECCurveType.named_curve,
      namedCurve: groupId,
      ecdhYs: ecdhYs,
    );
  }

  @override
  Uint8List processClientKeyExchange(dynamic clientKeyExchange) {
    final ecdhYc = clientKeyExchange.ecdhYc as List<int>?;

    if (ecdhYc == null || ecdhYc.isEmpty) {
      throw TLSDecodeError('No key share');
    }

    final kex = ECDHKeyExchange(groupId!, _serverVersionTuple);
    final extSupported = _supportedEcPointFormats();

    return kex.calcSharedKey(
      ecdhXs,
      Uint8List.fromList(ecdhYc),
      extSupported,
    );
  }

  @override
  Uint8List processServerKeyExchange(
    dynamic srvPublicKey,
    dynamic serverKeyExchange,
  ) {
    final curveType = serverKeyExchange.curveType;
    final namedCurve = serverKeyExchange.namedCurve;
    if (curveType != ECCurveType.named_curve ||
        !acceptedCurves!.contains(namedCurve)) {
      throw TLSIllegalParameterException("Server picked curve we didn't advertise");
    }

    final ecdhYs = serverKeyExchange.ecdhYs as List<int>;
    if (ecdhYs.isEmpty) {
      throw TLSDecodeError('Empty server key share');
    }

    final kex = ECDHKeyExchange(namedCurve!, _serverVersionTuple);
    final ecdhXc = kex.getRandomPrivateKey();
    final extNegotiated = _negotiateEcPointFormat();
    final extSupported = _supportedEcPointFormats();

    ecdhYc = kex.calcPublicValue(ecdhXc, extNegotiated);
    return kex.calcSharedKey(
      ecdhXc,
      Uint8List.fromList(ecdhYs),
      extSupported,
    );
  }

  @override
  tlsmsg.TlsClientKeyExchange makeClientKeyExchange() {
    final share = ecdhYc;
    if (share == null || share.isEmpty) {
      throw TLSInternalError('Client ECDH share not prepared');
    }
    return tlsmsg.TlsClientKeyExchange(
      cipherSuite: cipherSuite,
      version: _clientVersion,
      ecdhYc: share,
    );
  }

  int? _getFirstMatching(List<int> client, List<int>? server) {
    if (server == null) return null;
    for (final c in client) {
      if (server.contains(c)) return c;
    }
    return null;
  }

  String _negotiateEcPointFormat() {
    final shared = _sharedEcPointFormats();
    if (shared == null) {
      return 'uncompressed';
    }
    return _formatCodeToLabel(shared.first);
  }

  Set<String> _supportedEcPointFormats() {
    final shared = _sharedEcPointFormats();
    final formats = shared ?? const [ECPointFormat.uncompressed];
    return formats.map(_formatCodeToLabel).toSet();
  }

  List<int>? _sharedEcPointFormats() {
    final clientFormats = _extractPointFormats(clientHello);
    final serverFormats = _extractPointFormats(serverHello);
    if (clientFormats == null || serverFormats == null) {
      return null;
    }
    final shared = <int>[];
    for (final format in clientFormats) {
      if (serverFormats.contains(format) &&
          format == ECPointFormat.uncompressed) {
        shared.add(format);
      }
    }
    if (shared.isEmpty) {
      throw TLSIllegalParameterException('No common EC point format');
    }
    return shared;
  }

  List<int>? _extractPointFormats(dynamic hello) {
    if (hello == null) return null;
    try {
      final formatsProp = hello.ecPointFormats;
      if (formatsProp is List<int> && formatsProp.isNotEmpty) {
        return List<int>.from(formatsProp);
      }
      if (formatsProp is List && formatsProp.isNotEmpty) {
        return formatsProp.cast<int>();
      }
    } catch (_) {}
    try {
      final ext = hello.getExtension(ExtensionType.ec_point_formats);
      if (ext == null) {
        return null;
      }
      final formats = ext.formats;
      if (formats is List<int>) {
        return List<int>.from(formats);
      }
      if (formats is List) {
        return formats.cast<int>();
      }
    } catch (_) {}
    return null;
  }

  List<int>? _extractSupportedGroups(dynamic hello) {
    if (hello == null) return null;
    try {
      final groupsProp = hello.supportedGroups;
      if (groupsProp is List<int> && groupsProp.isNotEmpty) {
        return List<int>.from(groupsProp);
      }
      if (groupsProp is List && groupsProp.isNotEmpty) {
        return groupsProp.cast<int>();
      }
    } catch (_) {}
    try {
      final ext = hello.getExtension(ExtensionType.supported_groups);
      if (ext == null) {
        return null;
      }
      final groups = ext.groups;
      if (groups is List<int>) {
        return List<int>.from(groups);
      }
      if (groups is List) {
        return groups.cast<int>();
      }
    } catch (_) {}
    return null;
  }

  String _formatCodeToLabel(int format) {
    return format == ECPointFormat.uncompressed ? 'uncompressed' : 'compressed';
  }
}

/// Helper class for conducting ECDHE_RSA key exchange
class ECDHE_RSAKeyExchange extends AECDHKeyExchange {
  ECDHE_RSAKeyExchange(
    super.cipherSuite,
    super.clientHello,
    super.serverHello,
    super.privateKey, {
    super.acceptedCurves,
    super.defaultCurve,
  });

  @override
  tlsmsg.TlsServerKeyExchange makeServerKeyExchange({String? sigHash}) {
    final ske = super.makeServerKeyExchange(sigHash: sigHash);
    signServerKeyExchange(ske, sigHash: sigHash);
    return ske;
  }
}

/// Helper class for conducting SRP key exchange
class SRPKeyExchange extends KeyExchange {
  SRPKeyExchange(
    super.cipherSuite,
    super.clientHello,
    super.serverHello,
    super.privateKey, {
    required this.verifierDB,
    this.srpUsername,
    this.password,
    this.settings,
  }) {
    if (srpUsername != null && srpUsername is! Uint8List) {
      throw TypeError();
    }
    if (password != null && password is! Uint8List) {
      throw TypeError();
    }
  }

  final dynamic verifierDB;
  final Uint8List? srpUsername;
  final Uint8List? password;
  final dynamic settings;

  BigInt? N;
  BigInt? v;
  BigInt? b;
  BigInt? B;
  BigInt? A;

  @override
  @override
  tlsmsg.TlsServerKeyExchange makeServerKeyExchange({String? sigHash}) {
    final srpUser = clientHello.srp_username!;

    // Get parameters from username
    final entry = verifierDB[srpUser];
    if (entry == null) {
      throw TLSUnknownPSKIdentity('Unknown identity');
    }

    final (n, g, s, v_) = entry as (BigInt, BigInt, Uint8List, BigInt);
    N = n;
    v = v_;

    // Calculate server's ephemeral DH values (b, B)
    b = bytesToNumber(getRandomBytes(32));
    final k = makeK(N!, g);
    B = (powMod(g, b!, N!) + (k * v!)) % N!;

    // Create ServerKeyExchange, signing it if necessary
    return tlsmsg.TlsServerKeyExchange(
      cipherSuite: cipherSuite,
      version: _serverVersion,
      srpN: N!,
      srpG: g,
      srpS: s,
      srpB: B!,
    );
  }

  @override
  Uint8List processClientKeyExchange(dynamic clientKeyExchange) {
    final a = clientKeyExchange.srpA as BigInt;
    if (a % N! == BigInt.zero) {
      throw TLSIllegalParameterException('Invalid SRP A value');
    }

    // Calculate u
    final u = makeU(N!, a, B!);

    // Calculate premaster secret
    final s = powMod((a * powMod(v!, u, N!)) % N!, b!, N!);
    return numberToByteArray(s);
  }

  @override
  Uint8List processServerKeyExchange(
    dynamic srvPublicKey,
    dynamic serverKeyExchange,
  ) {
    final n = serverKeyExchange.srpN as BigInt;
    final g = serverKeyExchange.srpG as BigInt;
    final s = Uint8List.fromList(serverKeyExchange.srpS as List<int>);
    final b_ = serverKeyExchange.srpB as BigInt;

    if (!_isKnownSrpGroup(g, n)) {
      throw TLSInsufficientSecurity('Unknown group parameters');
    }

    final keyBits = numBits(n);
    final (minBits, maxBits) = _srpKeySizeBounds();
    if (keyBits < minBits) {
      throw TLSInsufficientSecurity('N value is too small: $keyBits');
    }
    if (keyBits > maxBits) {
      throw TLSInsufficientSecurity('N value is too large: $keyBits');
    }
    if (b_ % n == BigInt.zero) {
      throw TLSIllegalParameterException('Suspicious B value');
    }

    // Client ephemeral value
    final a = bytesToNumber(getRandomBytes(32));
    A = powMod(g, a, n);

    // Calculate client's static DH values (x, v)
    final x = makeX(s, srpUsername!, password!);
    final v_ = powMod(g, x, n);

    // Calculate u
    final u = makeU(n, A!, b_);

    // Calculate premaster secret
    final k = makeK(n, g);
    final premaster = powMod((b_ - (k * v_)) % n, a + (u * x), n);
    return numberToByteArray(premaster);
  }

  bool _isKnownSrpGroup(BigInt generator, BigInt prime) {
    for (final group in goodGroupParameters) {
      if (group.generator == generator && group.prime == prime) {
        return true;
      }
    }
    return false;
  }

  (int, int) _srpKeySizeBounds() {
    const defaults = (1023, 8193);
    final cfg = settings;
    if (cfg == null) {
      return defaults;
    }

    var minBits = defaults.$1;
    var maxBits = defaults.$2;

    try {
      final value = cfg.minKeySize;
      if (value is int && value > 0) {
        minBits = value;
      }
    } catch (_) {}

    try {
      final value = cfg.maxKeySize;
      if (value is int && value > 0) {
        maxBits = value;
      }
    } catch (_) {}

    if (minBits > maxBits) {
      minBits = maxBits;
    }

    return (minBits, maxBits);
  }

  @override
  @override
  tlsmsg.TlsClientKeyExchange makeClientKeyExchange() {
    final publicValue = A;
    if (publicValue == null || publicValue == BigInt.zero) {
      throw TLSInternalError('Client SRP share not prepared');
    }
    return tlsmsg.TlsClientKeyExchange(
      cipherSuite: cipherSuite,
      version: _clientVersion,
      srpA: publicValue,
    );
  }
}

/// Abstract class for performing Diffie-Hellman key exchange
abstract class RawDHKeyExchange {
  RawDHKeyExchange(this.groupName, this.version);

  final int groupName;
  final (int, int) version;

  /// Get a random private key for the key exchange
  dynamic getRandomPrivateKey();

  /// Calculate the public value for given private key
  Uint8List calcPublicValue(dynamic privateKey);

  /// Calculate the shared key given our private key and peer's public value
  Uint8List calcSharedKey(dynamic privateKey, Uint8List peerPublicKey);
}

/// Finite Field Diffie-Hellman key exchange
class FFDHKeyExchange extends RawDHKeyExchange {
  FFDHKeyExchange(
    super.groupName,
    super.version, {
    BigInt? generator,
    BigInt? prime,
  })  : assert(
          groupName == 0 || (generator == null && prime == null),
          "Can't set the RFC7919 group and custom params at the same time",
        ),
        generator = _resolveGenerator(groupName, generator),
        prime = _resolvePrime(groupName, prime) {
    if (this.generator <= BigInt.one || this.generator >= this.prime) {
      throw TLSIllegalParameterException('Invalid DH generator');
    }
  }

  final BigInt generator;
  final BigInt prime;

  static BigInt _resolveGenerator(int groupName, BigInt? explicitGenerator) {
    if (groupName != 0) {
      final group = rfc7919GroupMap[groupName];
      if (group == null) {
        throw TLSIllegalParameterException(
          'Unknown RFC 7919 group identifier: $groupName',
        );
      }
      return group.generator;
    }
    if (explicitGenerator == null) {
      throw ArgumentError('Custom DH parameters require a generator');
    }
    return explicitGenerator;
  }

  static BigInt _resolvePrime(int groupName, BigInt? explicitPrime) {
    if (groupName != 0) {
      final group = rfc7919GroupMap[groupName];
      if (group == null) {
        throw TLSIllegalParameterException(
          'Unknown RFC 7919 group identifier: $groupName',
        );
      }
      return group.prime;
    }
    if (explicitPrime == null) {
      throw ArgumentError('Custom DH parameters require a prime');
    }
    return explicitPrime;
  }

  @override
  BigInt getRandomPrivateKey() {
    // Per RFC 3526, Section 1, the exponent should have double the entropy
    // of the strength of the group
    final neededBytes = (paramStrength(prime) * 2 / 8).ceil();
    return bytesToNumber(getRandomBytes(neededBytes));
  }

  @override
  Uint8List calcPublicValue(dynamic privateKey, [String? pointFormat]) {
    final dhY = powMod(generator, privateKey as BigInt, prime);
    if (dhY == BigInt.one || dhY == prime - BigInt.one) {
      throw TLSIllegalParameterException('Small subgroup capture');
    }
    if (version.$1 < 3 || (version.$1 == 3 && version.$2 < 4)) {
      // For TLS < 1.3, return the BigInt directly
      return numberToByteArray(dhY);
    } else {
      return numberToByteArray(dhY, howManyBytes: numBytes(prime));
    }
  }

  @override
  Uint8List calcSharedKey(
    dynamic privateKey,
    Uint8List peerPublicKey, [
    Set<String>? validPointFormats,
  ]) {
    BigInt dhY;
    if (version.$1 < 3 || (version.$1 == 3 && version.$2 < 4)) {
      dhY = bytesToNumber(peerPublicKey);
    } else {
      dhY = bytesToNumber(peerPublicKey);
    }

    if (dhY <= BigInt.one || dhY >= prime - BigInt.one) {
      throw TLSIllegalParameterException('Invalid DH public value');
    }

    final shared = powMod(dhY, privateKey as BigInt, prime);
    if (shared == BigInt.one) {
      throw TLSIllegalParameterException('Small subgroup capture');
    }

    if (version.$1 < 3 || (version.$1 == 3 && version.$2 < 4)) {
      return numberToByteArray(shared);
    } else {
      return numberToByteArray(shared, howManyBytes: numBytes(prime));
    }
  }
}

/// Elliptic Curve Diffie-Hellman key exchange
class ECDHKeyExchange extends RawDHKeyExchange {
  ECDHKeyExchange(super.groupName, super.version);

  static final _xGroups = {GroupName.x25519, GroupName.x448};

  /// Verify using constant time operation that the bytearray is not zero
  // ignore: unused_element
  static void _nonZeroCheck(Uint8List value) {
    var summa = 0;
    for (final i in value) {
      summa |= i;
    }
    if (summa == 0) {
      throw TLSIllegalParameterException('Invalid key share');
    }
  }

  @override
  dynamic getRandomPrivateKey() {
    if (_xGroups.contains(groupName)) {
      final size = groupName == GroupName.x25519
          ? X25519_ORDER_SIZE
          : X448_ORDER_SIZE;
      return getRandomBytes(size);
    }

    final params = _domainParameters();
    final order = params.n;
    final bytesNeeded = (order.bitLength + 7) ~/ 8;
    while (true) {
      final candidate = bytesToNumber(getRandomBytes(bytesNeeded)) % order;
      if (candidate != BigInt.zero) {
        return candidate;
      }
    }
  }

  @override
  Uint8List calcPublicValue(dynamic privateKey, [String? pointFormat]) {
    if (_xGroups.contains(groupName)) {
      final scalar = _coerceMontgomeryScalar(privateKey);
      if (groupName == GroupName.x25519) {
        return x25519(scalar, X25519_G);
      }
      return x448(scalar, X448_G);
    }

    final params = _domainParameters();
    final scalar = _coerceClassicScalar(privateKey, params);
    final format = pointFormat ?? 'uncompressed';
    if (format != 'uncompressed') {
      throw TLSIllegalParameterException(
          'Unsupported EC point format: $format');
    }
    final point = params.G * scalar;
    if (point == null || point.isInfinity) {
      throw TLSIllegalParameterException('Invalid EC scalar');
    }
    return _encodeClassicPoint(point, params);
  }

  @override
  Uint8List calcSharedKey(
    dynamic privateKey,
    Uint8List peerShare, [
    Set<String>? validPointFormats,
  ]) {
    if (_xGroups.contains(groupName)) {
      final expectedLen = groupName == GroupName.x25519
          ? X25519_ORDER_SIZE
          : X448_ORDER_SIZE;
      if (peerShare.length != expectedLen) {
        throw TLSIllegalParameterException('Invalid key share');
      }

      final scalar = _coerceMontgomeryScalar(privateKey);
      final secret = groupName == GroupName.x25519
          ? x25519(scalar, peerShare)
          : x448(scalar, peerShare);
      _nonZeroCheck(secret);
      return secret;
    }

    final params = _domainParameters();
    final acceptedFormats = validPointFormats ?? const {'uncompressed'};
    if (acceptedFormats.isEmpty) {
      throw TLSDecodeError('Empty EC point formats extension');
    }
    if (!acceptedFormats.contains('uncompressed')) {
      throw TLSIllegalParameterException('Unsupported EC point encoding');
    }

    ECPoint point;
    try {
      final decoded = params.curve.decodePoint(peerShare);
      if (decoded == null) {
        throw TLSIllegalParameterException('Invalid EC point');
      }
      point = decoded;
    } on ArgumentError {
      throw TLSIllegalParameterException('Invalid EC point');
    } on StateError {
      throw TLSIllegalParameterException('Invalid EC point');
    }
    if (point.isInfinity) {
      throw TLSIllegalParameterException('Invalid EC point');
    }

    final scalar = _coerceClassicScalar(privateKey, params);
    final shared = point * scalar;
    if (shared == null || shared.isInfinity) {
      throw TLSIllegalParameterException('Invalid peer key share');
    }
    final xCoord = shared.x?.toBigInteger();
    if (xCoord == null) {
      throw TLSIllegalParameterException('Invalid shared secret point');
    }
    final coordSize = getPointByteSize(params);
    return numberToByteArray(xCoord, howManyBytes: coordSize);
  }

  Uint8List _coerceMontgomeryScalar(dynamic value) {
    final expectedLen = groupName == GroupName.x25519
        ? X25519_ORDER_SIZE
        : X448_ORDER_SIZE;

    if (value is Uint8List) {
      if (value.length != expectedLen) {
        throw TLSIllegalParameterException('Invalid private key length');
      }
      return Uint8List.fromList(value);
    }
    if (value is List<int>) {
      final bytes = Uint8List.fromList(value);
      if (bytes.length != expectedLen) {
        throw TLSIllegalParameterException('Invalid private key length');
      }
      return bytes;
    }
    throw TLSInternalError('Unsupported private key representation');
  }

  BigInt _coerceClassicScalar(dynamic value, ECDomainParameters params) {
    if (value is BigInt) {
      final reduced = value % params.n;
      if (reduced == BigInt.zero) {
        throw TLSIllegalParameterException('Invalid EC private key');
      }
      return reduced;
    }
    if (value is Uint8List) {
      return _coerceClassicScalar(bytesToNumber(value), params);
    }
    if (value is List<int>) {
      return _coerceClassicScalar(
        bytesToNumber(Uint8List.fromList(value)),
        params,
      );
    }
    throw TLSInternalError('Unsupported EC private key representation');
  }

  ECDomainParameters _domainParameters() {
    final curveName = GroupName.toStr(groupName);
    if (curveName.isEmpty) {
      throw TLSInternalError('Unknown ECDH group: $groupName');
    }
    return getCurveByName(curveName);
  }

  Uint8List _encodeClassicPoint(ECPoint point, ECDomainParameters params) {
    final coordSize = getPointByteSize(params);
    final x = point.x?.toBigInteger();
    final y = point.y?.toBigInteger();
    if (x == null || y == null) {
      throw TLSInternalError('Failed to encode EC point');
    }
    final xBytes = numberToByteArray(x, howManyBytes: coordSize);
    final yBytes = numberToByteArray(y, howManyBytes: coordSize);
    final encoded = Uint8List(1 + xBytes.length + yBytes.length);
    encoded[0] = 0x04;
    encoded.setRange(1, 1 + xBytes.length, xBytes);
    encoded.setRange(1 + xBytes.length, encoded.length, yBytes);
    return encoded;
  }
}

/// Key Encapsulation Mechanism key exchange (for PQC)
///
/// Caution: KEMs are not symmetric! While the client calls the
/// same getRandomPrivateKey(), calcPublicValue(), and calcSharedKey()
/// as in FFDH or ECDH, the server calls just the encapsulateKey() method.
///
/// This implementation uses Hybrid ML-KEM (Kyber) combined with
/// traditional ECDH, following draft-kwiatkowski-tls-ecdhe-mlkem.
// ignore: unused_element
class KEMKeyExchange {
  KEMKeyExchange(this.group) {
    if (!GroupName.allKEM.contains(group)) {
      throw TLSInternalError('KEMKeyExchange called with wrong group: $group');
    }
    
    // Determine the classic ECDH group used in the hybrid
    if (group == GroupName.secp256r1mlkem768) {
      _classicGroup = GroupName.secp256r1;
      _mlKem = mlKem768Instance;
    } else if (group == GroupName.x25519mlkem768) {
      _classicGroup = GroupName.x25519;
      _mlKem = mlKem768Instance;
    } else {
      assert(group == GroupName.secp384r1mlkem1024);
      _classicGroup = GroupName.secp384r1;
      _mlKem = mlKem1024Instance;
    }
  }

  final int group;
  late final int _classicGroup;
  late final MlKem _mlKem;
  
  /// ML-KEM is now available in pure Dart.
  static const bool mlKemAvailable = true;

  /// Get a random private key for the key exchange.
  ///
  /// Returns a tuple of ((pqcEk, pqcDk), classicKey).
  /// To be used only to generate the KeyShare in ClientHello.
  dynamic getRandomPrivateKey() {
    // Generate ML-KEM keypair
    final (pqcEk, pqcDk) = _mlKem.keygen();
    
    // Generate classic key
    final classicKex = ECDHKeyExchange(_classicGroup, (3, 4));
    final classicKey = classicKex.getRandomPrivateKey();
    
    return ((pqcEk, pqcDk), classicKey);
  }

  /// Calculate the public value for given private key.
  ///
  /// To be used only to generate the KeyShare in ClientHello.
  Uint8List calcPublicValue(dynamic privateKey, {String pointFormat = 'uncompressed'}) {
    final ((pqcEk, _), classicPrivKey) = privateKey as ((Uint8List, Uint8List), dynamic);
    
    final classicKex = ECDHKeyExchange(_classicGroup, (3, 4));
    final classicPubKeyShare = classicKex.calcPublicValue(classicPrivKey);
    
    // For x25519mlkem768: PQC first, then classic
    // For NIST curves: classic first, then PQC
    if (group == GroupName.x25519mlkem768) {
      return Uint8List.fromList([...pqcEk, ...classicPubKeyShare]);
    }
    return Uint8List.fromList([...classicPubKeyShare, ...pqcEk]);
  }

  /// Returns group parameters: (classicKeyLen, pqcEkKeyLen, pqcCiphertextLen, pqcFirst).
  (int, int, int, bool) _groupToParams() {
    if (group == GroupName.secp256r1mlkem768) {
      return (65, 1184, 1088, false);  // secp256r1: 65 bytes uncompressed
    } else if (group == GroupName.x25519mlkem768) {
      return (32, 1184, 1088, true);   // x25519: 32 bytes
    } else {
      assert(group == GroupName.secp384r1mlkem1024);
      return (97, 1568, 1568, false);  // secp384r1: 97 bytes uncompressed
    }
  }

  /// Split combined key share into PQC and classic portions.
  static (Uint8List, Uint8List) _splitKeyShares(
      Uint8List public, bool pqcFirst, int pqcKeyLen, int classicKeyLen) {
    final expectedLen = classicKeyLen + pqcKeyLen;
    if (public.length != expectedLen) {
      throw TLSIllegalParameterException(
          'Invalid key size for the selected group. '
          'Expected: $expectedLen, received: ${public.length}');
    }
    
    Uint8List pqcKey;
    Uint8List classicKeyShare;
    if (pqcFirst) {
      pqcKey = Uint8List.sublistView(public, 0, pqcKeyLen);
      classicKeyShare = Uint8List.sublistView(public, pqcKeyLen);
    } else {
      classicKeyShare = Uint8List.sublistView(public, 0, classicKeyLen);
      pqcKey = Uint8List.sublistView(public, classicKeyLen);
    }
    
    return (pqcKey, classicKeyShare);
  }

  /// Generate a random secret and encapsulate it (server side).
  ///
  /// Returns (sharedSecret, keyEncapsulation).
  /// To be used for generation of KeyShare in ServerHello.
  (Uint8List, Uint8List) encapsulateKey(Uint8List publicKey) {
    final (classicKeyLen, pqcKeyLen, _, pqcFirst) = _groupToParams();
    final (pqcEk, classicKeyShare) = _splitKeyShares(
        publicKey, pqcFirst, pqcKeyLen, classicKeyLen);
    
    // Classic ECDH key exchange
    final classicKex = ECDHKeyExchange(_classicGroup, (3, 4));
    final classicPrivKey = classicKex.getRandomPrivateKey();
    final classicMyKeyShare = classicKex.calcPublicValue(classicPrivKey);
    final classicSharedSecret = classicKex.calcSharedKey(classicPrivKey, classicKeyShare);
    
    // ML-KEM encapsulation
    Uint8List pqcSharedSecret, pqcCiphertext;
    try {
      final (ss, ct) = _mlKem.encaps(pqcEk);
      pqcSharedSecret = ss;
      pqcCiphertext = ct;
    } catch (e) {
      throw TLSIllegalParameterException('Invalid PQC key from peer: $e');
    }
    
    // Combine shared secrets and key encapsulations
    Uint8List sharedSecret, keyEncapsulation;
    if (pqcFirst) {
      sharedSecret = Uint8List.fromList([...pqcSharedSecret, ...classicSharedSecret]);
      keyEncapsulation = Uint8List.fromList([...pqcCiphertext, ...classicMyKeyShare]);
    } else {
      sharedSecret = Uint8List.fromList([...classicSharedSecret, ...pqcSharedSecret]);
      keyEncapsulation = Uint8List.fromList([...classicMyKeyShare, ...pqcCiphertext]);
    }
    
    return (sharedSecret, keyEncapsulation);
  }

  /// Decapsulate the key share received from server (client side).
  Uint8List calcSharedKey(dynamic privateKey, Uint8List keyEncaps) {
    final (classicKeyLen, _, pqcCiphertextLen, pqcFirst) = _groupToParams();
    final (pqcCiphertext, classicKeyShare) = _splitKeyShares(
        keyEncaps, pqcFirst, pqcCiphertextLen, classicKeyLen);
    
    final ((_, pqcDk), classicPrivKey) = privateKey as ((Uint8List, Uint8List), dynamic);
    
    // Classic ECDH shared secret
    final classicKex = ECDHKeyExchange(_classicGroup, (3, 4));
    final classicSharedSecret = classicKex.calcSharedKey(classicPrivKey, classicKeyShare);
    
    // ML-KEM decapsulation
    Uint8List pqcSharedSecret;
    try {
      pqcSharedSecret = _mlKem.decaps(pqcDk, pqcCiphertext);
    } catch (e) {
      throw TLSIllegalParameterException('Error in KEM decapsulation: $e');
    }
    
    // Combine shared secrets
    if (pqcFirst) {
      return Uint8List.fromList([...pqcSharedSecret, ...classicSharedSecret]);
    } else {
      return Uint8List.fromList([...classicSharedSecret, ...pqcSharedSecret]);
    }
  }
}
