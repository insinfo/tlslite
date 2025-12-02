/// Handling of cryptographic operations for key exchange

import 'dart:typed_data';

import 'constants.dart';
import 'errors.dart';
import 'ffdhe_groups.dart';
import 'mathtls.dart';
import 'messages.dart' as tlsmsg;
import 'tls_protocol.dart';
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
  });

  final (BigInt, BigInt)? dhParams;
  final List<int>? dhGroups;

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
    // TODO: make the minimum changeable
    if (dhP < BigInt.from(2).pow(1023)) {
      throw TLSInsufficientSecurity('DH prime too small');
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
      final ext = clientHello.getExtension(ExtensionType.supported_groups);
      if (ext == null) {
        return null;
      }
      final groups = ext.groups;
      if (groups is List<int>) {
        return groups;
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
  });

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
    dynamic clientCurvesExt;
    try {
      clientCurvesExt = clientHello.getExtension(ExtensionType.supported_groups);
    } catch (_) {}
    List<int> clientCurves;

    if (clientCurvesExt == null) {
      // In case there is no extension, we can pick any curve
      clientCurves = [defaultCurve];
    } else {
      final groups = clientCurvesExt.groups;
      if (groups == null || groups.isEmpty) {
        throw TLSInternalError("Can't do ECDHE with no client curves");
      }
      clientCurves = groups.cast<int>();
    }

    // Pick first client preferred group we support
    groupId = _getFirstMatching(clientCurves, acceptedCurves);
    if (groupId == null) {
      throw TLSInsufficientSecurity('No mutual groups');
    }

    final kex = ECDHKeyExchange(groupId!, _serverVersionTuple);
    ecdhXs = kex.getRandomPrivateKey();

    var extNegotiated = 'uncompressed';
    // TODO: Handle EC point formats extension negotiation

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
    final extSupported = {'uncompressed'};
    // TODO: Handle EC point formats extension negotiation

    return kex.calcSharedKey(ecdhXs, Uint8List.fromList(ecdhYc), extSupported);
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
    final extNegotiated = 'uncompressed';
    final extSupported = {'uncompressed'};
    // TODO: Handle EC point formats extension negotiation

    ecdhYc = kex.calcPublicValue(ecdhXc, extNegotiated);
    return kex.calcSharedKey(ecdhXc, Uint8List.fromList(ecdhYs), extSupported);
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

    // TODO: Check if (g, N) are in goodGroupParameters
    // TODO: Check minKeySize and maxKeySize from settings

    if (numBits(n) < 1024) {
      throw TLSInsufficientSecurity('N value is too small: ${numBits(n)}');
    }
    if (numBits(n) > 8192) {
      throw TLSInsufficientSecurity('N value is too large: ${numBits(n)}');
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
    } else {
      // ECDSA curve - need ecdsa library
      throw UnimplementedError('ECDSA curves not yet supported');
    }
  }

  @override
  Uint8List calcPublicValue(dynamic privateKey, [String? pointFormat]) {
    if (!_xGroups.contains(groupName)) {
      throw UnimplementedError('ECDSA curves not yet supported');
    }

    final scalar = _coerceScalar(privateKey);
    if (groupName == GroupName.x25519) {
      return x25519(scalar, X25519_G);
    }
    return x448(scalar, X448_G);
  }

  @override
  Uint8List calcSharedKey(
    dynamic privateKey,
    Uint8List peerShare, [
    Set<String>? validPointFormats,
  ]) {
    if (!_xGroups.contains(groupName)) {
      // ECDH with NIST curves
      throw UnimplementedError('ECDSA curves not yet supported');
    }

    final expectedLen = groupName == GroupName.x25519
        ? X25519_ORDER_SIZE
        : X448_ORDER_SIZE;
    if (peerShare.length != expectedLen) {
      throw TLSIllegalParameterException('Invalid key share');
    }

    final scalar = _coerceScalar(privateKey);
    final secret = groupName == GroupName.x25519
        ? x25519(scalar, peerShare)
        : x448(scalar, peerShare);
    _nonZeroCheck(secret);
    return secret;
  }

  Uint8List _coerceScalar(dynamic value) {
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
}

/// Key Encapsulation Mechanism key exchange (for PQC)
///
/// Caution: KEMs are not symmetric! While the client calls the
/// same getRandomPrivateKey(), calcPublicValue(), and calcSharedKey()
/// as in FFDH or ECDH, the server calls just the encapsulateKey() method.
class KEMKeyExchange {
  KEMKeyExchange(this.group);

  final int group;

  /// Get a random private key for the key exchange
  dynamic getRandomPrivateKey() {
    // ML-KEM (Kyber) key generation
    // TODO: Add proper ML-KEM group constants to GroupName
    // For now, just stub out the implementation
    throw UnimplementedError('ML-KEM not yet supported - group: $group');
  }

  /// Calculate the public value for given private key
  Uint8List calcPublicValue(dynamic privateKey) {
    throw UnimplementedError('KEMKeyExchange.calcPublicValue');
  }

  /// Generate a random secret and encapsulate it (server side)
  (Uint8List, Uint8List) encapsulateKey(Uint8List publicKey) {
    // Returns (ciphertext, shared_secret)
    throw UnimplementedError('KEMKeyExchange.encapsulateKey');
  }

  /// Decapsulate the key share received from server (client side)
  Uint8List calcSharedKey(dynamic privateKey, Uint8List keyEncaps) {
    throw UnimplementedError('KEMKeyExchange.calcSharedKey');
  }
}
