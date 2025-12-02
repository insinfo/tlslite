

/// Handling of cryptographic operations for key exchange

import 'dart:typed_data';

import 'constants.dart';
import 'errors.dart';
import 'utils/cryptomath.dart';
import 'mathtls.dart';
import 'utils/x25519.dart';

// Temporary stub classes for messages - will be replaced when messages.dart is ported
// ignore: unused_element
class _ClientKeyExchange {
  Uint8List? encryptedPreMasterSecret;
  BigInt? dh_Yc;
  Uint8List? ecdh_Yc;
  BigInt? srp_A;

  void createRSA(Uint8List? encrypted) {
    encryptedPreMasterSecret = encrypted;
  }

  void createDH(BigInt? dhYc) {
    dh_Yc = dhYc;
  }

  void createECDH(Uint8List? ecdhYc) {
    ecdh_Yc = ecdhYc;
  }

  void createSRP(BigInt? srpA) {
    srp_A = srpA;
  }
}

// ignore: unused_element
class _ServerKeyExchange {
  int? hashAlg;
  int? signAlg;
  Uint8List? signature;
  BigInt? dh_p;
  BigInt? dh_g;
  BigInt? dh_Ys;
  BigInt? srp_N;
  BigInt? srp_g;
  Uint8List? srp_s;
  BigInt? srp_B;
  int? curve_type;
  int? named_curve;
  Uint8List? ecdh_Ys;
  (int, int)? version;

  _ServerKeyExchange(int cipherSuite, (int, int) ver) {
    version = ver;
  }

  void createDH(BigInt? p, BigInt? g, Uint8List ys) {
    dh_p = p;
    dh_g = g;
    dh_Ys = bytesToNumber(ys);
  }

  void createECDH(int curveType, {int? named_curve, Uint8List? point}) {
    curve_type = curveType;
    this.named_curve = named_curve;
    ecdh_Ys = point;
  }

  void createSRP(BigInt? N, BigInt? g, Uint8List? s, BigInt? B) {
    srp_N = N;
    srp_g = g;
    srp_s = s;
    srp_B = B;
  }

  Uint8List hash(Uint8List clientRandom, Uint8List serverRandom) {
    // Stub - will be implemented with proper hashing
    return Uint8List(32);
  }
}

// ignore: unused_element
class _ClientHello {
  (int, int)? client_version;
  Uint8List? srp_username;

  dynamic getExtension(int type) {
    return null;
  }
}

// ignore: unused_element
class _ServerHello {
  (int, int)? server_version;

  dynamic getExtension(int type) {
    return null;
  }
}

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

  /// Create a ServerKeyExchange object
  ///
  /// Returns a ServerKeyExchange object for the server's initial leg in the
  /// handshake. If the key exchange method does not send ServerKeyExchange
  /// (e.g. RSA), it returns null.
  dynamic makeServerKeyExchange({String? sigHash}) {
    throw UnimplementedError('makeServerKeyExchange');
  }

  /// Create a ClientKeyExchange object
  dynamic makeClientKeyExchange() {
    throw UnimplementedError('makeClientKeyExchange');
  }

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
    throw UnimplementedError('signServerKeyExchange');
  }
}

/// Common methods for key exchanges that authenticate Server Key Exchange
abstract class AuthenticatedKeyExchange extends KeyExchange {
  AuthenticatedKeyExchange(
    super.cipherSuite,
    super.clientHello,
    super.serverHello,
    super.privateKey,
  );

  @override
  dynamic makeServerKeyExchange({String? sigHash}) {
    final ske = super.makeServerKeyExchange(sigHash: sigHash);
    signServerKeyExchange(ske, sigHash: sigHash);
    return ske;
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
  dynamic makeClientKeyExchange() {
    // Return a client key exchange with clients key share
    final clientKeyExchange = super.makeClientKeyExchange();
    clientKeyExchange.createRSA(encPremasterSecret);
    return clientKeyExchange;
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
  dynamic makeServerKeyExchange({String? sigHash}) {
    // Select DH parameters
    if (dhParams != null) {
      dhG = dhParams!.$1;
      dhP = dhParams!.$2;
    } else if (dhGroups != null && dhGroups!.isNotEmpty) {
      // TODO: Implement RFC 7919 group selection from dhGroups
      // For now use first group as default
      throw UnimplementedError('RFC 7919 group selection not yet implemented');
    } else {
      // Use default 2048-bit safe prime
      throw UnimplementedError('Default DH params not yet implemented');
    }

    final kex = FFDHKeyExchange(0, serverHello.server_version!, generator: dhG, prime: dhP);
    dhXs = kex.getRandomPrivateKey();
    final dhYs = kex.calcPublicValue(dhXs);

    final version = serverHello.server_version;
    final serverKeyExchange = _ServerKeyExchange(cipherSuite, version!);
    serverKeyExchange.createDH(dhP, dhG, dhYs);
    // No sign for anonymous ServerKeyExchange
    return serverKeyExchange;
  }

  @override
  Uint8List processClientKeyExchange(dynamic clientKeyExchange) {
    final dhYc = clientKeyExchange.dh_Yc;

    final kex = FFDHKeyExchange(0, serverHello.server_version!, generator: dhG, prime: dhP);
    return kex.calcSharedKey(dhXs!, numberToByteArray(dhYc));
  }

  @override
  Uint8List processServerKeyExchange(
    dynamic srvPublicKey,
    dynamic serverKeyExchange,
  ) {
    final dhP = serverKeyExchange.dh_p!;
    // TODO: make the minimum changeable
    if (dhP < BigInt.from(2).pow(1023)) {
      throw TLSInsufficientSecurity('DH prime too small');
    }
    final dhG = serverKeyExchange.dh_g!;
    final dhYs = serverKeyExchange.dh_Ys!;

    final kex = FFDHKeyExchange(0, serverHello.server_version!, generator: dhG, prime: dhP);

    final dhXc = kex.getRandomPrivateKey();
    dhYc = dhXc;
    return kex.calcSharedKey(dhXc, numberToByteArray(dhYs));
  }

  @override
  dynamic makeClientKeyExchange() {
    final cke = _ClientKeyExchange();
    cke.createDH(dhYc);
    return cke;
  }
}

/// Helper class for conducting DHE_RSA key exchange
class DHE_RSAKeyExchange extends AuthenticatedKeyExchange
    implements ADHKeyExchange {
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
  dynamic makeServerKeyExchange({String? sigHash}) {
    // Get client supported groups
    final clientCurvesExt = clientHello.getExtension(ExtensionType.supported_groups);
    List<int> clientCurves;

    if (clientCurvesExt == null) {
      // In case there is no extension, we can pick any curve
      clientCurves = [defaultCurve];
    } else {
      final groups = clientCurvesExt.groups;
      if (groups == null || groups.isEmpty) {
        throw TLSInternalError("Can't do ECDHE with no client curves");
      }
      clientCurves = groups;
    }

    // Pick first client preferred group we support
    groupId = _getFirstMatching(clientCurves, acceptedCurves);
    if (groupId == null) {
      throw TLSInsufficientSecurity('No mutual groups');
    }

    final kex = ECDHKeyExchange(groupId!, serverHello.server_version!);
    ecdhXs = kex.getRandomPrivateKey();

    var extNegotiated = 'uncompressed';
    // TODO: Handle EC point formats extension negotiation

    final ecdhYs = kex.calcPublicValue(ecdhXs, extNegotiated);

    final version = serverHello.server_version;
    final serverKeyExchange = _ServerKeyExchange(cipherSuite, version!);
    serverKeyExchange.createECDH(
      ECCurveType.named_curve,
      named_curve: groupId,
      point: ecdhYs,
    );
    // No sign for anonymous ServerKeyExchange
    return serverKeyExchange;
  }

  @override
  Uint8List processClientKeyExchange(dynamic clientKeyExchange) {
    final ecdhYc = clientKeyExchange.ecdh_Yc;

    if (ecdhYc == null || ecdhYc.isEmpty) {
      throw TLSDecodeError('No key share');
    }

    final kex = ECDHKeyExchange(groupId!, serverHello.server_version!);
    final extSupported = {'uncompressed'};
    // TODO: Handle EC point formats extension negotiation

    return kex.calcSharedKey(ecdhXs, ecdhYc, extSupported);
  }

  @override
  Uint8List processServerKeyExchange(
    dynamic srvPublicKey,
    dynamic serverKeyExchange,
  ) {
    if (serverKeyExchange.curve_type != ECCurveType.named_curve ||
        !acceptedCurves!.contains(serverKeyExchange.named_curve)) {
      throw TLSIllegalParameterException("Server picked curve we didn't advertise");
    }

    final ecdhYs = serverKeyExchange.ecdh_Ys;
    if (ecdhYs == null || ecdhYs.isEmpty) {
      throw TLSDecodeError('Empty server key share');
    }

    final kex = ECDHKeyExchange(serverKeyExchange.named_curve!, serverHello.server_version!);
    final ecdhXc = kex.getRandomPrivateKey();
    final extNegotiated = 'uncompressed';
    final extSupported = {'uncompressed'};
    // TODO: Handle EC point formats extension negotiation

    ecdhYc = kex.calcPublicValue(ecdhXc, extNegotiated);
    return kex.calcSharedKey(ecdhXc, ecdhYs, extSupported);
  }

  @override
  dynamic makeClientKeyExchange() {
    final cke = _ClientKeyExchange();
    cke.createECDH(ecdhYc);
    return cke;
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
  dynamic makeServerKeyExchange({String? sigHash}) {
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
  dynamic makeServerKeyExchange({String? sigHash}) {
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
    final serverKeyExchange = _ServerKeyExchange(cipherSuite, serverHello.server_version!);
    serverKeyExchange.createSRP(N, g, s, B);

    // TODO: Sign if cipherSuite is in srpCertSuites
    // if (CipherSuite.srpCertSuites.contains(cipherSuite)) {
    //   signServerKeyExchange(serverKeyExchange, sigHash);
    // }

    return serverKeyExchange;
  }

  @override
  Uint8List processClientKeyExchange(dynamic clientKeyExchange) {
    final a = clientKeyExchange.srp_A as BigInt;
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
    final n = serverKeyExchange.srp_N as BigInt;
    final g = serverKeyExchange.srp_g as BigInt;
    final s = serverKeyExchange.srp_s as Uint8List;
    final b_ = serverKeyExchange.srp_B as BigInt;

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
  dynamic makeClientKeyExchange() {
    final cke = _ClientKeyExchange();
    cke.createSRP(A);
    return cke;
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
  })  : generator = generator ?? BigInt.zero,
        prime = prime ?? BigInt.zero {
    if (prime != null && groupName != 0) {
      throw ArgumentError(
        "Can't set the RFC7919 group and custom params at the same time",
      );
    }
    // TODO: Load RFC7919 groups when groupName is specified
    if (this.generator <= BigInt.one || this.generator >= this.prime) {
      throw TLSIllegalParameterException('Invalid DH generator');
    }
  }

  final BigInt generator;
  final BigInt prime;

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
