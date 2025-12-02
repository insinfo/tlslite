

/// Class for setting handshake parameters

import 'constants.dart';
import 'x509.dart';

// Cipher names
const _cipherNames = [
  'chacha20-poly1305',
  'aes256gcm',
  'aes128gcm',
  'aes256ccm',
  'aes128ccm',
  'aes256',
  'aes128',
  '3des',
];

const allCipherNames = [
  ..._cipherNames,
  'chacha20-poly1305_draft00',
  'aes128ccm_8',
  'aes256ccm_8',
  'rc4',
  'null',
];

const _macNames = ['sha', 'sha256', 'sha384', 'aead'];
const allMacNames = [..._macNames, 'md5'];

const keyExchangeNames = [
  'ecdhe_ecdsa',
  'rsa',
  'dhe_rsa',
  'ecdhe_rsa',
  'srp_sha',
  'srp_sha_rsa',
  'ecdh_anon',
  'dh_anon',
  'dhe_dsa',
];

const cipherImplementations = ['openssl', 'pycrypto', 'python'];
const _certificateTypes = ['x509'];

const rsaSignatureHashes = ['sha512', 'sha384', 'sha256', 'sha224', 'sha1'];
const dsaSignatureHashes = ['sha512', 'sha384', 'sha256', 'sha224', 'sha1'];
const ecdsaSignatureHashes = ['sha512', 'sha384', 'sha256', 'sha224', 'sha1'];
const allRsaSignatureHashes = [...rsaSignatureHashes, 'md5'];

const signatureSchemes = [
  'Ed25519',
  'Ed448',
  'ecdsa_brainpoolP512r1tls13_sha512',
  'ecdsa_brainpoolP384r1tls13_sha384',
  'ecdsa_brainpoolP256r1tls13_sha256',
];

const _rsaSchemes = ['pss', 'pkcs1'];

// Curve names - order matters (preferred first)
const curveNames = [
  'x25519',
  'x448',
  'secp384r1',
  'secp256r1',
  'secp521r1',
  'brainpoolP512r1',
  'brainpoolP384r1',
  'brainpoolP256r1',
  'brainpoolP256r1tls13',
  'brainpoolP384r1tls13',
  'brainpoolP512r1tls13',
];

const allCurveNames = [...curveNames, 'secp256k1', 'secp224r1', 'secp192r1'];

const allDhGroupNames = [
  'ffdhe2048',
  'ffdhe3072',
  'ffdhe4096',
  'ffdhe6144',
  'ffdhe8192',
];

const curveAliases = {
  'secp256r1': ['NIST256p', 'prime256v1', 'P-256'],
  'secp384r1': ['NIST384p', 'P-384'],
  'secp521r1': ['NIST521p', 'P-521'],
  'secp256k1': ['SECP256k1'],
  'secp192r1': ['NIST192p', 'P-192'],
  'secp224r1': ['NIST224p', 'P-224'],
  'brainpoolP256r1': ['BRAINPOOLP256r1'],
  'brainpoolP384r1': ['BRAINPOOLP384r1'],
  'brainpoolP512r1': ['BRAINPOOLP512r1'],
};

const tls13PermittedGroups = [
  'secp256r1',
  'secp384r1',
  'secp521r1',
  'x25519',
  'x448',
  'ffdhe2048',
  'ffdhe3072',
  'ffdhe4096',
  'ffdhe6144',
  'ffdhe8192',
  'brainpoolP256r1tls13',
  'brainpoolP384r1tls13',
  'brainpoolP512r1tls13',
];

const knownVersions = [(3, 0), (3, 1), (3, 2), (3, 3), (3, 4)];

const ticketCiphers = [
  'chacha20-poly1305',
  'aes256gcm',
  'aes128gcm',
  'aes128ccm',
  'aes128ccm_8',
  'aes256ccm',
  'aes256ccm_8',
];

const _pskModes = ['psk_dhe_ke', 'psk_ke'];

const _ecPointFormats = [
  ECPointFormat.ansiX962_compressed_prime,
  ECPointFormat.uncompressed,
];

const allCompressionAlgosSend = ['zlib'];
const allCompressionAlgosReceive = ['zlib'];

/// Key, certificate and related data
///
/// Stores certificate associated data like OCSPs and transparency info.
/// First certificate in certificates needs to match key, remaining should
/// build a trust path to a root CA.
class Keypair {
  Keypair({this.key, this.certificates = const []});

  /// Private key (RSA or ECDSA)
  final dynamic key;

  /// The certificates to send to peer if the key is selected
  final List<X509> certificates;

  /// Sanity check the keypair
  void validate() {
    if (key == null || certificates.isEmpty) {
      throw ArgumentError('Key or certificate missing in Keypair');
    }
  }
}

/// Configuration of keys and certs for a single virtual server
///
/// This class encapsulates keys and certificates for hosts specified by
/// server_name (SNI) and ALPN extensions.
class VirtualHost {
  VirtualHost({
    this.keys = const [],
    Set<String>? hostnames,
    this.trustAnchors = const [],
    this.appProtocols = const [],
  }) : hostnames = hostnames ?? {};

  /// List of certificates and keys to be used in this virtual host
  final List<Keypair> keys;

  /// All the hostnames that server supports
  final Set<String> hostnames;

  /// List of CA certificates supported for client certificate authentication
  final List<X509> trustAnchors;

  /// All the application protocols that the server supports (for ALPN)
  final List<String> appProtocols;

  /// Checks if the virtual host can serve hostname
  bool matchesHostname(String hostname) {
    return hostnames.contains(hostname);
  }

  /// Sanity check the settings
  void validate() {
    if (keys.isEmpty) {
      throw ArgumentError('Virtual host missing keys');
    }
    for (final keypair in keys) {
      keypair.validate();
    }
  }
}

/// Parameters that can be used with a TLS handshake
class HandshakeSettings {
  HandshakeSettings({
    this.minKeySize = 1023,
    this.maxKeySize = 8193,
    List<String>? cipherNames,
    List<String>? macNames,
    List<String>? certificateTypes,
    this.minVersion = const (3, 1),
    this.maxVersion = const (3, 3),
    this.useExperimentalTackExtension = false,
    this.sendFallbackSCSV = false,
    List<String>? rsaSigHashes,
    List<String>? dsaSigHashes,
    List<String>? ecdsaSigHashes,
    List<String>? moreSigSchemes,
    List<String>? rsaSchemes,
    List<String>? eccCurves,
    List<String>? dhGroups,
    this.useEncryptThenMAC = true,
    this.useExtendedMasterSecret = true,
    this.requireExtendedMasterSecret = false,
    List<(int, int)>? supportedVersions,
    this.defaultCurve = 'secp256r1',
    this.keyShares = const ['secp256r1', 'x25519'],
    this.ticketCipher = 'aes128gcm',
    List<String>? pskModes,
    this.ticketKeys = const [],
    this.ticketLifetime = 3600 * 24,
    this.useExperimental0rttTempKey = false,
    this.alpnProtos = const [],
    this.dhParams,
    List<int>? ecPointFormats,
    this.padding_cb,
    this.record_size_limit = 2 << 13,
    this.use_heartbeat_extension = true,
    this.heartbeat_response_callback,
    this.max_early_data = 2 << 13,
    this.heartbeatCiphersuites = const [],
    this.useLegacySignatureSchemeIDCombination = false,
  })  : cipherNames = cipherNames ?? _cipherNames,
        macNames = macNames ?? _macNames,
        certificateTypes = certificateTypes ?? _certificateTypes,
        rsaSigHashes = rsaSigHashes ?? rsaSignatureHashes,
        dsaSigHashes = dsaSigHashes ?? dsaSignatureHashes,
        ecdsaSigHashes = ecdsaSigHashes ?? ecdsaSignatureHashes,
        moreSigSchemes = moreSigSchemes ?? signatureSchemes,
        rsaSchemes = rsaSchemes ?? _rsaSchemes,
        eccCurves = eccCurves ?? curveNames,
        dhGroups = dhGroups ?? allDhGroupNames,
        supportedVersions = supportedVersions ?? knownVersions,
        pskModes = pskModes ?? _pskModes,
        ecPointFormats = ecPointFormats ?? _ecPointFormats;

  /// The minimum bit length for asymmetric keys (default: 1023)
  final int minKeySize;

  /// The maximum bit length for asymmetric keys (default: 8193)
  final int maxKeySize;

  /// The allowed ciphers
  final List<String> cipherNames;

  /// The allowed MAC algorithms
  final List<String> macNames;

  /// The allowed certificate types
  final List<String> certificateTypes;

  /// The minimum allowed SSL/TLS version (default: TLS 1.0)
  final (int, int) minVersion;

  /// The maximum allowed SSL/TLS version (default: TLS 1.2)
  final (int, int) maxVersion;

  /// Whether to enable TACK support (experimental)
  final bool useExperimentalTackExtension;

  /// Whether to, as a client, send FALLBACK_SCSV
  final bool sendFallbackSCSV;

  /// List of hashes for RSA signatures in TLS 1.2+
  final List<String> rsaSigHashes;

  /// List of hashes for DSA signatures in TLS 1.2+
  final List<String> dsaSigHashes;

  /// List of hashes for ECDSA signatures in TLS 1.2+
  final List<String> ecdsaSigHashes;

  /// Additional signature schemes (Ed25519, Ed448, etc.)
  final List<String> moreSigSchemes;

  /// RSA padding schemes (pss, pkcs1)
  final List<String> rsaSchemes;

  /// List of named curves to advertise in supported_groups
  final List<String> eccCurves;

  /// List of FFDH groups to advertise
  final List<String> dhGroups;

  /// Whether to support encrypt then MAC extension (RFC 7366)
  final bool useEncryptThenMAC;

  /// Whether to support extended master secret (RFC 7627)
  final bool useExtendedMasterSecret;

  /// Whether to require extended master secret
  final bool requireExtendedMasterSecret;

  /// List of supported TLS versions
  final List<(int, int)> supportedVersions;

  /// Default curve to use for ECDHE
  final String defaultCurve;

  /// Key shares to send in TLS 1.3 ClientHello
  final List<String> keyShares;

  /// Cipher to use for session tickets
  final String ticketCipher;

  /// PSK modes for TLS 1.3
  final List<String> pskModes;

  /// Keys for encrypting session tickets
  final List<dynamic> ticketKeys;

  /// Session ticket lifetime in seconds
  final int ticketLifetime;

  /// Use experimental 0-RTT temp key (not standardized)
  final bool useExperimental0rttTempKey;

  /// ALPN protocols to advertise
  final List<String> alpnProtos;

  /// Custom DH parameters (generator, prime)
  final (int, int)? dhParams;

  /// EC point formats to advertise
  final List<int> ecPointFormats;

  /// Callback for padding records
  final dynamic padding_cb;

  /// Record size limit extension value
  final int record_size_limit;

  /// Whether to use heartbeat extension
  final bool use_heartbeat_extension;

  /// Callback for heartbeat responses
  final dynamic heartbeat_response_callback;

  /// Maximum early data size for 0-RTT
  final int max_early_data;

  /// Ciphersuites that support heartbeat
  final List<int> heartbeatCiphersuites;

  /// Use legacy signature scheme ID combination
  final bool useLegacySignatureSchemeIDCombination;

  /// Create a new HandshakeSettings with modified values
  HandshakeSettings copyWith({
    int? minKeySize,
    int? maxKeySize,
    List<String>? cipherNames,
    List<String>? macNames,
    List<String>? certificateTypes,
    (int, int)? minVersion,
    (int, int)? maxVersion,
    bool? useExperimentalTackExtension,
    bool? sendFallbackSCSV,
    List<String>? rsaSigHashes,
    List<String>? dsaSigHashes,
    List<String>? ecdsaSigHashes,
    List<String>? moreSigSchemes,
    List<String>? rsaSchemes,
    List<String>? eccCurves,
    List<String>? dhGroups,
    bool? useEncryptThenMAC,
    bool? useExtendedMasterSecret,
    bool? requireExtendedMasterSecret,
    List<(int, int)>? supportedVersions,
    String? defaultCurve,
    List<String>? keyShares,
    String? ticketCipher,
    List<String>? pskModes,
    List<dynamic>? ticketKeys,
    int? ticketLifetime,
    bool? useExperimental0rttTempKey,
    List<String>? alpnProtos,
    (int, int)? dhParams,
    List<int>? ecPointFormats,
    dynamic padding_cb,
    int? record_size_limit,
    bool? use_heartbeat_extension,
    dynamic heartbeat_response_callback,
    int? max_early_data,
    List<int>? heartbeatCiphersuites,
    bool? useLegacySignatureSchemeIDCombination,
  }) {
    return HandshakeSettings(
      minKeySize: minKeySize ?? this.minKeySize,
      maxKeySize: maxKeySize ?? this.maxKeySize,
      cipherNames: cipherNames ?? this.cipherNames,
      macNames: macNames ?? this.macNames,
      certificateTypes: certificateTypes ?? this.certificateTypes,
      minVersion: minVersion ?? this.minVersion,
      maxVersion: maxVersion ?? this.maxVersion,
      useExperimentalTackExtension:
          useExperimentalTackExtension ?? this.useExperimentalTackExtension,
      sendFallbackSCSV: sendFallbackSCSV ?? this.sendFallbackSCSV,
      rsaSigHashes: rsaSigHashes ?? this.rsaSigHashes,
      dsaSigHashes: dsaSigHashes ?? this.dsaSigHashes,
      ecdsaSigHashes: ecdsaSigHashes ?? this.ecdsaSigHashes,
      moreSigSchemes: moreSigSchemes ?? this.moreSigSchemes,
      rsaSchemes: rsaSchemes ?? this.rsaSchemes,
      eccCurves: eccCurves ?? this.eccCurves,
      dhGroups: dhGroups ?? this.dhGroups,
      useEncryptThenMAC: useEncryptThenMAC ?? this.useEncryptThenMAC,
      useExtendedMasterSecret:
          useExtendedMasterSecret ?? this.useExtendedMasterSecret,
      requireExtendedMasterSecret:
          requireExtendedMasterSecret ?? this.requireExtendedMasterSecret,
      supportedVersions: supportedVersions ?? this.supportedVersions,
      defaultCurve: defaultCurve ?? this.defaultCurve,
      keyShares: keyShares ?? this.keyShares,
      ticketCipher: ticketCipher ?? this.ticketCipher,
      pskModes: pskModes ?? this.pskModes,
      ticketKeys: ticketKeys ?? this.ticketKeys,
      ticketLifetime: ticketLifetime ?? this.ticketLifetime,
      useExperimental0rttTempKey:
          useExperimental0rttTempKey ?? this.useExperimental0rttTempKey,
      alpnProtos: alpnProtos ?? this.alpnProtos,
      dhParams: dhParams ?? this.dhParams,
      ecPointFormats: ecPointFormats ?? this.ecPointFormats,
      padding_cb: padding_cb ?? this.padding_cb,
      record_size_limit: record_size_limit ?? this.record_size_limit,
      use_heartbeat_extension:
          use_heartbeat_extension ?? this.use_heartbeat_extension,
      heartbeat_response_callback:
          heartbeat_response_callback ?? this.heartbeat_response_callback,
      max_early_data: max_early_data ?? this.max_early_data,
      heartbeatCiphersuites:
          heartbeatCiphersuites ?? this.heartbeatCiphersuites,
      useLegacySignatureSchemeIDCombination:
          useLegacySignatureSchemeIDCombination ??
              this.useLegacySignatureSchemeIDCombination,
    );
  }

  /// Validate and normalize settings
  void validate() {
    // Check key sizes
    if (minKeySize < 512) {
      throw ArgumentError('minKeySize too small: $minKeySize');
    }
    if (maxKeySize < 512) {
      throw ArgumentError('maxKeySize too small: $maxKeySize');
    }
    if (minKeySize > maxKeySize) {
      throw ArgumentError('minKeySize > maxKeySize');
    }

    // Check versions
    if (!knownVersions.contains(minVersion)) {
      throw ArgumentError('Unknown minVersion: $minVersion');
    }
    if (!knownVersions.contains(maxVersion)) {
      throw ArgumentError('Unknown maxVersion: $maxVersion');
    }
    if (minVersion.$1 > maxVersion.$1 ||
        (minVersion.$1 == maxVersion.$1 && minVersion.$2 > maxVersion.$2)) {
      throw ArgumentError('minVersion > maxVersion');
    }

    // Validate cipher names
    for (final cipher in cipherNames) {
      if (!allCipherNames.contains(cipher)) {
        throw ArgumentError('Unknown cipher: $cipher');
      }
    }

    // Validate MAC names
    for (final mac in macNames) {
      if (!allMacNames.contains(mac)) {
        throw ArgumentError('Unknown MAC: $mac');
      }
    }

    // Validate certificate types
    for (final certType in certificateTypes) {
      if (!certificateTypes.contains(certType)) {
        throw ArgumentError('Unknown certificate type: $certType');
      }
    }

    // Validate curves
    for (final curve in eccCurves) {
      if (!allCurveNames.contains(curve)) {
        throw ArgumentError('Unknown curve: $curve');
      }
    }

    // Validate DH groups
    for (final group in dhGroups) {
      if (!allDhGroupNames.contains(group)) {
        throw ArgumentError('Unknown DH group: $group');
      }
    }
  }
}
