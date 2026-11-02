// Ported to Dart from tlslite-ng tlslite/constants.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:typed_data';


/// Converte uma string hexadecimal em uma lista de bytes (Uint8List).
Uint8List _hexToBytes(String hexString) {
  hexString =
      hexString.replaceAll(RegExp(r'\s+'), ''); // Remove espaços/novas linhas
  if (hexString.length % 2 != 0) {
    throw FormatException("Hex string must have an even number of characters");
  }
  final result = Uint8List(hexString.length ~/ 2);
  for (int i = 0; i < result.length; i++) {
    final byteString = hexString.substring(i * 2, (i * 2) + 2);
    result[i] = int.parse(byteString, radix: 16);
  }
  return result;
}

/// Constantes usadas em vários lugares.

/// Número da versão do protocolo usado para negociar TLS 1.3 entre implementações
/// da especificação de rascunho
/// DEPRECIADO!
const List<int> tls13Draft = [3, 4];

/// Valor ServerHello.random significando que a mensagem é um HelloRetryRequest
final Uint8List tls13Hrr = _hexToBytes(
    "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

/// Últimos bytes de ServerHello.random a serem usados ao negociar TLS 1.1 ou
/// anterior enquanto suporta TLS 1.2 ou superior
final Uint8List tls11DowngradeSentinel = _hexToBytes("444F574E47524400");

/// Últimos bytes de ServerHello.random a serem usados ao negociar TLS 1.2
/// enquanto suporta TLS 1.3 ou superior
final Uint8List tls12DowngradeSentinel = _hexToBytes("444F574E47524401");

final Uint8List rsaPssOid = _hexToBytes('06092a864886f70d01010a');

/// Classe base (conceitual) para diferentes enums de IDs TLS
/// Em Dart, usamos classes com constantes estáticas e mapas para lookup reverso.
abstract class _TLSEnumHelper {
  static String? intToName(int value, Map<int, String> map) {
    return map[value];
  }

  static String intToString(int value, Map<int, String> map) {
    return map[value] ?? value.toString();
  }
}

class CertificateType {
  static const int x509 = 0;
  static const int openpgp = 1;

  static const Map<int, String> _intToNameMap = {
    x509: 'x509',
    openpgp: 'openpgp',
  };

  /// Converte o tipo numérico para representação de string (nome se encontrado, null caso contrário)
  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);

  /// Converte o tipo numérico para string legível por humanos, se possível
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class ClientCertificateType {
  static const int rsaSign = 1;
  static const int dssSign = 2;
  static const int rsaFixedDh = 3;
  static const int dssFixedDh = 4;
  static const int ecdsaSign = 64; // RFC 8422
  static const int rsaFixedEcdh = 65; // RFC 8422
  static const int ecdsaFixedEcdh = 66; // RFC 8422

  static const Map<int, String> _intToNameMap = {
    rsaSign: 'rsa_sign',
    dssSign: 'dss_sign',
    rsaFixedDh: 'rsa_fixed_dh',
    dssFixedDh: 'dss_fixed_dh',
    ecdsaSign: 'ecdsa_sign',
    rsaFixedEcdh: 'rsa_fixed_ecdh',
    ecdsaFixedEcdh: 'ecdsa_fixed_ecdh',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class SSL2HandshakeType {
  /// Tipos de mensagem do Protocolo SSL2 Handshake.
  static const int error = 0;
  static const int clientHello = 1;
  static const int clientMasterKey = 2;
  static const int clientFinished = 3;
  static const int serverHello = 4;
  static const int serverVerify = 5;
  static const int serverFinished = 6;
  static const int requestCertificate = 7;
  static const int clientCertificate = 8;

  static const Map<int, String> _intToNameMap = {
    error: 'error',
    clientHello: 'client_hello',
    clientMasterKey: 'client_master_key',
    clientFinished: 'client_finished',
    serverHello: 'server_hello',
    serverVerify: 'server_verify',
    serverFinished: 'server_finished',
    requestCertificate: 'request_certificate',
    clientCertificate: 'client_certificate',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class SSL2ErrorDescription {
  /// Descrições de mensagens de erro do protocolo SSL2 Handshake
  static const int noCipher = 0x0001;
  static const int noCertificate = 0x0002;
  static const int badCertificate = 0x0004;
  static const int unsupportedCertificateType = 0x0006;

  static const Map<int, String> _intToNameMap = {
    noCipher: 'no_cipher',
    noCertificate: 'no_certificate',
    badCertificate: 'bad_certificate',
    unsupportedCertificateType: 'unsupported_certificate_type',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class HandshakeType {
  /// Tipos de mensagem no protocolo TLS Handshake
  static const int helloRequest = 0;
  static const int clientHello = 1;
  static const int serverHello = 2;
  static const int newSessionTicket = 4;
  static const int endOfEarlyData = 5; // TLS 1.3
  static const int helloRetryRequest = 6; // TLS 1.3
  static const int encryptedExtensions = 8; // TLS 1.3
  static const int certificate = 11;
  static const int serverKeyExchange = 12;
  static const int certificateRequest = 13;
  static const int serverHelloDone = 14;
  static const int certificateVerify = 15;
  static const int clientKeyExchange = 16;
  static const int finished = 20;
  static const int certificateStatus = 22;
  static const int keyUpdate = 24; // TLS 1.3
  static const int compressedCertificate = 25; // TLS 1.3 - RFC 8879
  static const int nextProtocol = 67; // Deprecated by ALPN
  static const int messageHash = 254; // TLS 1.3

  static const Map<int, String> _intToNameMap = {
    helloRequest: 'hello_request',
    clientHello: 'client_hello',
    serverHello: 'server_hello',
    newSessionTicket: 'new_session_ticket',
    endOfEarlyData: 'end_of_early_data',
    helloRetryRequest: 'hello_retry_request',
    encryptedExtensions: 'encrypted_extensions',
    certificate: 'certificate',
    serverKeyExchange: 'server_key_exchange',
    certificateRequest: 'certificate_request',
    serverHelloDone: 'server_hello_done',
    certificateVerify: 'certificate_verify',
    clientKeyExchange: 'client_key_exchange',
    finished: 'finished',
    certificateStatus: 'certificate_status',
    keyUpdate: 'key_update',
    compressedCertificate: 'compressed_certificate',
    nextProtocol: 'next_protocol',
    messageHash: 'message_hash',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class ContentType {
  /// Tipos de conteúdo da camada de registro TLS para payloads
  static const int changeCipherSpec = 20;
  static const int alert = 21;
  static const int handshake = 22;
  static const int applicationData = 23;
  static const int heartbeat = 24; // RFC 6520
  static const List<int> all = [20, 21, 22, 23, 24];

  static const Map<int, String> _intToNameMap = {
    changeCipherSpec: 'change_cipher_spec',
    alert: 'alert',
    handshake: 'handshake',
    applicationData: 'application_data',
    heartbeat: 'heartbeat',
  };

  /// Converte o tipo numérico para representação de nome
  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);

  /// Converte o tipo numérico para string legível por humanos, se possível
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class ExtensionType {
  /// Valores do registro de Tipo de Extensão TLS
  static const int serverName = 0; // RFC 6066 / 4366
  static const int maxFragmentLength = 1; // RFC 6066 / 4366
  static const int statusRequest = 5; // RFC 6066 / 4366
  static const int certType = 9; // RFC 6091
  static const int supportedGroups =
      10; // RFC 4492, RFC-ietf-tls-negotiated-ff-dhe-10
  static const int ecPointFormats = 11; // RFC 4492
  static const int srp = 12; // RFC 5054
  static const int signatureAlgorithms = 13; // RFC 5246
  static const int heartbeat = 15; // RFC 6520
  static const int alpn = 16; // RFC 7301
  static const int signedCertificateTimestamp = 18; // RFC 6962
  static const int clientHelloPadding = 21; // RFC 7685
  static const int encryptThenMac = 22; // RFC 7366
  static const int extendedMasterSecret = 23; // RFC 7627
  static const int compressCertificate = 27; // RFC 8879
  static const int recordSizeLimit = 28; // RFC 8449
  static const int sessionTicket = 35; // RFC 5077
  static const int extendedRandom =
      40; // draft-rescorla-tls-extended-random-02
  static const int preSharedKey = 41; // TLS 1.3
  static const int earlyData = 42; // TLS 1.3
  static const int supportedVersions = 43; // TLS 1.3
  static const int cookie = 44; // TLS 1.3
  static const int pskKeyExchangeModes = 45; // TLS 1.3
  static const int postHandshakeAuth = 49; // TLS 1.3
  static const int signatureAlgorithmsCert = 50; // TLS 1.3
  static const int keyShare = 51; // TLS 1.3
  static const int statusRequestV2 = 65; // RFC 6961
  static const int supportsNpn = 13172;
  static const int tack = 0xF300;
  static const int renegotiationInfo = 0xff01; // RFC 5746

  static const Map<int, String> _intToNameMap = {
    serverName: 'server_name',
    maxFragmentLength: 'max_fragment_length',
    statusRequest: 'status_request',
    certType: 'cert_type',
    supportedGroups: 'supported_groups',
    ecPointFormats: 'ec_point_formats',
    srp: 'srp',
    signatureAlgorithms: 'signature_algorithms',
    heartbeat: 'heartbeat',
    alpn: 'alpn',
    signedCertificateTimestamp: 'signed_certificate_timestamp',
    clientHelloPadding: 'client_hello_padding',
    encryptThenMac: 'encrypt_then_mac',
    extendedMasterSecret: 'extended_master_secret',
    compressCertificate: 'compress_certificate',
    recordSizeLimit: 'record_size_limit',
    sessionTicket: 'session_ticket',
    extendedRandom: 'extended_random',
    preSharedKey: 'pre_shared_key',
    earlyData: 'early_data',
    supportedVersions: 'supported_versions',
    cookie: 'cookie',
    pskKeyExchangeModes: 'psk_key_exchange_modes',
    postHandshakeAuth: 'post_handshake_auth',
    signatureAlgorithmsCert: 'signature_algorithms_cert',
    keyShare: 'key_share',
    statusRequestV2: 'status_request_v2',
    supportsNpn: 'supports_npn',
    tack: 'tack',
    renegotiationInfo: 'renegotiation_info',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class HashAlgorithm {
  /// IDs de algoritmo de hash usados no TLSv1.2
  static const int none = 0;
  static const int md5 = 1;
  static const int sha1 = 2;
  static const int sha224 = 3;
  static const int sha256 = 4;
  static const int sha384 = 5;
  static const int sha512 = 6;
  static const int intrinsic = 8; // RFC 8422

  static const Map<int, String> _intToNameMap = {
    none: 'none',
    md5: 'md5',
    sha1: 'sha1',
    sha224: 'sha224',
    sha256: 'sha256',
    sha384: 'sha384',
    sha512: 'sha512',
    intrinsic: 'intrinsic',
  };

  static final Map<String, int> _nameToIntMap = {
    for (final entry in _intToNameMap.entries) entry.value.toLowerCase(): entry.key,
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);

  /// Retorna o identificador numérico para o nome do hash informado.
  static int? fromName(String name) => _nameToIntMap[name.toLowerCase()];
}

class SignatureAlgorithm {
  /// Algoritmos de assinatura usados no TLSv1.2
  static const int anonymous = 0;
  static const int rsa = 1;
  static const int dsa = 2;
  static const int ecdsa = 3;
  static const int ed25519 = 7; // RFC 8422
  static const int ed448 = 8; // RFC 8422

  static const Map<int, String> _intToNameMap = {
    anonymous: 'anonymous',
    rsa: 'rsa',
    dsa: 'dsa',
    ecdsa: 'ecdsa',
    ed25519: 'ed25519',
    ed448: 'ed448',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

/// Representa um valor de esquema de assinatura (par hash, sig)
class _SignatureSchemeValue {
  final int hashAlgorithm;
  final int signatureAlgorithm;
  final int value; // Valor combinado como em TLS (hash << 8 | sig)

  const _SignatureSchemeValue(this.hashAlgorithm, this.signatureAlgorithm)
      : value = (hashAlgorithm << 8) | signatureAlgorithm;

  // Permite comparar com o valor numérico combinado
  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is _SignatureSchemeValue &&
          runtimeType == other.runtimeType &&
          value == other.value ||
      other is int && value == other; // Permite comparar com int diretamente

  @override
  int get hashCode => value.hashCode;

  @override
  String toString() =>
      '(${HashAlgorithm.toStr(hashAlgorithm)}, ${SignatureAlgorithm.toStr(signatureAlgorithm)})';
}

class SignatureScheme {
  /// Esquema de assinatura usado para sinalizar algoritmos de assinatura suportados.
  /// Este é o substituto para as listas HashAlgorithm e SignatureAlgorithm.
  /// Introduzido com TLSv1.3.

  static const _SignatureSchemeValue rsaPkcs1Sha1 = _SignatureSchemeValue(
      HashAlgorithm.sha1, SignatureAlgorithm.rsa); // 0x0201
  static const _SignatureSchemeValue rsaPkcs1Sha224 = _SignatureSchemeValue(
      HashAlgorithm.sha224,
      SignatureAlgorithm.rsa); // 0x0301 - Non-standard? Check RFCs
  static const _SignatureSchemeValue rsaPkcs1Sha256 = _SignatureSchemeValue(
      HashAlgorithm.sha256, SignatureAlgorithm.rsa); // 0x0401
  static const _SignatureSchemeValue rsaPkcs1Sha384 = _SignatureSchemeValue(
      HashAlgorithm.sha384, SignatureAlgorithm.rsa); // 0x0501
  static const _SignatureSchemeValue rsaPkcs1Sha512 = _SignatureSchemeValue(
      HashAlgorithm.sha512, SignatureAlgorithm.rsa); // 0x0601
  static const _SignatureSchemeValue ecdsaSha1 = _SignatureSchemeValue(
      HashAlgorithm.sha1, SignatureAlgorithm.ecdsa); // 0x0203
  static const _SignatureSchemeValue ecdsaSha224 = _SignatureSchemeValue(
      HashAlgorithm.sha224,
      SignatureAlgorithm.ecdsa); // 0x0303 - Non-standard? Check RFCs
  static const _SignatureSchemeValue ecdsaSecp256r1Sha256 =
      _SignatureSchemeValue(
          HashAlgorithm.sha256, SignatureAlgorithm.ecdsa); // 0x0403
  static const _SignatureSchemeValue ecdsaSecp384r1Sha384 =
      _SignatureSchemeValue(
          HashAlgorithm.sha384, SignatureAlgorithm.ecdsa); // 0x0503
  static const _SignatureSchemeValue ecdsaSecp521r1Sha512 =
      _SignatureSchemeValue(
          HashAlgorithm.sha512, SignatureAlgorithm.ecdsa); // 0x0603
  static const _SignatureSchemeValue rsaPssRsaeSha256 =
      _SignatureSchemeValue(HashAlgorithm.intrinsic,
          4); // 0x0804 - Note: Hash is intrinsic to PSS
  static const _SignatureSchemeValue rsaPssRsaeSha384 =
      _SignatureSchemeValue(HashAlgorithm.intrinsic, 5); // 0x0805
  static const _SignatureSchemeValue rsaPssRsaeSha512 =
      _SignatureSchemeValue(HashAlgorithm.intrinsic, 6); // 0x0806
  static const _SignatureSchemeValue ed25519 = _SignatureSchemeValue(
      HashAlgorithm.intrinsic, SignatureAlgorithm.ed25519); // 0x0807 - RFC 8422
  static const _SignatureSchemeValue ed448 = _SignatureSchemeValue(
      HashAlgorithm.intrinsic, SignatureAlgorithm.ed448); // 0x0808 - RFC 8422
  static const _SignatureSchemeValue rsaPssPssSha256 =
      _SignatureSchemeValue(HashAlgorithm.intrinsic, 9); // 0x0809
  static const _SignatureSchemeValue rsaPssPssSha384 =
      _SignatureSchemeValue(HashAlgorithm.intrinsic, 10); // 0x080a
  static const _SignatureSchemeValue rsaPssPssSha512 =
      _SignatureSchemeValue(HashAlgorithm.intrinsic, 11); // 0x080b

  // backwards compatibility (for TLS1.2) aliases
  static const _SignatureSchemeValue rsaPssSha256 = rsaPssRsaeSha256;
  static const _SignatureSchemeValue rsaPssSha384 = rsaPssRsaeSha384;
  static const _SignatureSchemeValue rsaPssSha512 = rsaPssRsaeSha512;

  // RFC 8734
  static const _SignatureSchemeValue ecdsaBrainpoolP256r1tls13Sha256 =
      _SignatureSchemeValue(HashAlgorithm.intrinsic, 0x1A); // 0x081A
  static const _SignatureSchemeValue ecdsaBrainpoolP384r1tls13Sha384 =
      _SignatureSchemeValue(HashAlgorithm.intrinsic, 0x1B); // 0x081B
  static const _SignatureSchemeValue ecdsaBrainpoolP512r1tls13Sha512 =
      _SignatureSchemeValue(HashAlgorithm.intrinsic, 0x1C); // 0x081C

  static const _SignatureSchemeValue dsaSha1 = _SignatureSchemeValue(
      HashAlgorithm.sha1, SignatureAlgorithm.dsa); // 0x0202
  static const _SignatureSchemeValue dsaSha224 = _SignatureSchemeValue(
      HashAlgorithm.sha224,
      SignatureAlgorithm.dsa); // 0x0302 - Non-standard? Check RFCs
  static const _SignatureSchemeValue dsaSha256 = _SignatureSchemeValue(
      HashAlgorithm.sha256, SignatureAlgorithm.dsa); // 0x0402
  static const _SignatureSchemeValue dsaSha384 = _SignatureSchemeValue(
      HashAlgorithm.sha384, SignatureAlgorithm.dsa); // 0x0502
  static const _SignatureSchemeValue dsaSha512 = _SignatureSchemeValue(
      HashAlgorithm.sha512, SignatureAlgorithm.dsa); // 0x0602

  static const Map<int, String> _valueToNameMap = {
    0x0201: 'rsa_pkcs1_sha1',
    0x0301: 'rsa_pkcs1_sha224',
    0x0401: 'rsa_pkcs1_sha256',
    0x0501: 'rsa_pkcs1_sha384',
    0x0601: 'rsa_pkcs1_sha512',
    0x0203: 'ecdsa_sha1',
    0x0303: 'ecdsa_sha224',
    0x0403: 'ecdsa_secp256r1_sha256',
    0x0503: 'ecdsa_secp384r1_sha384',
    0x0603: 'ecdsa_secp521r1_sha512',
    0x0804: 'rsa_pss_rsae_sha256', // Also rsa_pss_sha256
    0x0805: 'rsa_pss_rsae_sha384', // Also rsa_pss_sha384
    0x0806: 'rsa_pss_rsae_sha512', // Also rsa_pss_sha512
    0x0807: 'ed25519',
    0x0808: 'ed448',
    0x0809: 'rsa_pss_pss_sha256',
    0x080a: 'rsa_pss_pss_sha384',
    0x080b: 'rsa_pss_pss_sha512',
    0x081A: 'ecdsa_brainpoolP256r1tls13_sha256',
    0x081B: 'ecdsa_brainpoolP384r1tls13_sha384',
    0x081C: 'ecdsa_brainpoolP512r1tls13_sha512',
    0x0202: 'dsa_sha1',
    0x0302: 'dsa_sha224',
    0x0402: 'dsa_sha256',
    0x0502: 'dsa_sha384',
    0x0602: 'dsa_sha512',
  };

  static const Map<String, _SignatureSchemeValue> _nameToValueMap = {
    'rsa_pkcs1_sha1': rsaPkcs1Sha1,
    'rsa_pkcs1_sha224': rsaPkcs1Sha224,
    'rsa_pkcs1_sha256': rsaPkcs1Sha256,
    'rsa_pkcs1_sha384': rsaPkcs1Sha384,
    'rsa_pkcs1_sha512': rsaPkcs1Sha512,
    'ecdsa_sha1': ecdsaSha1,
    'ecdsa_sha224': ecdsaSha224,
    'ecdsa_secp256r1_sha256': ecdsaSecp256r1Sha256,
    'ecdsa_secp384r1_sha384': ecdsaSecp384r1Sha384,
    'ecdsa_secp521r1_sha512': ecdsaSecp521r1Sha512,
    'rsa_pss_rsae_sha256': rsaPssRsaeSha256,
    'rsa_pss_rsae_sha384': rsaPssRsaeSha384,
    'rsa_pss_rsae_sha512': rsaPssRsaeSha512,
    'ed25519': ed25519,
    'ed448': ed448,
    'rsa_pss_pss_sha256': rsaPssPssSha256,
    'rsa_pss_pss_sha384': rsaPssPssSha384,
    'rsa_pss_pss_sha512': rsaPssPssSha512,
    'rsa_pss_sha256': rsaPssSha256, // alias
    'rsa_pss_sha384': rsaPssSha384, // alias
    'rsa_pss_sha512': rsaPssSha512, // alias
    'ecdsa_brainpoolP256r1tls13_sha256': ecdsaBrainpoolP256r1tls13Sha256,
    'ecdsa_brainpoolP384r1tls13_sha384': ecdsaBrainpoolP384r1tls13Sha384,
    'ecdsa_brainpoolP512r1tls13_sha512': ecdsaBrainpoolP512r1tls13Sha512,
    'dsa_sha1': dsaSha1,
    'dsa_sha224': dsaSha224,
    'dsa_sha256': dsaSha256,
    'dsa_sha384': dsaSha384,
    'dsa_sha512': dsaSha512,
  };

  static _SignatureSchemeValue? _lookup(String schemeName) {
    return _nameToValueMap[schemeName.toLowerCase()];
  }

  static bool isSupported(String schemeName) => _lookup(schemeName) != null;

  static int? valueOf(String schemeName) => _lookup(schemeName)?.value;

  static int? hashIdFromName(String schemeName) =>
      _lookup(schemeName)?.hashAlgorithm;

  static int? signatureIdFromName(String schemeName) =>
      _lookup(schemeName)?.signatureAlgorithm;

  /// Converte o valor numérico (_SignatureSchemeValue ou int) para representação de nome
  static String? toRepr(dynamic value) {
    int? intValue;
    if (value is _SignatureSchemeValue) {
      intValue = value.value;
    } else if (value is int) {
      intValue = value;
    }
    if (intValue != null) {
      return _valueToNameMap[intValue];
    }
    return null;
  }

  /// Converte o valor numérico (_SignatureSchemeValue ou int) para string legível por humanos, se possível
  static String toStr(dynamic value) => toRepr(value) ?? value.toString();

  /// Retorna o nome do algoritmo de assinatura usado no esquema.
  /// Ex: para "rsa_pkcs1_sha1" retorna "rsa"
  static String getKeyType(String schemeName) {
    final normalized = schemeName.toLowerCase();
    if (normalized == "ed25519" || normalized == "ed448") {
      return "eddsa";
    }
    if (!_nameToValueMap.containsKey(normalized)) {
      throw ArgumentError('"$schemeName" scheme is unknown');
    }
    // Heurística baseada nos nomes comuns
    if (normalized.startsWith('rsa_')) return 'rsa';
    if (normalized.startsWith('ecdsa_')) return 'ecdsa';
    if (normalized.startsWith('dsa_')) return 'dsa';
    // Casos especiais ou fallback (pode precisar de ajuste)
    if (normalized.contains('rsa')) return 'rsa';
    if (normalized.contains('ecdsa')) return 'ecdsa';
    if (normalized.contains('dsa')) return 'dsa';

    throw ArgumentError('Could not determine key type for "$schemeName"');
  }

  /// Retorna o nome do esquema de padding usado no esquema de assinatura.
  static String getPadding(String schemeName) {
    final normalized = schemeName.toLowerCase();
    if (!_nameToValueMap.containsKey(normalized)) {
      throw ArgumentError('"$schemeName" scheme is unknown');
    }
    final parts = normalized.split('_');
    // Heurística: rsa_pkcs1_..., rsa_pss_...
    if (parts.length >= 2 && parts[0] == 'rsa') {
      if (parts[1] == 'pkcs1') return 'pkcs1';
      if (parts[1] == 'pss') return 'pss'; // Pode ser pss_rsae ou pss_pss
    }
    // Outros não usam padding explícito no nome geralmente
    // Ou o padding está implícito no tipo de chave (ex: ecdsa)
    // Retornar uma string vazia ou null pode ser apropriado
    return ''; // Ou lançar erro se padding for sempre esperado para RSA
  }

  /// Retorna o nome do hash usado no esquema de assinatura.
  static String getHash(String schemeName) {
    // Hash não explícito para EDDSA, veja RFC 8422
    final normalized = schemeName.toLowerCase();
    if (normalized == "ed25519" || normalized == "ed448") {
      return "intrinsic";
    }
    final value = _nameToValueMap[normalized];
    if (value == null) {
      throw ArgumentError('"$schemeName" scheme is unknown');
    }

    // Para PSS, o hash está ligado ao MGF e não é o mesmo que o "HashAlgorithm" no valor TLS
    if (normalized.contains("_pss_")) {
      if (normalized.endsWith("_sha256")) return "sha256";
      if (normalized.endsWith("_sha384")) return "sha384";
      if (normalized.endsWith("_sha512")) return "sha512";
      return "intrinsic"; // Ou outro valor indicando que depende dos params PSS
    }
    // Para Brainpool TLS1.3, o nome já inclui o hash
    if (normalized.contains("tls13")) {
      if (normalized.endsWith("_sha256")) return "sha256";
      if (normalized.endsWith("_sha384")) return "sha384";
      if (normalized.endsWith("_sha512")) return "sha512";
    }

    // Usa o mapeamento reverso de HashAlgorithm
    return HashAlgorithm.toStr(value.hashAlgorithm);
  }
}

/// conjunto de esquemas específicos do TLS 1.3 para curvas Brainpool
final Set<_SignatureSchemeValue> tls13BrainpoolSigSchemes =
    Set.unmodifiable([
  SignatureScheme.ecdsaBrainpoolP256r1tls13Sha256,
  SignatureScheme.ecdsaBrainpoolP384r1tls13Sha384,
  SignatureScheme.ecdsaBrainpoolP512r1tls13Sha512,
]);

class AlgorithmOID {
  /// OIDs de Algoritmo como definidos em rfc5758(ecdsa),
  /// rfc5754(rsa, sha), rfc3447(rss-pss).
  /// A chave é o OID codificado em DER em bytes (Uint8List) e
  /// o valor é o id do algoritmo (SignatureSchemeValue ou um par legado).

  // Nota: A comparação de chaves Uint8List em Map requer cuidados.
  // Usar String codificada em Base64 pode ser mais robusto, ou uma classe wrapper.
  // Mantendo Uint8List por enquanto para tradução direta.

  // É crucial que as instâncias de Uint8List usadas como chaves sejam canônicas
  // (ou seja, sempre criadas da mesma forma para o mesmo valor lógico).
  // _hexToBytes garante isso.

  static final Map<Uint8List, dynamic> oid = _initializeOidMap();

  static Map<Uint8List, dynamic> _initializeOidMap() {
    // Usando um método estático para inicialização para melhor legibilidade
    final map = <Uint8List, dynamic>{};

    map[_hexToBytes('06072a8648ce3d0401')] = SignatureScheme.ecdsaSha1;
    map[_hexToBytes('06082a8648ce3d040301')] =
        SignatureScheme.ecdsaSha224; // Check standard
    map[_hexToBytes('06082a8648ce3d040302')] =
        SignatureScheme.ecdsaSecp256r1Sha256;
    map[_hexToBytes('06082a8648ce3d040303')] =
        SignatureScheme.ecdsaSecp384r1Sha384;
    map[_hexToBytes('06082a8648ce3d040304')] =
        SignatureScheme.ecdsaSecp521r1Sha512;
    map[_hexToBytes('06092a864886f70d010104')] = const [
      HashAlgorithm.md5,
      SignatureAlgorithm.rsa
    ]; // Legacy tuple
    map[_hexToBytes('06092a864886f70d010105')] = SignatureScheme.rsaPkcs1Sha1;
    map[_hexToBytes('06092a864886f70d01010e')] =
        SignatureScheme.rsaPkcs1Sha224; // Check standard
    map[_hexToBytes('06092a864886f70d01010b')] =
        SignatureScheme.rsaPkcs1Sha256;
    map[_hexToBytes('06092a864886f70d01010c')] =
        SignatureScheme.rsaPkcs1Sha384;
    map[_hexToBytes('06092a864886f70d01010d')] =
        SignatureScheme.rsaPkcs1Sha512;
    // Note: OID for rsaEncryption (1.2.840.113549.1.1.1) might also map to RSA generically?

    // PSS OIDs (RFC 4055 / RFC 8017) - Note the parameters part
    // id-RSASSA-PSS (1.2.840.113549.1.1.10)
    map[_hexToBytes('06092a864886f70d01010a')] =
        'rsaEncryptionPss'; // Generic PSS identifier
    // Specific hash OIDs under RSASSA-PSS parameters (less common in cert sig alg field itself)
    // Example from  code structure suggests mapping specific DER encodings
    map[_hexToBytes('300b0609608648016503040201')] = SignatureScheme
        .rsaPssRsaeSha256; // Check encoding, likely part of PSS params
    map[_hexToBytes('300b0609608648016503040202')] =
        SignatureScheme.rsaPssRsaeSha384; // Check encoding
    map[_hexToBytes('300b0609608648016503040203')] =
        SignatureScheme.rsaPssRsaeSha512; // Check encoding
    // With NULL parameters (RFC 4055 Section 2.1)
    map[_hexToBytes('300d06096086480165030402010500')] =
        SignatureScheme.rsaPssRsaeSha256; // Check encoding
    map[_hexToBytes('300d06096086480165030402020500')] =
        SignatureScheme.rsaPssRsaeSha384; // Check encoding
    map[_hexToBytes('300d06096086480165030402030500')] =
        SignatureScheme.rsaPssRsaeSha512; // Check encoding

    // DSA OIDs (RFC 5754)
    map[_hexToBytes('06072A8648CE380403')] =
        SignatureScheme.dsaSha1; // id-dsa-with-sha1
    // OIDs for dsa-with-sha2 (RFC 5754 section 3.2)
    map[_hexToBytes('0609608648016503040301')] =
        SignatureScheme.dsaSha224; // id-dsa-with-sha224
    map[_hexToBytes('0609608648016503040302')] =
        SignatureScheme.dsaSha256; // id-dsa-with-sha256
    // RFC 5754 doesn't define DSA with SHA384/512 OIDs explicitly for certs? Check updates.
    //  code includes them, potentially from other contexts.
    // map[_hexToBytes('0609608648016503040303')] = SignatureScheme.dsaSha384;
    // map[_hexToBytes('0609608648016503040304')] = SignatureScheme.dsaSha512;

    // EdDSA OIDs (RFC 8410)
    map[_hexToBytes('06032b6570')] = SignatureScheme.ed25519; // id-Ed25519
    map[_hexToBytes('06032b6571')] = SignatureScheme.ed448; // id-Ed448

    // Note: Comparing Uint8List keys requires iterating or using a specialized Map.
    // For simplicity here, assume direct lookup works if the input Uint8List is canonical.
    return Map.unmodifiable(map);
  }

  // Helper to find value for a given OID (Uint8List)
  // This requires iterating because default Map equality on lists checks identity.
  static dynamic findSignatureSchemeForOid(Uint8List oidBytes) {
    for (var entry in oid.entries) {
      if (_listEquals(entry.key, oidBytes)) {
        return entry.value;
      }
    }
    return null;
  }

  // Helper to compare Uint8List instances for equality
  static bool _listEquals(Uint8List? a, Uint8List? b) {
    if (a == null) return b == null;
    if (b == null || a.length != b.length) return false;
    for (int i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }
}

class GroupName {
  /// Nome dos grupos suportados para troca de chaves (EC)DH
  // RFC4492 - Deprecated/Obsolete curves often removed
  static const int sect163k1 = 1;
  static const int sect163r1 = 2;
  static const int sect163r2 = 3;
  static const int sect193r1 = 4;
  static const int sect193r2 = 5;
  static const int sect233k1 = 6;
  static const int sect233r1 = 7;
  static const int sect239k1 = 8;
  static const int sect283k1 = 9;
  static const int sect283r1 = 10;
  static const int sect409k1 = 11;
  static const int sect409r1 = 12;
  static const int sect571k1 = 13;
  static const int sect571r1 = 14;
  static const int secp160k1 = 15;
  static const int secp160r1 = 16;
  static const int secp160r2 = 17;
  static const int secp192k1 = 18;
  static const int secp192r1 = 19; // NIST P-192
  static const int secp224k1 = 20;
  static const int secp224r1 = 21; // NIST P-224
  static const int secp256k1 = 22; // Bitcoin curve
  static const int secp256r1 = 23; // NIST P-256, prime256v1
  static const int secp384r1 = 24; // NIST P-384
  static const int secp521r1 = 25; // NIST P-521

  // RFC7027 - Brainpool Curves (Now RFC 8422)
  static const int brainpoolP256r1 = 26;
  static const int brainpoolP384r1 = 27;
  static const int brainpoolP512r1 = 28;

  // RFC 8422 / RFC 7748 - Modern Curves
  static const int x25519 = 29; // Curve25519 ECDH
  static const int x448 = 30; // Curve448 ECDH

  // RFC7919 - Finite Field Diffie-Hellman Ephemeral Parameters
  static const int ffdhe2048 = 256;
  static const int ffdhe3072 = 257;
  static const int ffdhe4096 = 258;
  static const int ffdhe6144 = 259;
  static const int ffdhe8192 = 260;

  // RFC8734 - Brainpool Curves for TLS 1.3 Key Exchange
  static const int brainpoolP256r1tls13 = 31;
  static const int brainpoolP384r1tls13 = 32;
  static const int brainpoolP512r1tls13 = 33;

  // draft-kwiatkowski-tls-ecdhe-mlkem - Post-Quantum KEMs (Experimental)
  static const int secp256r1mlkem768 = 0x11EB;
  static const int x25519mlkem768 = 0x11EC;
  static const int secp384r1mlkem1024 = 0x11ED;

  // --- Grouping Lists ---
  static final List<int> allEC = List.unmodifiable([
    sect163k1,
    sect163r1,
    sect163r2,
    sect193r1,
    sect193r2,
    sect233k1,
    sect233r1,
    sect239k1,
    sect283k1,
    sect283r1,
    sect409k1,
    sect409r1,
    sect571k1,
    sect571r1,
    secp160k1,
    secp160r1,
    secp160r2,
    secp192k1,
    secp192r1,
    secp224k1,
    secp224r1,
    secp256k1,
    secp256r1,
    secp384r1,
    secp521r1,
    brainpoolP256r1,
    brainpoolP384r1,
    brainpoolP512r1,
    x25519,
    x448,
    brainpoolP256r1tls13,
    brainpoolP384r1tls13,
    brainpoolP512r1tls13
  ]);

  static final List<int> allFF = List.unmodifiable(
      [ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192]);

  static final List<int> allKEM = List.unmodifiable(
      [secp256r1mlkem768, x25519mlkem768, secp384r1mlkem1024]);

  static final List<int> all =
      List.unmodifiable([...allEC, ...allFF, ...allKEM]);

  static const Map<int, String> _intToNameMap = {
    sect163k1: 'sect163k1',
    sect163r1: 'sect163r1',
    sect163r2: 'sect163r2',
    sect193r1: 'sect193r1',
    sect193r2: 'sect193r2',
    sect233k1: 'sect233k1',
    sect233r1: 'sect233r1',
    sect239k1: 'sect239k1',
    sect283k1: 'sect283k1',
    sect283r1: 'sect283r1',
    sect409k1: 'sect409k1',
    sect409r1: 'sect409r1',
    sect571k1: 'sect571k1',
    sect571r1: 'sect571r1',
    secp160k1: 'secp160k1',
    secp160r1: 'secp160r1',
    secp160r2: 'secp160r2',
    secp192k1: 'secp192k1',
    secp192r1: 'secp192r1',
    secp224k1: 'secp224k1',
    secp224r1: 'secp224r1',
    secp256k1: 'secp256k1',
    secp256r1: 'secp256r1',
    secp384r1: 'secp384r1',
    secp521r1: 'secp521r1',
    brainpoolP256r1: 'brainpoolP256r1',
    brainpoolP384r1: 'brainpoolP384r1',
    brainpoolP512r1: 'brainpoolP512r1',
    x25519: 'x25519',
    x448: 'x448',
    ffdhe2048: 'ffdhe2048',
    ffdhe3072: 'ffdhe3072',
    ffdhe4096: 'ffdhe4096',
    ffdhe6144: 'ffdhe6144',
    ffdhe8192: 'ffdhe8192',
    brainpoolP256r1tls13: 'brainpoolP256r1tls13',
    brainpoolP384r1tls13: 'brainpoolP384r1tls13',
    brainpoolP512r1tls13: 'brainpoolP512r1tls13',
    secp256r1mlkem768: 'secp256r1mlkem768',
    x25519mlkem768: 'x25519mlkem768',
    secp384r1mlkem1024: 'secp384r1mlkem1024',
  };

  static final Map<String, int> _nameToIntMap = {
    for (final entry in _intToNameMap.entries)
      entry.value.toLowerCase(): entry.key,
  };

  /// Converte o tipo numérico para representação de nome
  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);

  /// Converte o tipo numérico para string legível por humanos, se possível
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);

  /// Resolve o identificador numérico a partir do nome textual do grupo.
  static int? valueOf(String name) => _nameToIntMap[name.toLowerCase()];
}

// grupos proibidos pela RFC 8446 seção B.3.1.4
// (Curvas arbitrárias e obsoletas/fracas nomeadas)
final Set<int> tls13ForbiddenGroups = Set.unmodifiable([
  ...List<int>.generate(
      0x17 - 1,
      (i) =>
          i +
          1), // 1 a 22 (sect163k1 a secp256k1) - Inclui curvas não recomendadas
  ...List<int>.generate(
      0x1D - 0x1A,
      (i) =>
          i +
          0x1A), // 26 a 28 (brainpoolP*r1) - Permitidas se explicitamente listadas e acordadas
  0xff01, 0xff02 // explicit_prime, explicit_char2
]);
// Nota: A proibição real em TLS 1.3 é mais sobre não usar curvas arbitrárias
// e focar nas recomendadas (secp256r1, secp384r1, secp521r1, x25519, x448, ffdhe*)
// Esta lista parece refletir as curvas nomeadas *não* recomendadas.

class ECPointFormat {
  /// Nomes e IDs dos formatos de ponto EC suportados.
  static const int uncompressed = 0;
  static const int ansiX962CompressedPrime = 1;
  static const int ansiX962CompressedChar2 = 2;

  static const List<int> all = [
    uncompressed,
    ansiX962CompressedPrime,
    ansiX962CompressedChar2
  ];

  static const Map<int, String> _intToNameMap = {
    uncompressed: 'uncompressed',
    ansiX962CompressedPrime: 'ansiX962_compressed_prime',
    ansiX962CompressedChar2: 'ansiX962_compressed_char2',
  };

  /// Converte o tipo numérico para representação de nome.
  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);

  /// Converte o tipo numérico para string legível por humanos, se possível.
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class ECCurveType {
  /// Tipos de curvas ECC suportadas em TLS do RFC4492
  static const int explicitPrime = 1;
  static const int explicitChar2 = 2;
  static const int namedCurve = 3;

  static const Map<int, String> _intToNameMap = {
    explicitPrime: 'explicit_prime',
    explicitChar2: 'explicit_char2',
    namedCurve: 'named_curve',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class NameType {
  /// Tipo de entradas na extensão Server Name Indication.
  static const int hostName = 0;

  static const Map<int, String> _intToNameMap = {
    hostName: 'host_name',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class CertificateStatusType {
  /// Tipo de respostas nas mensagens status_request e CertificateStatus.
  static const int ocsp = 1;

  static const Map<int, String> _intToNameMap = {
    ocsp: 'ocsp',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class HeartbeatMode {
  /// Tipos de modos heartbeat do RFC 6520
  static const int peerAllowedToSend = 1;
  static const int peerNotAllowedToSend = 2;

  static const Map<int, String> _intToNameMap = {
    peerAllowedToSend: 'PEER_ALLOWED_TO_SEND',
    peerNotAllowedToSend: 'PEER_NOT_ALLOWED_TO_SEND',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class HeartbeatMessageType {
  /// Tipos de mensagens heartbeat do RFC 6520
  static const int heartbeatRequest = 1;
  static const int heartbeatResponse = 2;

  static const Map<int, String> _intToNameMap = {
    heartbeatRequest: 'heartbeat_request',
    heartbeatResponse: 'heartbeat_response',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class KeyUpdateMessageType {
  /// Tipos de mensagens keyupdate do RFC 8446
  static const int updateNotRequested = 0;
  static const int updateRequested = 1;

  static const Map<int, String> _intToNameMap = {
    updateNotRequested: 'update_not_requested',
    updateRequested: 'update_requested',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class AlertLevel {
  /// Enumeração de níveis do protocolo TLS Alert
  static const int warning = 1;
  static const int fatal = 2;

  static const Map<int, String> _intToNameMap = {
    warning: 'warning',
    fatal: 'fatal',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class AlertDescription {
  /// Descrições de Alerta TLS
  ///
  /// `bad_record_mac`: Um registro TLS falhou ao descriptografar corretamente.
  /// Se isso ocorrer durante um handshake SRP, provavelmente indica uma senha incorreta.
  /// Também pode indicar um erro de implementação ou alguma adulteração dos dados em trânsito.
  /// Este alerta será sinalizado pelo servidor se a senha SRP estiver incorreta.
  /// Também pode ser sinalizado pelo servidor se o nome de usuário SRP for desconhecido
  /// para o servidor, mas ele não deseja revelar esse fato.
  ///
  /// `handshake_failure`: Ocorreu um problema durante o handshake.
  /// Isso geralmente indica falta de conjuntos de cifras comuns entre cliente e servidor,
  /// ou algum outro desacordo (sobre parâmetros SRP ou tamanhos de chave, por exemplo).
  ///
  /// `protocol_version`: A versão SSL/TLS da outra parte era inaceitável.
  /// Indica que o cliente e o servidor não conseguiram concordar sobre qual versão
  /// de SSL ou TLS usar.
  ///
  /// `user_canceled`: O handshake está sendo cancelado por algum motivo.

  static const int closeNotify = 0;
  static const int unexpectedMessage = 10;
  static const int badRecordMac = 20;
  static const int decryptionFailed =
      21; // TLS 1.3 replaces legacy description
  static const int recordOverflow = 22;
  static const int decompressionFailure = 30; // Legacy
  static const int handshakeFailure = 40;
  static const int noCertificate = 41; // SSLv3, removed in TLS
  static const int badCertificate = 42;
  static const int unsupportedCertificate = 43;
  static const int certificateRevoked = 44;
  static const int certificateExpired = 45;
  static const int certificateUnknown = 46;
  static const int illegalParameter = 47;
  static const int unknownCa = 48;
  static const int accessDenied = 49;
  static const int decodeError = 50;
  static const int decryptError = 51;
  static const int exportRestriction = 60; // Legacy
  static const int protocolVersion = 70;
  static const int insufficientSecurity = 71;
  static const int internalError = 80;
  static const int inappropriateFallback = 86; // RFC 7507
  static const int userCanceled = 90;
  static const int noRenegotiation = 100; // RFC 5746, deprecated in TLS 1.3
  static const int missingExtension = 109; // RFC 8446 Appendix B.3.1
  static const int unsupportedExtension = 110; // RFC 5246 / RFC 8446
  static const int certificateUnobtainable = 111; // RFC 6066 / RFC 8446
  static const int unrecognizedName = 112; // RFC 6066 / RFC 8446
  static const int badCertificateStatusResponse = 113; // RFC 6066 / RFC 8446
  static const int badCertificateHashValue = 114; // RFC 6066 / RFC 8446
  static const int unknownPskIdentity = 115; // RFC 8446
  static const int certificateRequired = 116; // RFC 8446
  static const int noApplicationProtocol = 120; // RFC 7301

  static const Map<int, String> _intToNameMap = {
    closeNotify: 'close_notify',
    unexpectedMessage: 'unexpected_message',
    badRecordMac: 'bad_record_mac',
    decryptionFailed: 'decryption_failed',
    recordOverflow: 'record_overflow',
    decompressionFailure: 'decompression_failure',
    handshakeFailure: 'handshake_failure',
    noCertificate: 'no_certificate',
    badCertificate: 'bad_certificate',
    unsupportedCertificate: 'unsupported_certificate',
    certificateRevoked: 'certificate_revoked',
    certificateExpired: 'certificate_expired',
    certificateUnknown: 'certificate_unknown',
    illegalParameter: 'illegal_parameter',
    unknownCa: 'unknown_ca',
    accessDenied: 'access_denied',
    decodeError: 'decode_error',
    decryptError: 'decrypt_error',
    exportRestriction: 'export_restriction',
    protocolVersion: 'protocol_version',
    insufficientSecurity: 'insufficient_security',
    internalError: 'internal_error',
    inappropriateFallback: 'inappropriate_fallback',
    userCanceled: 'user_canceled',
    noRenegotiation: 'no_renegotiation',
    missingExtension: 'missing_extension',
    unsupportedExtension: 'unsupported_extension',
    certificateUnobtainable: 'certificate_unobtainable',
    unrecognizedName: 'unrecognized_name',
    badCertificateStatusResponse: 'bad_certificate_status_response',
    badCertificateHashValue: 'bad_certificate_hash_value',
    unknownPskIdentity: 'unknown_psk_identity',
    certificateRequired: 'certificate_required',
    noApplicationProtocol: 'no_application_protocol',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class PskKeyExchangeMode {
  /// Valores usados na extensão PSK Key Exchange Modes.
  static const int pskKe = 0; // PSK-only key establishment
  static const int pskDheKe = 1; // PSK with (EC)DHE key establishment

  static const Map<int, String> _intToNameMap = {
    pskKe: 'psk_ke',
    pskDheKe: 'psk_dhe_ke',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

class CertificateCompressionAlgorithm {
  /// Algoritmos de compressão usados para a compressão de certificados
  /// do RFC 8879.
  static const int zlib = 1;
  static const int brotli = 2;
  static const int zstd = 3;

  static const Map<int, String> _intToNameMap = {
    zlib: 'zlib',
    brotli: 'brotli',
    zstd: 'zstd',
  };

  static String? toRepr(int value) =>
      _TLSEnumHelper.intToName(value, _intToNameMap);
  static String toStr(int value) =>
      _TLSEnumHelper.intToString(value, _intToNameMap);
}

// Placeholder for Settings used in filter methods
class TlsSettings {
  // Example properties needed based on  code usage
  final List<int> maxVersion; // e.g., [3, 4] for TLS 1.3
  final List<int> minVersion; // e.g., [3, 3] for TLS 1.2
  final List<String> macNames; // e.g., ['sha256', 'sha384', 'aead']
  final List<String>
      cipherNames; // e.g., ['aes128gcm', 'aes256gcm', 'chacha20-poly1305']
  final List<String>
      keyExchangeNames; // e.g., ['ecdhe_rsa', 'dhe_rsa', 'ecdhe_ecdsa']

  const TlsSettings({
    required this.maxVersion,
    required this.minVersion,
    required this.macNames,
    required this.cipherNames,
    required this.keyExchangeNames,
  });
}

// Placeholder for Certificate Chain used in filter methods
class CertificateChain {
  // Example property assuming a list of certificate objects
  final List<X509Certificate>
      x509List; // Replace X509Certificate with your actual cert class

  const CertificateChain({required this.x509List});
}

// Placeholder for actual Certificate representation
class X509Certificate {
  final String certAlg; // e.g., "rsa", "ecdsa", "rsa-pss", "Ed25519"
  // Add other relevant properties
  const X509Certificate({required this.certAlg});
}

// Assuming AlertDescription enum/class exists from previous translation
// Assuming other constants/enums like HashAlgorithm, SignatureAlgorithm exist

/// Numeric values of ciphersuites and ciphersuite types
class CipherSuite {
  /// Dictionary with string names of the ciphersuites
  static const Map<int, String> ietfNames = {
    // SSLv2 from draft-hickman-netscape-ssl-00.txt
    0x010080: 'SSL_CK_RC4_128_WITH_MD5',
    0x020080: 'SSL_CK_RC4_128_EXPORT40_WITH_MD5',
    0x030080: 'SSL_CK_RC2_128_CBC_WITH_MD5',
    0x040080: 'SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5',
    0x050080: 'SSL_CK_IDEA_128_CBC_WITH_MD5',
    0x060040: 'SSL_CK_DES_64_CBC_WITH_MD5',
    0x0700C0: 'SSL_CK_DES_192_EDE3_CBC_WITH_MD5',

    // RFC 5246 - TLS v1.2 Protocol
    0x0001: 'TLS_RSA_WITH_NULL_MD5',
    0x0002: 'TLS_RSA_WITH_NULL_SHA',
    0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
    0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
    0x000A: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
    0x000D: 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA', // unsupported in many impls
    0x0013: 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA', // unsupported in many impls
    0x0016: 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
    0x0018: 'TLS_DH_ANON_WITH_RC4_128_MD5',
    0x001B: 'TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA',
    0x002F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
    0x0030: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA', // unsupported in many impls
    0x0032: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA', // unsupported in many impls
    0x0033: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
    0x0034: 'TLS_DH_ANON_WITH_AES_128_CBC_SHA',
    0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
    0x0036: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA', // unsupported in many impls
    0x0038: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA', // unsupported in many impls
    0x0039: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
    0x003A: 'TLS_DH_ANON_WITH_AES_256_CBC_SHA',
    0x003B: 'TLS_RSA_WITH_NULL_SHA256',
    0x003C: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
    0x003D: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
    0x003E: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256', // unsupported in many impls
    0x0040: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256', // unsupported in many impls
    0x0067: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
    0x0068: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256', // unsupported in many impls
    0x006A: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256', // unsupported in many impls
    0x006B: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
    0x006C: 'TLS_DH_ANON_WITH_AES_128_CBC_SHA256',
    0x006D: 'TLS_DH_ANON_WITH_AES_256_CBC_SHA256',

    // RFC 5288 - AES-GCM ciphers for TLSv1.2
    0x009C: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
    0x009D: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
    0x009E: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
    0x009F: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
    0x00A2: 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256', // unsupported in many impls
    0x00A3: 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384', // unsupported in many impls
    0x00A4: 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256', // unsupported in many impls
    0x00A5: 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384', // unsupported in many impls
    0x00A6: 'TLS_DH_ANON_WITH_AES_128_GCM_SHA256',
    0x00A7: 'TLS_DH_ANON_WITH_AES_256_GCM_SHA384',

    // RFC 6655 - AES-CCM ciphers for TLSv1.2
    0xC09C: 'TLS_RSA_WITH_AES_128_CCM',
    0xC09D: 'TLS_RSA_WITH_AES_256_CCM',
    0xC09E: 'TLS_DHE_RSA_WITH_AES_128_CCM',
    0xC09F: 'TLS_DHE_RSA_WITH_AES_256_CCM',
    0xC0A0: 'TLS_RSA_WITH_AES_128_CCM_8',
    0xC0A1: 'TLS_RSA_WITH_AES_256_CCM_8',
    0xC0A2: 'TLS_DHE_RSA_WITH_AES_128_CCM_8',
    0xC0A3: 'TLS_DHE_RSA_WITH_AES_256_CCM_8',

    // Weird pseudo-ciphersuite from RFC 5746
    0x00FF: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',

    // TLS 1.3 ciphersuites
    0x1301: 'TLS_AES_128_GCM_SHA256',
    0x1302: 'TLS_AES_256_GCM_SHA384',
    0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
    0x1304: 'TLS_AES_128_CCM_SHA256',
    0x1305: 'TLS_AES_128_CCM_8_SHA256',

    // RFC 7507 - Fallback SCSV
    0x5600: 'TLS_FALLBACK_SCSV',

    // RFC 4492 - ECC Cipher Suites for TLS
    0xC001: 'TLS_ECDH_ECDSA_WITH_NULL_SHA', // unsupported in many impls
    0xC002: 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA', // unsupported in many impls
    0xC003: 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA', // unsupported in many impls
    0xC004: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA', // unsupported in many impls
    0xC005: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA', // unsupported in many impls
    0xC006: 'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
    0xC007: 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
    0xC008: 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
    0xC009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
    0xC00A: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
    0xC00B: 'TLS_ECDH_RSA_WITH_NULL_SHA', // unsupported in many impls
    0xC00C: 'TLS_ECDH_RSA_WITH_RC4_128_SHA', // unsupported in many impls
    0xC00D: 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA', // unsupported in many impls
    0xC00E: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA', // unsupported in many impls
    0xC00F: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA', // unsupported in many impls
    0xC010: 'TLS_ECDHE_RSA_WITH_NULL_SHA',
    0xC011: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
    0xC012: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
    0xC013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    0xC014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    0xC015: 'TLS_ECDH_ANON_WITH_NULL_SHA',
    0xC016: 'TLS_ECDH_ANON_WITH_RC4_128_SHA',
    0xC017: 'TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA',
    0xC018: 'TLS_ECDH_ANON_WITH_AES_128_CBC_SHA',
    0xC019: 'TLS_ECDH_ANON_WITH_AES_256_CBC_SHA',

    // RFC 5054 - SRP
    0xC01A: 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA',
    0xC01B: 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
    0xC01C:
        'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA', // unsupported in many impls
    0xC01D: 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA',
    0xC01E: 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
    0xC01F: 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA', // unsupported in many impls
    0xC020: 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA',
    0xC021: 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
    0xC022: 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA', // unsupported in many impls

    // RFC 5289 - ECC with SHA-256/384 HMAC and AES-GCM
    0xC023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
    0xC024: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
    0xC025:
        'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256', // unsupported in many impls
    0xC026:
        'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384', // unsupported in many impls
    0xC027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
    0xC028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
    0xC029: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256', // unsupported in many impls
    0xC02A: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384', // unsupported in many impls
    0xC02B: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    0xC02C: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    0xC02D:
        'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256', // unsupported in many impls
    0xC02E:
        'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384', // unsupported in many impls
    0xC02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    0xC030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    0xC031: 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256', // unsupported in many impls
    0xC032: 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384', // unsupported in many impls

    // draft-ietf-tls-chacha20-poly1305-00
    0xCCA1: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_draft_00',
    0xCCA2: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_draft_00',
    0xCCA3: 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_draft_00',

    // RFC 7905 - ChaCha20-Poly1305
    0xCCA8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    0xCCA9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    0xCCAA: 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',

    // RFC 7251 - AES-CCM ECC
    0xC0AC: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM',
    0xC0AD: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM',
    0xC0AE: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8',
    0xC0AF: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8',
  };

  // SSLv2 Constants
  static const int sslCkRc4128WithMd5 = 0x010080;
  static const int sslCkRc4128Export40WithMd5 = 0x020080;
  static const int sslCkRc2128CbcWithMd5 = 0x030080;
  static const int sslCkRc2128CbcExport40WithMd5 = 0x040080;
  static const int sslCkIdea128CbcWithMd5 = 0x050080;
  static const int sslCkDes64CbcWithMd5 = 0x060040;
  static const int sslCkDes192Ede3CbcWithMd5 = 0x0700C0;

  /// SSL2 ciphersuites which use RC4 symmetric cipher
  static const List<int> ssl2rc4 = [
    sslCkRc4128WithMd5,
    sslCkRc4128Export40WithMd5,
  ];

  /// SSL2 ciphersuites which use RC2 symmetric cipher
  static const List<int> ssl2rc2 = [
    sslCkRc2128CbcWithMd5,
    sslCkRc2128CbcExport40WithMd5,
  ];

  /// SSL2 ciphersuites which use IDEA symmetric cipher
  static const List<int> ssl2idea = [sslCkIdea128CbcWithMd5];

  /// SSL2 ciphersuites which use (single) DES symmetric cipher
  static const List<int> ssl2des = [sslCkDes64CbcWithMd5];

  /// SSL2 ciphersuites which use 3DES symmetric cipher
  static const List<int> ssl2_3des = [sslCkDes192Ede3CbcWithMd5];

  /// SSL2 ciphersuites which encrypt only part (40 bits) of the key
  static const List<int> ssl2export = [
    sslCkRc4128Export40WithMd5,
    sslCkRc2128CbcExport40WithMd5,
  ];

  /// SSL2 ciphersuties which use 128 bit key
  static const List<int> ssl2_128Key = [
    sslCkRc4128WithMd5,
    sslCkRc4128Export40WithMd5,
    sslCkRc2128CbcWithMd5,
    sslCkRc2128CbcExport40WithMd5,
    sslCkIdea128CbcWithMd5,
  ];

  /// SSL2 ciphersuites which use 64 bit key
  static const List<int> ssl2_64Key = [sslCkDes64CbcWithMd5];

  /// SSL2 ciphersuites which use 192 bit key
  static const List<int> ssl2_192Key = [sslCkDes192Ede3CbcWithMd5];

  // SSLv3 and TLS cipher suite definitions

  // RFC 5246 - TLS v1.2 Protocol
  static const int tlsRsaWithNullMd5 = 0x0001;
  static const int tlsRsaWithNullSha = 0x0002;
  static const int tlsRsaWithRc4128Md5 = 0x0004;
  static const int tlsRsaWithRc4128Sha = 0x0005;
  static const int tlsRsaWith3desEdeCbcSha = 0x000A;
  static const int tlsDhDssWith3desEdeCbcSha = 0x000D;
  static const int tlsDheDssWith3desEdeCbcSha = 0x0013;
  static const int tlsDheRsaWith3desEdeCbcSha = 0x0016;
  static const int tlsDhAnonWithRc4128Md5 = 0x0018;
  static const int tlsDhAnonWith3desEdeCbcSha = 0x001B;
  static const int tlsRsaWithAes128CbcSha = 0x002F;
  static const int tlsDhDssWithAes128CbcSha = 0x0030;
  static const int tlsDheDssWithAes128CbcSha = 0x0032;
  static const int tlsDheRsaWithAes128CbcSha = 0x0033;
  static const int tlsDhAnonWithAes128CbcSha = 0x0034;
  static const int tlsRsaWithAes256CbcSha = 0x0035;
  static const int tlsDhDssWithAes256CbcSha = 0x0036;
  static const int tlsDheDssWithAes256CbcSha = 0x0038;
  static const int tlsDheRsaWithAes256CbcSha = 0x0039;
  static const int tlsDhAnonWithAes256CbcSha = 0x003A;
  static const int tlsRsaWithNullSha256 = 0x003B;
  static const int tlsRsaWithAes128CbcSha256 = 0x003C;
  static const int tlsRsaWithAes256CbcSha256 = 0x003D;
  static const int tlsDhDssWithAes128CbcSha256 = 0x003E;
  static const int tlsDheDssWithAes128CbcSha256 = 0x0040;
  static const int tlsDheRsaWithAes128CbcSha256 = 0x0067;
  static const int tlsDhDssWithAes256CbcSha256 = 0x0068;
  static const int tlsDheDssWithAes256CbcSha256 = 0x006A;
  static const int tlsDheRsaWithAes256CbcSha256 = 0x006B;
  static const int tlsDhAnonWithAes128CbcSha256 = 0x006C;
  static const int tlsDhAnonWithAes256CbcSha256 = 0x006D;

  // RFC 5288 - AES-GCM ciphers for TLSv1.2
  static const int tlsRsaWithAes128GcmSha256 = 0x009C;
  static const int tlsRsaWithAes256GcmSha384 = 0x009D;
  static const int tlsDheRsaWithAes128GcmSha256 = 0x009E;
  static const int tlsDheRsaWithAes256GcmSha384 = 0x009F;
  static const int tlsDheDssWithAes128GcmSha256 = 0x00A2;
  static const int tlsDheDssWithAes256GcmSha384 = 0x00A3;
  static const int tlsDhDssWithAes128GcmSha256 = 0x00A4;
  static const int tlsDhDssWithAes256GcmSha384 = 0x00A5;
  static const int tlsDhAnonWithAes128GcmSha256 = 0x00A6;
  static const int tlsDhAnonWithAes256GcmSha384 = 0x00A7;

  // RFC 6655 - AES-CCM ciphers for TLSv1.2
  static const int tlsRsaWithAes128Ccm = 0xC09C;
  static const int tlsRsaWithAes256Ccm = 0xC09D;
  static const int tlsDheRsaWithAes128Ccm = 0xC09E;
  static const int tlsDheRsaWithAes256Ccm = 0xC09F;
  static const int tlsRsaWithAes128Ccm8 = 0xC0A0;
  static const int tlsRsaWithAes256Ccm8 = 0xC0A1;
  static const int tlsDheRsaWithAes128Ccm8 = 0xC0A2;
  static const int tlsDheRsaWithAes256Ccm8 = 0xC0A3;

  // Weird pseudo-ciphersuite from RFC 5746
  static const int tlsEmptyRenegotiationInfoScsv = 0x00FF;

  // TLS 1.3 ciphersuites
  static const int tlsAes128GcmSha256 = 0x1301;
  static const int tlsAes256GcmSha384 = 0x1302;
  static const int tlsChacha20Poly1305Sha256 = 0x1303;
  static const int tlsAes128CcmSha256 = 0x1304;
  static const int tlsAes128Ccm8Sha256 = 0x1305;

  // RFC 7507 - Fallback SCSV
  static const int tlsFallbackScsv = 0x5600;

  // RFC 4492 - ECC Cipher Suites for TLS
  static const int tlsEcdhEcdsaWithNullSha = 0xC001;
  static const int tlsEcdhEcdsaWithRc4128Sha = 0xC002;
  static const int tlsEcdhEcdsaWith3desEdeCbcSha = 0xC003;
  static const int tlsEcdhEcdsaWithAes128CbcSha = 0xC004;
  static const int tlsEcdhEcdsaWithAes256CbcSha = 0xC005;
  static const int tlsEcdheEcdsaWithNullSha = 0xC006;
  static const int tlsEcdheEcdsaWithRc4128Sha = 0xC007;
  static const int tlsEcdheEcdsaWith3desEdeCbcSha = 0xC008;
  static const int tlsEcdheEcdsaWithAes128CbcSha = 0xC009;
  static const int tlsEcdheEcdsaWithAes256CbcSha = 0xC00A;
  static const int tlsEcdhRsaWithNullSha = 0xC00B;
  static const int tlsEcdhRsaWithRc4128Sha = 0xC00C;
  static const int tlsEcdhRsaWith3desEdeCbcSha = 0xC00D;
  static const int tlsEcdhRsaWithAes128CbcSha = 0xC00E;
  static const int tlsEcdhRsaWithAes256CbcSha = 0xC00F;
  static const int tlsEcdheRsaWithNullSha = 0xC010;
  static const int tlsEcdheRsaWithRc4128Sha = 0xC011;
  static const int tlsEcdheRsaWith3desEdeCbcSha = 0xC012;
  static const int tlsEcdheRsaWithAes128CbcSha = 0xC013;
  static const int tlsEcdheRsaWithAes256CbcSha = 0xC014;
  static const int tlsEcdhAnonWithNullSha = 0xC015;
  static const int tlsEcdhAnonWithRc4128Sha = 0xC016;
  static const int tlsEcdhAnonWith3desEdeCbcSha = 0xC017;
  static const int tlsEcdhAnonWithAes128CbcSha = 0xC018;
  static const int tlsEcdhAnonWithAes256CbcSha = 0xC019;

  // RFC 5054 - SRP
  static const int tlsSrpShaWith3desEdeCbcSha = 0xC01A;
  static const int tlsSrpShaRsaWith3desEdeCbcSha = 0xC01B;
  static const int tlsSrpShaDssWith3desEdeCbcSha = 0xC01C;
  static const int tlsSrpShaWithAes128CbcSha = 0xC01D;
  static const int tlsSrpShaRsaWithAes128CbcSha = 0xC01E;
  static const int tlsSrpShaDssWithAes128CbcSha = 0xC01F;
  static const int tlsSrpShaWithAes256CbcSha = 0xC020;
  static const int tlsSrpShaRsaWithAes256CbcSha = 0xC021;
  static const int tlsSrpShaDssWithAes256CbcSha = 0xC022;

  // RFC 5289 - ECC with SHA-256/384 HMAC and AES-GCM
  static const int tlsEcdheEcdsaWithAes128CbcSha256 = 0xC023;
  static const int tlsEcdheEcdsaWithAes256CbcSha384 = 0xC024;
  static const int tlsEcdhEcdsaWithAes128CbcSha256 = 0xC025;
  static const int tlsEcdhEcdsaWithAes256CbcSha384 = 0xC026;
  static const int tlsEcdheRsaWithAes128CbcSha256 = 0xC027;
  static const int tlsEcdheRsaWithAes256CbcSha384 = 0xC028;
  static const int tlsEcdhRsaWithAes128CbcSha256 = 0xC029;
  static const int tlsEcdhRsaWithAes256CbcSha384 = 0xC02A;
  static const int tlsEcdheEcdsaWithAes128GcmSha256 = 0xC02B;
  static const int tlsEcdheEcdsaWithAes256GcmSha384 = 0xC02C;
  static const int tlsEcdhEcdsaWithAes128GcmSha256 = 0xC02D;
  static const int tlsEcdhEcdsaWithAes256GcmSha384 = 0xC02E;
  static const int tlsEcdheRsaWithAes128GcmSha256 = 0xC02F;
  static const int tlsEcdheRsaWithAes256GcmSha384 = 0xC030;
  static const int tlsEcdhRsaWithAes128GcmSha256 = 0xC031;
  static const int tlsEcdhRsaWithAes256GcmSha384 = 0xC032;

  // draft-ietf-tls-chacha20-poly1305-00
  static const int tlsEcdheRsaWithChacha20Poly1305Draft00 = 0xCCA1;
  static const int tlsEcdheEcdsaWithChacha20Poly1305Draft00 = 0xCCA2;
  static const int tlsDheRsaWithChacha20Poly1305Draft00 = 0xCCA3;

  // RFC 7905 - ChaCha20-Poly1305
  static const int tlsEcdheRsaWithChacha20Poly1305Sha256 = 0xCCA8;
  static const int tlsEcdheEcdsaWithChacha20Poly1305Sha256 = 0xCCA9;
  static const int tlsDheRsaWithChacha20Poly1305Sha256 = 0xCCAA;

  // RFC 7251 - AES-CCM ECC
  static const int tlsEcdheEcdsaWithAes128Ccm = 0xC0AC;
  static const int tlsEcdheEcdsaWithAes256Ccm = 0xC0AD;
  static const int tlsEcdheEcdsaWithAes128Ccm8 = 0xC0AE;
  static const int tlsEcdheEcdsaWithAes256Ccm8 = 0xC0AF;

  // --- Cipher Suite Families ---

  /// 3DES CBC ciphers
  static const List<int> tripleDESSuites = [
    tlsEcdheEcdsaWith3desEdeCbcSha,
    tlsEcdhEcdsaWith3desEdeCbcSha, // unsupported
    tlsEcdhRsaWith3desEdeCbcSha, // unsupported
    tlsEcdheRsaWith3desEdeCbcSha,
    tlsSrpShaWith3desEdeCbcSha,
    tlsSrpShaRsaWith3desEdeCbcSha,
    tlsRsaWith3desEdeCbcSha,
    tlsDheRsaWith3desEdeCbcSha,
    tlsDhAnonWith3desEdeCbcSha,
    tlsEcdhAnonWith3desEdeCbcSha,
    tlsDhDssWith3desEdeCbcSha, // unsupported
    tlsDheDssWith3desEdeCbcSha, // unsupported
    tlsSrpShaDssWith3desEdeCbcSha, // unsupported
  ];

  /// AES-128 CBC ciphers
  static const List<int> aes128Suites = [
    tlsSrpShaWithAes128CbcSha,
    tlsSrpShaRsaWithAes128CbcSha,
    tlsRsaWithAes128CbcSha,
    tlsDheRsaWithAes128CbcSha,
    tlsDhAnonWithAes128CbcSha,
    tlsRsaWithAes128CbcSha256,
    tlsDheRsaWithAes128CbcSha256,
    tlsDhAnonWithAes128CbcSha256,
    tlsEcdheEcdsaWithAes128CbcSha256,
    tlsEcdheEcdsaWithAes128CbcSha,
    tlsEcdhEcdsaWithAes128CbcSha256, // unsupported
    tlsEcdhEcdsaWithAes128CbcSha, // unsupported
    tlsEcdhRsaWithAes128CbcSha256, // unsupported
    tlsEcdhRsaWithAes128CbcSha, // unsupported
    tlsEcdheRsaWithAes128CbcSha,
    tlsEcdheRsaWithAes128CbcSha256,
    tlsEcdhAnonWithAes128CbcSha,
    tlsDhDssWithAes128CbcSha, // unsupported
    tlsDheDssWithAes128CbcSha, // unsupported
    tlsDhDssWithAes128CbcSha256, // unsupported
    tlsDheDssWithAes128CbcSha256, // unsupported
    tlsSrpShaDssWithAes128CbcSha, // unsupported
  ];

  /// AES-256 CBC ciphers
  static const List<int> aes256Suites = [
    tlsSrpShaWithAes256CbcSha,
    tlsSrpShaRsaWithAes256CbcSha,
    tlsRsaWithAes256CbcSha,
    tlsDhAnonWithAes256CbcSha,
    tlsDheRsaWithAes256CbcSha,
    tlsRsaWithAes256CbcSha256,
    tlsDheRsaWithAes256CbcSha256,
    tlsDhAnonWithAes256CbcSha256,
    tlsEcdheEcdsaWithAes256CbcSha384,
    tlsEcdheEcdsaWithAes256CbcSha,
    tlsEcdhEcdsaWithAes256CbcSha384, // unsupported
    tlsEcdhEcdsaWithAes256CbcSha, // unsupported
    tlsEcdhRsaWithAes256CbcSha384, // unsupported
    tlsEcdhRsaWithAes256CbcSha, // unsupported
    tlsEcdheRsaWithAes256CbcSha,
    tlsEcdheRsaWithAes256CbcSha384,
    tlsEcdhAnonWithAes256CbcSha,
    tlsDhDssWithAes256CbcSha, // unsupported
    tlsDheDssWithAes256CbcSha, // unsupported
    tlsDhDssWithAes256CbcSha256, // unsupported
    tlsDheDssWithAes256CbcSha256, // unsupported
    tlsSrpShaDssWithAes256CbcSha, // unsupported
  ];

  /// AES-128 GCM ciphers
  static const List<int> aes128GcmSuites = [
    tlsRsaWithAes128GcmSha256,
    tlsDheRsaWithAes128GcmSha256,
    tlsDhAnonWithAes128GcmSha256,
    tlsEcdheEcdsaWithAes128GcmSha256,
    tlsEcdhEcdsaWithAes128GcmSha256, // unsupported
    tlsEcdhRsaWithAes128GcmSha256, // unsupported
    tlsEcdheRsaWithAes128GcmSha256,
    tlsAes128GcmSha256, // TLS 1.3
    tlsDheDssWithAes128GcmSha256, // unsupported
    tlsDhDssWithAes128GcmSha256, // unsupported
  ];

  /// AES-256-GCM ciphers (implicit SHA384)
  static const List<int> aes256GcmSuites = [
    tlsRsaWithAes256GcmSha384,
    tlsDheRsaWithAes256GcmSha384,
    tlsDhAnonWithAes256GcmSha384,
    tlsEcdheEcdsaWithAes256GcmSha384,
    tlsEcdhEcdsaWithAes256GcmSha384, // unsupported
    tlsEcdhRsaWithAes256GcmSha384, // unsupported
    tlsEcdheRsaWithAes256GcmSha384,
    tlsAes256GcmSha384, // TLS 1.3
    tlsDheDssWithAes256GcmSha384, // unsupported
    tlsDhDssWithAes256GcmSha384, // unsupported
  ];

  /// AES-128 CCM_8 ciphers
  static const List<int> aes128Ccm_8Suites = [
    tlsRsaWithAes128Ccm8,
    tlsDheRsaWithAes128Ccm8,
    tlsEcdheEcdsaWithAes128Ccm8,
    tlsAes128Ccm8Sha256, // TLS 1.3
  ];

  /// AES-128 CCM ciphers
  static const List<int> aes128CcmSuites = [
    tlsRsaWithAes128Ccm,
    tlsDheRsaWithAes128Ccm,
    tlsEcdheEcdsaWithAes128Ccm,
    tlsAes128CcmSha256, // TLS 1.3
  ];

  /// AES-256 CCM_8 ciphers
  static const List<int> aes256Ccm_8Suites = [
    tlsRsaWithAes256Ccm8,
    tlsDheRsaWithAes256Ccm8,
    tlsEcdheEcdsaWithAes256Ccm8,
  ];

  /// AES-256 CCM ciphers
  static const List<int> aes256CcmSuites = [
    tlsRsaWithAes256Ccm,
    tlsDheRsaWithAes256Ccm,
    tlsEcdheEcdsaWithAes256Ccm,
  ];

  /// CHACHA20 cipher, 00'th IETF draft (implicit POLY1305 authenticator)
  static const List<int> chacha20draft00Suites = [
    tlsEcdheRsaWithChacha20Poly1305Draft00,
    tlsEcdheEcdsaWithChacha20Poly1305Draft00,
    tlsDheRsaWithChacha20Poly1305Draft00,
  ];

  /// CHACHA20 cipher (implicit POLY1305 authenticator, SHA256 PRF)
  static const List<int> chacha20Suites = [
    tlsEcdheRsaWithChacha20Poly1305Sha256,
    tlsEcdheEcdsaWithChacha20Poly1305Sha256,
    tlsDheRsaWithChacha20Poly1305Sha256,
    tlsChacha20Poly1305Sha256, // TLS 1.3
  ];

  /// RC4 128 stream cipher (Generally considered insecure)
  static const List<int> rc4Suites = [
    tlsEcdheRsaWithRc4128Sha,
    tlsEcdheEcdsaWithRc4128Sha,
    tlsEcdhEcdsaWithRc4128Sha, // unsupported
    tlsEcdhRsaWithRc4128Sha, // unsupported
    tlsDhAnonWithRc4128Md5,
    tlsRsaWithRc4128Sha,
    tlsRsaWithRc4128Md5,
    tlsEcdhAnonWithRc4128Sha,
  ];

  /// No encryption (Extremely insecure)
  static const List<int> nullSuites = [
    tlsRsaWithNullMd5,
    tlsRsaWithNullSha,
    tlsRsaWithNullSha256,
    tlsEcdheEcdsaWithNullSha,
    tlsEcdhEcdsaWithNullSha, // unsupported
    tlsEcdhRsaWithNullSha, // unsupported
    tlsEcdheRsaWithNullSha,
    tlsEcdhAnonWithNullSha,
  ];

  /// SHA-1 HMAC, protocol default PRF
  static const List<int> shaSuites = [
    tlsSrpShaWith3desEdeCbcSha,
    tlsSrpShaWithAes128CbcSha,
    tlsSrpShaWithAes256CbcSha,
    tlsSrpShaRsaWith3desEdeCbcSha,
    tlsSrpShaRsaWithAes128CbcSha,
    tlsSrpShaRsaWithAes256CbcSha,
    tlsSrpShaDssWith3desEdeCbcSha, // unsupported
    tlsSrpShaDssWithAes128CbcSha, // unsupported
    tlsSrpShaDssWithAes256CbcSha, // unsupported
    tlsRsaWith3desEdeCbcSha,
    tlsRsaWithAes128CbcSha,
    tlsRsaWithAes256CbcSha,
    tlsRsaWithRc4128Sha,
    tlsDheRsaWith3desEdeCbcSha,
    tlsDheRsaWithAes128CbcSha,
    tlsDheRsaWithAes256CbcSha,
    tlsDheDssWith3desEdeCbcSha, // unsupported
    tlsDheDssWithAes128CbcSha, // unsupported
    tlsDheDssWithAes256CbcSha, // unsupported
    tlsDhAnonWithAes128CbcSha,
    tlsDhAnonWithAes256CbcSha,
    tlsDhAnonWith3desEdeCbcSha,
    tlsDhDssWith3desEdeCbcSha, // unsupported
    tlsDhDssWithAes128CbcSha, // unsupported
    tlsDhDssWithAes256CbcSha, // unsupported
    tlsRsaWithNullSha,
    tlsEcdheEcdsaWithAes256CbcSha,
    tlsEcdheEcdsaWithAes128CbcSha,
    tlsEcdheEcdsaWith3desEdeCbcSha,
    tlsEcdheEcdsaWithRc4128Sha,
    tlsEcdheEcdsaWithNullSha,
    tlsEcdhEcdsaWithAes256CbcSha, // unsupported
    tlsEcdhEcdsaWithAes128CbcSha, // unsupported
    tlsEcdhEcdsaWith3desEdeCbcSha, // unsupported
    tlsEcdhEcdsaWithRc4128Sha, // unsupported
    tlsEcdhEcdsaWithNullSha, // unsupported
    tlsEcdhRsaWithAes256CbcSha, // unsupported
    tlsEcdhRsaWithAes128CbcSha, // unsupported
    tlsEcdhRsaWith3desEdeCbcSha, // unsupported
    tlsEcdhRsaWithRc4128Sha, // unsupported
    tlsEcdhRsaWithNullSha, // unsupported
    tlsEcdheRsaWithAes128CbcSha,
    tlsEcdheRsaWithAes256CbcSha,
    tlsEcdheRsaWith3desEdeCbcSha,
    tlsEcdheRsaWithRc4128Sha,
    tlsEcdheRsaWithNullSha,
    tlsEcdhAnonWithAes256CbcSha,
    tlsEcdhAnonWithAes128CbcSha,
    tlsEcdhAnonWith3desEdeCbcSha,
    tlsEcdhAnonWithRc4128Sha,
    tlsEcdhAnonWithNullSha,
  ];

  /// SHA-256 HMAC, SHA-256 PRF
  static const List<int> sha256Suites = [
    tlsRsaWithAes128CbcSha256,
    tlsRsaWithAes256CbcSha256,
    tlsDheRsaWithAes128CbcSha256,
    tlsDheRsaWithAes256CbcSha256,
    tlsRsaWithNullSha256,
    tlsDhAnonWithAes128CbcSha256,
    tlsDhAnonWithAes256CbcSha256,
    tlsEcdheEcdsaWithAes128CbcSha256,
    tlsEcdhEcdsaWithAes128CbcSha256, // unsupported
    tlsEcdhRsaWithAes128CbcSha256, // unsupported
    tlsEcdheRsaWithAes128CbcSha256,
    // TLS 1.3 suites using SHA256 implicitly are handled separately
  ];

  /// SHA-384 HMAC, SHA-384 PRF
  static const List<int> sha384Suites = [
    tlsEcdheEcdsaWithAes256CbcSha384,
    tlsEcdhEcdsaWithAes256CbcSha384, // unsupported
    tlsEcdhRsaWithAes256CbcSha384, // unsupported
    tlsEcdheRsaWithAes256CbcSha384,
    tlsDheDssWithAes256GcmSha384, // unsupported (also GCM)
    tlsDhDssWithAes256GcmSha384, // unsupported (also GCM)
    // GCM suites using SHA384 are handled separately (in aes256GcmSuites)
  ];

  /// stream cipher construction (RC4, NULL)
  static const List<int> streamSuites = [...rc4Suites, ...nullSuites];

  /// AEAD integrity, any PRF (GCM, CCM, ChaCha20)
  static const List<int> aeadSuites = [
    ...aes128GcmSuites,
    ...aes256GcmSuites,
    ...aes128CcmSuites,
    ...aes128Ccm_8Suites,
    ...aes256CcmSuites,
    ...aes256Ccm_8Suites,
    ...chacha20Suites,
    ...chacha20draft00Suites,
  ];

  /// any with SHA384 PRF (CBC-SHA384 and GCM-SHA384)
  static const List<int> sha384PrfSuites = [
    ...sha384Suites,
    ...aes256GcmSuites,
  ];

  /// MD-5 HMAC, protocol default PRF (Insecure)
  static const List<int> md5Suites = [
    tlsDhAnonWithRc4128Md5,
    tlsRsaWithRc4128Md5,
    tlsRsaWithNullMd5,
  ];

  /// SSL3, TLS1.0, TLS1.1 compatible ciphers
  static const List<int> ssl3Suites = [
    ...shaSuites,
    ...md5Suites,
  ];

  // --- TLS 1.3 Handling ---
  /// TLS1.3 specific ciphersuites
  static const List<int> tls13Suites = [
    tlsAes128GcmSha256,
    tlsAes256GcmSha384,
    tlsChacha20Poly1305Sha256,
    tlsAes128CcmSha256,
    tlsAes128Ccm8Sha256,
  ];

  // Generate TLS 1.2 specific suites by removing TLS 1.3 ones from combined lists
  static final Set<int> _tls12OnlySet = {
    ...sha256Suites,
    ...sha384Suites,
    ...aeadSuites,
  }..removeAll(tls13Suites);

  /// TLS1.2 specific ciphersuites (excluding those also in TLS 1.3)
  static final List<int> tls12Suites = List.unmodifiable(_tls12OnlySet);

  // Generate SHA256 PRF suites for TLS 1.2 by removing SHA384 PRF ones
  static final Set<int> _sha256PrfOnlySet = Set<int>.from(tls12Suites)
    ..removeAll(sha384PrfSuites); // sha384PrfSuites already excludes TLS 1.3

  /// any that will end up using SHA256 PRF in TLS 1.2 or later (excluding SHA384 PRF)
  static final List<int> sha256PrfSuites = List.unmodifiable(_sha256PrfOnlySet);

  /// Return a copy of suites without ciphers incompatible with version range.
  /// Versions are represented as (major, minor) records, e.g., (3, 3) for TLS 1.2.
  static List<int> filterForVersion(
      List<int> suites, (int, int) minVersion, (int, int) maxVersion) {
    final includeSuites = <int>{};
    // Compare versions lexicographically
    bool isGreaterOrEqual((int, int) v1, (int, int) v2) =>
        v1.$1 > v2.$1 || (v1.$1 == v2.$1 && v1.$2 >= v2.$2);

    if (isGreaterOrEqual(minVersion, (3, 0)) &&
        isGreaterOrEqual((3, 3), minVersion)) {
      includeSuites.addAll(CipherSuite.ssl3Suites);
    }
    if (isGreaterOrEqual(maxVersion, (3, 3)) &&
        isGreaterOrEqual((3, 3), minVersion)) {
      includeSuites.addAll(CipherSuite.tls12Suites);
    }
    if (isGreaterOrEqual(maxVersion, (3, 4))) {
      // Assuming (3, 4) is TLS 1.3
      includeSuites.addAll(CipherSuite.tls13Suites);
    }
    return suites.where((s) => includeSuites.contains(s)).toList();
  }

  /// Return a copy of suites without ciphers incompatible with the cert.
  /// NOTE: `certChain` is dynamic here. Replace with actual type if known.
  /// Expects structure like `certChain.x509List[0].certAlg`.
  static List<int> filterForCertificate(List<int> suites, dynamic certChain) {
    final includeSuites = <int>{};
    includeSuites
        .addAll(CipherSuite.tls13Suites); // TLS 1.3 suites work with RSA/ECDSA

    if (certChain != null &&
        certChain.x509List != null &&
        certChain.x509List.isNotEmpty) {
      final String certAlg =
          certChain.x509List[0].certAlg ?? ''; // Get algorithm name

      if (certAlg == "rsa" || certAlg == "rsa-pss") {
        includeSuites.addAll(CipherSuite.certAllSuites);
      }
      if (certAlg == "rsa-pss") {
        // suites in which RSA encryption is used can't be used with rsa-pss
        final rsaEncryptionOnly = Set<int>.from(CipherSuite.certSuites);
        includeSuites.removeAll(rsaEncryptionOnly);
      }
      if (certAlg == "ecdsa" || certAlg == "Ed25519" || certAlg == "Ed448") {
        includeSuites.addAll(CipherSuite.ecdheEcdsaSuites);
      }
      if (certAlg == "dsa") {
        includeSuites.addAll(CipherSuite.dheDsaSuites);
      }
    } else {
      // No certificate means anonymous or SRP
      includeSuites.addAll(CipherSuite.srpSuites);
      includeSuites.addAll(CipherSuite.anonSuites);
      includeSuites.addAll(CipherSuite.ecdhAnonSuites);
    }
    return suites.where((s) => includeSuites.contains(s)).toList();
  }

  /// Return a copy of suites without ciphers incompatible with the
  /// specified prfs ('sha256' or 'sha384'). Only relevant for TLS 1.2.
  static List<int> filterForPrfs(List<int> suites, List<String?> prfs) {
    final includeSuites = <int>{};
    final Set<String> actualPrfs = Set<String>.from(prfs.whereType<String>());

    // Default PRF for TLS < 1.2 is usually SHA1-based, but for TLS 1.2
    // the PRF is determined by the suite. 'null' might imply default/legacy.
    if (prfs.contains(null)) {
      actualPrfs.add("sha256"); // Assume default maps to sha256 for filtering
    }

    if (actualPrfs.contains("sha256")) {
      includeSuites.addAll(CipherSuite.sha256PrfSuites);
      // Also include TLS 1.3 suites implicitly using SHA256
      includeSuites.addAll([
        tlsAes128GcmSha256,
        tlsChacha20Poly1305Sha256,
        tlsAes128CcmSha256,
        tlsAes128Ccm8Sha256
      ]);
    }
    if (actualPrfs.contains("sha384")) {
      includeSuites.addAll(CipherSuite.sha384PrfSuites);
      // Also include TLS 1.3 suites implicitly using SHA384
      includeSuites.add(tlsAes256GcmSha384);
    }

    // For suites compatible with TLS < 1.2, PRF isn't explicitly SHA256/384
    // Include them if *any* PRF filtering is happening? Or only if specific legacy PRF is requested?
    // The original  doesn't seem to filter these out based on sha256/sha384 PRF request.
    // Let's include ssl3Suites regardless of the PRF filter for simplicity matching  intent.
    includeSuites.addAll(CipherSuite.ssl3Suites);

    return suites.where((s) => includeSuites.contains(s)).toList();
  }

  /// Internal helper to filter suites based on settings.
  /// NOTE: `settings` is dynamic here. Replace with actual Settings type.
  /// Expects settings with properties like macNames, cipherNames, keyExchangeNames, maxVersion.
  /// Version is a (major, minor) record, e.g., (3, 3) for TLS 1.2.
  static List<int> _filterSuites(
      List<int> suites, dynamic settings, (int, int)? version) {
    version ??= settings.maxVersion as (
      int,
      int
    )?; // Use settings.maxVersion if version is null
    final effectiveVersion =
        version ?? (3, 3); // Default to TLS 1.2 if still null

    bool isGreaterOrEqual((int, int) v1, (int, int) v2) =>
        v1.$1 > v2.$1 || (v1.$1 == v2.$1 && v1.$2 >= v2.$2);

    final macNames = Set<String>.from(settings.macNames as List? ?? []);
    final cipherNames = Set<String>.from(settings.cipherNames as List? ?? []);
    final keyExchangeNames =
        Set<String>.from(settings.keyExchangeNames as List? ?? []);

    final macSuites = <int>{};
    if (macNames.contains("sha")) macSuites.addAll(CipherSuite.shaSuites);
    if (macNames.contains("sha256") &&
        isGreaterOrEqual(effectiveVersion, (3, 3)))
      macSuites.addAll(CipherSuite.sha256Suites);
    if (macNames.contains("sha384") &&
        isGreaterOrEqual(effectiveVersion, (3, 3)))
      macSuites.addAll(CipherSuite.sha384Suites);
    if (macNames.contains("md5")) macSuites.addAll(CipherSuite.md5Suites);
    if (macNames.contains("aead") && isGreaterOrEqual(effectiveVersion, (3, 3)))
      macSuites.addAll(CipherSuite.aeadSuites);
    // TLS 1.3 suites are implicitly AEAD
    if (isGreaterOrEqual(effectiveVersion, (3, 4)))
      macSuites.addAll(CipherSuite.tls13Suites);

    final cipherSuites = <int>{};
    if (cipherNames.contains("chacha20-poly1305") &&
        isGreaterOrEqual(effectiveVersion, (3, 3)))
      cipherSuites.addAll(CipherSuite.chacha20Suites);
    if (cipherNames.contains("chacha20-poly1305_draft00") &&
        isGreaterOrEqual(effectiveVersion, (3, 3)))
      cipherSuites.addAll(CipherSuite.chacha20draft00Suites);
    if (cipherNames.contains("aes128gcm") &&
        isGreaterOrEqual(effectiveVersion, (3, 3)))
      cipherSuites.addAll(CipherSuite.aes128GcmSuites);
    if (cipherNames.contains("aes256gcm") &&
        isGreaterOrEqual(effectiveVersion, (3, 3)))
      cipherSuites.addAll(CipherSuite.aes256GcmSuites);
    if (cipherNames.contains("aes128ccm") &&
        isGreaterOrEqual(effectiveVersion, (3, 3)))
      cipherSuites.addAll(CipherSuite.aes128CcmSuites);
    if (cipherNames.contains("aes128ccm_8") &&
        isGreaterOrEqual(effectiveVersion, (3, 3)))
      cipherSuites.addAll(CipherSuite.aes128Ccm_8Suites);
    if (cipherNames.contains("aes256ccm") &&
        isGreaterOrEqual(effectiveVersion, (3, 3)))
      cipherSuites.addAll(CipherSuite.aes256CcmSuites);
    if (cipherNames.contains("aes256ccm_8") &&
        isGreaterOrEqual(effectiveVersion, (3, 3)))
      cipherSuites.addAll(CipherSuite.aes256Ccm_8Suites);
    if (cipherNames.contains("aes128"))
      cipherSuites.addAll(CipherSuite.aes128Suites);
    if (cipherNames.contains("aes256"))
      cipherSuites.addAll(CipherSuite.aes256Suites);
    if (cipherNames.contains("3des"))
      cipherSuites.addAll(CipherSuite.tripleDESSuites);
    if (cipherNames.contains("rc4")) cipherSuites.addAll(CipherSuite.rc4Suites);
    if (cipherNames.contains("null"))
      cipherSuites.addAll(CipherSuite.nullSuites);
    // TLS 1.3 suites are implicitly AEAD
    if (isGreaterOrEqual(effectiveVersion, (3, 4)))
      cipherSuites.addAll(CipherSuite.tls13Suites);

    final keyExchangeSuites = <int>{};
    if (isGreaterOrEqual(effectiveVersion, (3, 4))) {
      // TLS 1.3
      keyExchangeSuites.addAll(CipherSuite.tls13Suites);
    }
    if (keyExchangeNames.contains("rsa"))
      keyExchangeSuites.addAll(CipherSuite.certSuites);
    if (keyExchangeNames.contains("dhe_rsa"))
      keyExchangeSuites.addAll(CipherSuite.dheCertSuites);
    if (keyExchangeNames.contains("dhe_dsa"))
      keyExchangeSuites.addAll(CipherSuite.dheDsaSuites);
    if (keyExchangeNames.contains("ecdhe_rsa"))
      keyExchangeSuites.addAll(CipherSuite.ecdheCertSuites);
    if (keyExchangeNames.contains("ecdhe_ecdsa"))
      keyExchangeSuites.addAll(CipherSuite.ecdheEcdsaSuites);
    if (keyExchangeNames.contains("srp_sha"))
      keyExchangeSuites.addAll(CipherSuite.srpSuites);
    if (keyExchangeNames.contains("srp_sha_rsa"))
      keyExchangeSuites.addAll(CipherSuite.srpCertSuites);
    if (keyExchangeNames.contains("dh_anon"))
      keyExchangeSuites.addAll(CipherSuite.anonSuites);
    if (keyExchangeNames.contains("ecdh_anon"))
      keyExchangeSuites.addAll(CipherSuite.ecdhAnonSuites);

    return suites
        .where((s) =>
            macSuites.contains(s) &&
            cipherSuites.contains(s) &&
            keyExchangeSuites.contains(s))
        .toList();
  }

  /// Return cipher suites that are TLS 1.3 specific.
  /// NOTE: `settings` is dynamic. Replace with actual type.
  static List<int> getTLS13Suites(dynamic settings, [(int, int)? version]) {
    // Ensure version passed is at least TLS 1.3, otherwise result is empty
    final effectiveVersion =
        version ?? settings.maxVersion as (int, int)? ?? (3, 4);
    bool isGreaterOrEqual((int, int) v1, (int, int) v2) =>
        v1.$1 > v2.$1 || (v1.$1 == v2.$1 && v1.$2 >= v2.$2);
    if (!isGreaterOrEqual(effectiveVersion, (3, 4))) {
      return [];
    }
    return _filterSuites(CipherSuite.tls13Suites, settings, effectiveVersion);
  }

  /// SRP key exchange, no certificate base authentication
  static const List<int> srpSuites = [
    tlsSrpShaWithAes256CbcSha,
    tlsSrpShaWithAes128CbcSha,
    tlsSrpShaWith3desEdeCbcSha,
  ];

  /// Return SRP cipher suites matching settings
  /// NOTE: `settings` is dynamic. Replace with actual type.
  static List<int> getSrpSuites(dynamic settings, [(int, int)? version]) {
    return _filterSuites(CipherSuite.srpSuites, settings, version);
  }

  /// SRP key exchange, RSA authentication
  static const List<int> srpCertSuites = [
    tlsSrpShaRsaWithAes256CbcSha,
    tlsSrpShaRsaWithAes128CbcSha,
    tlsSrpShaRsaWith3desEdeCbcSha,
  ];

  /// Return SRP cipher suites that use server certificates (RSA)
  /// NOTE: `settings` is dynamic. Replace with actual type.
  static List<int> getSrpCertSuites(dynamic settings, [(int, int)? version]) {
    return _filterSuites(CipherSuite.srpCertSuites, settings, version);
  }

  /// SRP key exchange, DSA authentication
  static const List<int> srpDsaSuites = [
    tlsSrpShaDssWith3desEdeCbcSha, // unsupported
    tlsSrpShaDssWithAes128CbcSha, // unsupported
    tlsSrpShaDssWithAes256CbcSha, // unsupported
  ];

  /// Return SRP DSA cipher suites that use server certificates
  /// NOTE: `settings` is dynamic. Replace with actual type.
  static List<int> getSrpDsaSuites(dynamic settings, [(int, int)? version]) {
    // Since all base suites are marked unsupported, filtering might always return empty.
    // Kept for structural parity.
    return _filterSuites(CipherSuite.srpDsaSuites, settings, version);
  }

  /// All that use SRP key exchange
  static const List<int> srpAllSuites = [
    ...srpSuites,
    ...srpCertSuites,
    ...srpDsaSuites
  ];

  /// Return all SRP cipher suites matching settings
  /// NOTE: `settings` is dynamic. Replace with actual type.
  static List<int> getSrpAllSuites(dynamic settings, [(int, int)? version]) {
    return _filterSuites(CipherSuite.srpAllSuites, settings, version);
  }

  /// RSA key exchange, RSA authentication
  static const List<int> certSuites = [
    tlsRsaWithAes256GcmSha384,
    tlsRsaWithAes128GcmSha256,
    tlsRsaWithAes256Ccm,
    tlsRsaWithAes128Ccm,
    tlsRsaWithAes256CbcSha256,
    tlsRsaWithAes128CbcSha256,
    tlsRsaWithAes256CbcSha,
    tlsRsaWithAes128CbcSha,
    tlsRsaWithAes256Ccm8,
    tlsRsaWithAes128Ccm8,
    tlsRsaWith3desEdeCbcSha,
    tlsRsaWithRc4128Sha,
    tlsRsaWithRc4128Md5,
    tlsRsaWithNullMd5,
    tlsRsaWithNullSha,
    tlsRsaWithNullSha256,
  ];

  /// Return ciphers with RSA key exchange matching settings
  /// NOTE: `settings` is dynamic. Replace with actual type.
  static List<int> getCertSuites(dynamic settings, [(int, int)? version]) {
    return _filterSuites(CipherSuite.certSuites, settings, version);
  }

  /// FFDHE key exchange, RSA authentication
  static const List<int> dheCertSuites = [
    tlsDheRsaWithChacha20Poly1305Sha256,
    tlsDheRsaWithChacha20Poly1305Draft00,
    tlsDheRsaWithAes256GcmSha384,
    tlsDheRsaWithAes128GcmSha256,
    tlsDheRsaWithAes256Ccm,
    tlsDheRsaWithAes128Ccm,
    tlsDheRsaWithAes256CbcSha256,
    tlsDheRsaWithAes128CbcSha256,
    tlsDheRsaWithAes256CbcSha,
    tlsDheRsaWithAes128CbcSha,
    tlsDheRsaWithAes256Ccm8,
    tlsDheRsaWithAes128Ccm8,
    tlsDheRsaWith3desEdeCbcSha,
  ];

  /// Provide authenticated DHE ciphersuites matching settings
  /// NOTE: `settings` is dynamic. Replace with actual type.
  static List<int> getDheCertSuites(dynamic settings, [(int, int)? version]) {
    return _filterSuites(CipherSuite.dheCertSuites, settings, version);
  }

  /// ECDHE key exchange, RSA authentication
  static const List<int> ecdheCertSuites = [
    tlsEcdheRsaWithChacha20Poly1305Sha256,
    tlsEcdheRsaWithChacha20Poly1305Draft00,
    tlsEcdheRsaWithAes256GcmSha384,
    tlsEcdheRsaWithAes128GcmSha256,
    tlsEcdheRsaWithAes256CbcSha384,
    tlsEcdheRsaWithAes128CbcSha256,
    tlsEcdheRsaWithAes256CbcSha,
    tlsEcdheRsaWithAes128CbcSha,
    tlsEcdheRsaWith3desEdeCbcSha,
    tlsEcdheRsaWithRc4128Sha,
    tlsEcdheRsaWithNullSha,
  ];

  /// Provide authenticated ECDHE_RSA ciphersuites matching settings
  /// NOTE: `settings` is dynamic. Replace with actual type.
  static List<int> getEcdheCertSuites(dynamic settings, [(int, int)? version]) {
    return _filterSuites(CipherSuite.ecdheCertSuites, settings, version);
  }

  /// All RSA authentication (RSA kx, DHE_RSA, ECDHE_RSA, SRP_RSA)
  static const List<int> certAllSuites = [
    ...srpCertSuites,
    ...certSuites,
    ...dheCertSuites,
    ...ecdheCertSuites,
  ];

  /// ECDHE key exchange, ECDSA authentication
  static const List<int> ecdheEcdsaSuites = [
    tlsEcdheEcdsaWithChacha20Poly1305Sha256,
    tlsEcdheEcdsaWithChacha20Poly1305Draft00,
    tlsEcdheEcdsaWithAes256GcmSha384,
    tlsEcdheEcdsaWithAes128GcmSha256,
    tlsEcdheEcdsaWithAes256Ccm,
    tlsEcdheEcdsaWithAes128Ccm,
    tlsEcdheEcdsaWithAes256CbcSha384,
    tlsEcdheEcdsaWithAes128CbcSha256,
    tlsEcdheEcdsaWithAes256CbcSha,
    tlsEcdheEcdsaWithAes128CbcSha,
    tlsEcdheEcdsaWith3desEdeCbcSha,
    tlsEcdheEcdsaWithAes256Ccm8,
    tlsEcdheEcdsaWithAes128Ccm8,
    tlsEcdheEcdsaWithRc4128Sha,
    tlsEcdheEcdsaWithNullSha,
  ];

  /// Provide ECDSA authenticated ciphersuites matching settings
  /// NOTE: `settings` is dynamic. Replace with actual type.
  static List<int> getEcdsaSuites(dynamic settings, [(int, int)? version]) {
    return _filterSuites(CipherSuite.ecdheEcdsaSuites, settings, version);
  }

  /// DHE key exchange, DSA authentication
  static const List<int> dheDsaSuites = [
    tlsDheDssWithAes256GcmSha384, // unsupported
    tlsDheDssWithAes128GcmSha256, // unsupported
    tlsDheDssWithAes256CbcSha256, // unsupported
    tlsDheDssWithAes128CbcSha256, // unsupported
    tlsDheDssWithAes256CbcSha, // unsupported
    tlsDheDssWithAes128CbcSha, // unsupported
    tlsDheDssWith3desEdeCbcSha, // unsupported
  ];

  /// Provide DSA authenticated ciphersuites matching settings
  /// NOTE: `settings` is dynamic. Replace with actual type.
  static List<int> getDheDsaSuites(dynamic settings, [(int, int)? version]) {
    // Since all base suites are marked unsupported, filtering might always return empty.
    // Kept for structural parity.
    return _filterSuites(CipherSuite.dheDsaSuites, settings, version);
  }

  /// anon FFDHE key exchange
  static const List<int> anonSuites = [
    tlsDhAnonWithAes256GcmSha384,
    tlsDhAnonWithAes128GcmSha256,
    tlsDhAnonWithAes256CbcSha256,
    tlsDhAnonWithAes256CbcSha,
    tlsDhAnonWithAes128CbcSha256,
    tlsDhAnonWithAes128CbcSha,
    tlsDhAnonWith3desEdeCbcSha,
    tlsDhAnonWithRc4128Md5,
  ];

  /// Provide anonymous DH ciphersuites matching settings
  /// NOTE: `settings` is dynamic. Replace with actual type.
  static List<int> getAnonSuites(dynamic settings, [(int, int)? version]) {
    return _filterSuites(CipherSuite.anonSuites, settings, version);
  }

  /// All FFDHE suites (Authenticated RSA/DSA + Anonymous)
  static const List<int> dhAllSuites = [
    ...dheCertSuites,
    ...anonSuites,
    ...dheDsaSuites,
  ];

  /// anon ECDHE key exchange
  static const List<int> ecdhAnonSuites = [
    tlsEcdhAnonWithAes256CbcSha,
    tlsEcdhAnonWithAes128CbcSha,
    tlsEcdhAnonWith3desEdeCbcSha,
    tlsEcdhAnonWithRc4128Sha,
    tlsEcdhAnonWithNullSha,
  ];

  /// Provide anonymous ECDH ciphersuites matching settings
  /// NOTE: `settings` is dynamic. Replace with actual type.
  static List<int> getEcdhAnonSuites(dynamic settings, [(int, int)? version]) {
    return _filterSuites(CipherSuite.ecdhAnonSuites, settings, version);
  }

  /// all ciphersuites which use ephemeral ECDH key exchange
  static const List<int> ecdhAllSuites = [
    ...ecdheEcdsaSuites,
    ...ecdheCertSuites,
    ...ecdhAnonSuites,
  ];

  /// Return the canonical name of the cipher whose number is provided.
  static String? canonicalCipherName(int ciphersuite) {
    if (CipherSuite.aes128GcmSuites.contains(ciphersuite)) return "aes128gcm";
    if (CipherSuite.aes256GcmSuites.contains(ciphersuite)) return "aes256gcm";
    if (CipherSuite.aes128Ccm_8Suites.contains(ciphersuite))
      return "aes128ccm_8";
    if (CipherSuite.aes128CcmSuites.contains(ciphersuite)) return "aes128ccm";
    if (CipherSuite.aes256CcmSuites.contains(ciphersuite)) return "aes256ccm";
    if (CipherSuite.aes256Ccm_8Suites.contains(ciphersuite))
      return "aes256ccm_8";
    if (CipherSuite.aes128Suites.contains(ciphersuite)) return "aes128";
    if (CipherSuite.aes256Suites.contains(ciphersuite)) return "aes256";
    if (CipherSuite.rc4Suites.contains(ciphersuite)) return "rc4";
    if (CipherSuite.tripleDESSuites.contains(ciphersuite)) return "3des";
    if (CipherSuite.nullSuites.contains(ciphersuite)) return "null";
    if (CipherSuite.chacha20draft00Suites.contains(ciphersuite))
      return "chacha20-poly1305_draft00";
    if (CipherSuite.chacha20Suites.contains(ciphersuite))
      return "chacha20-poly1305";

    return null; // Not found in defined families
  }

  /// Return the canonical name of the MAC whose number is provided.
  /// Note: Returns null for AEAD suites where MAC is integrated.
  static String? canonicalMacName(int ciphersuite) {
    if (CipherSuite.sha384Suites.contains(ciphersuite)) return "sha384";
    if (CipherSuite.sha256Suites.contains(ciphersuite)) return "sha256";
    if (CipherSuite.shaSuites.contains(ciphersuite)) return "sha";
    if (CipherSuite.md5Suites.contains(ciphersuite)) return "md5";
    // AEAD suites don't have a separate MAC name in this context
    if (CipherSuite.aeadSuites.contains(ciphersuite))
      return null; // Or "aead"?  returns None.

    return null; // Not found or AEAD
  }
}

// The following faults are induced as part of testing.
// Assumes AlertDescription enum/class exists.
class Fault {
  static const int badUsername = 101;
  static const int badPassword = 102;
  static const int badA = 103;
  static const List<int> clientSrpFaults = [badUsername, badPassword, badA];

  static const int badVerifyMessage = 601;
  static const List<int> clientCertFaults = [badVerifyMessage];

  static const int badPremasterPadding = 501;
  static const int shortPremasterSecret = 502;
  static const List<int> clientNoAuthFaults = [
    badPremasterPadding,
    shortPremasterSecret
  ];

  static const int badB = 201;
  static const List<int> serverFaults = [badB]; // Only one listed in 

  static const int badFinished = 300;
  static const int badMAC = 301;
  static const int badPadding = 302;
  static const List<int> genericFaults = [badFinished, badMAC, badPadding];

  /// Describes the allowed alerts that may be triggered by these faults.
  /// Requires AlertDescription constants to be defined elsewhere.
  static final Map<int, List<int>> faultAlerts = {
    badUsername: [
      AlertDescription.unknownPskIdentity,
      AlertDescription.badRecordMac
    ],
    badPassword: [AlertDescription.badRecordMac],
    badA: [AlertDescription.illegalParameter],
    badPremasterPadding: [AlertDescription.badRecordMac],
    shortPremasterSecret: [AlertDescription.badRecordMac],
    badVerifyMessage: [AlertDescription.decryptError],
    badFinished: [AlertDescription.decryptError],
    badMAC: [AlertDescription.badRecordMac],
    badPadding: [AlertDescription.badRecordMac],
    // Note: badB is not mapped in the  code's faultAlerts dictionary
  };

  /// Human-readable names for the faults.
  static const Map<int, String> faultNames = {
    badUsername: "bad username",
    badPassword: "bad password",
    badA: "bad A",
    badPremasterPadding: "bad premaster padding",
    shortPremasterSecret: "short premaster secret",
    badVerifyMessage: "bad verify message",
    badFinished: "bad finished message",
    badMAC: "bad MAC",
    badPadding: "bad padding",
    // Note: badB is not mapped in the  code's faultNames dictionary
  };
}
