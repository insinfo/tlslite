import 'dart:ffi';
import 'package:ffi/ffi.dart';

import 'generated/ffi.dart';
import 'openssl_loader.dart';

/// Constantes – os valores abaixo devem corresponder aos valores definidos na sua binding.
const int OSSL_PARAM_UNSIGNED_INTEGER = 1;
const int EVP_PKEY_KEYPAIR = 1; // Seleção para criação de par de chaves
const int BIO_CTRL_INFO = 3;
const int EVP_PKEY_RSA = 6;

/// Funções auxiliares para construir os parâmetros OSSL_PARAM para chave RSA.
Pointer<OSSL_PARAM> constructParams(int bits, int pubexp) {
  // Alocamos um array com 3 parâmetros: "rsa_bits", "rsa_pubexp" e o marcador de fim.
  const paramCount = 3;
  final params = calloc<OSSL_PARAM>(paramCount);

  // Primeiro parâmetro: "rsa_bits"
  final keyBits = "rsa_bits".toNativeUtf8();
  params[0].key = keyBits.cast<Char>();
  params[0].data_type = OSSL_PARAM_UNSIGNED_INTEGER;
  // Aloca memória para armazenar o valor dos bits (uint32)
  final bitsPtr = calloc<Uint32>();
  bitsPtr.value = bits;
  params[0].data = bitsPtr.cast<Void>();
  params[0].data_size = sizeOf<Uint32>();

  // Segundo parâmetro: "rsa_pubexp"
  final keyPubexp = "rsa_pubexp".toNativeUtf8();
  params[1].key = keyPubexp.cast<Char>();
  params[1].data_type = OSSL_PARAM_UNSIGNED_INTEGER;
  final pubexpPtr = calloc<Uint32>();
  pubexpPtr.value = pubexp;
  params[1].data = pubexpPtr.cast<Void>();
  params[1].data_size = sizeOf<Uint32>();

  // Terceiro parâmetro: marca o fim (key == nullptr)
  params[2].key = nullptr;

  return params;
}

void freeParams(Pointer<OSSL_PARAM> params) {
  // Libera as strings e os dados alocados para os parâmetros
  if (params[0].key != nullptr) {
    calloc.free(params[0].key);
    calloc.free(params[0].data);
  }
  if (params[1].key != nullptr) {
    calloc.free(params[1].key);
    calloc.free(params[1].data);
  }
  calloc.free(params);
}

/// Classe auxiliar para criar certificado autoassinado usando as novas APIs.
class X509CertificateBuilder {
  final OpenSsl libcrypt;
  final bool _supportsFromData;
  X509CertificateBuilder(this.libcrypt, {bool supportsFromDataKeygen = true})
      : _supportsFromData = supportsFromDataKeygen;

  factory X509CertificateBuilder.withSystemLibraries() {
    final bindings = OpenSslBindings.load();
    return X509CertificateBuilder(
      bindings.crypto,
      supportsFromDataKeygen: bindings.supportsFromDataKeygen,
    );
  }

  /// Gera um par de chaves RSA e retorna um ponteiro para EVP_PKEY utilizando EVP_PKEY_fromdata.
  Pointer<EVP_PKEY> generateKeyPair() {
    if (_supportsFromData) {
      try {
        return _generateViaFromData();
      } catch (_) {
        // Fallback when the loaded OpenSSL advertises fromdata symbols but
        // rejects the parameters at runtime.
      }
    }
    return _generateLegacyRsa();
  }

  Pointer<EVP_PKEY> _generateViaFromData() {
    final rsaName = 'RSA'.toNativeUtf8();
    Pointer<EVP_PKEY_CTX> ctx;
    try {
      ctx = libcrypt.EVP_PKEY_CTX_new_from_name(
        nullptr.cast<OSSL_LIB_CTX>(),
        rsaName.cast(),
        nullptr.cast<Char>(),
      );
    } finally {
      calloc.free(rsaName);
    }

    if (ctx == nullptr) {
      ctx = libcrypt.EVP_PKEY_CTX_new_id(
        EVP_PKEY_RSA,
        nullptr.cast<ENGINE>(),
      );
    }

    if (ctx == nullptr) {
      throw Exception('Falha ao criar EVP_PKEY_CTX');
    }

    if (libcrypt.EVP_PKEY_fromdata_init(ctx) != 1) {
      libcrypt.EVP_PKEY_CTX_free(ctx);
      throw Exception('Falha ao inicializar EVP_PKEY_fromdata');
    }

    final params = constructParams(2048, 65537);
    final pkeyPtr = calloc<Pointer<EVP_PKEY>>();
    final ret =
        libcrypt.EVP_PKEY_fromdata(ctx, pkeyPtr, EVP_PKEY_KEYPAIR, params);
    freeParams(params);
    libcrypt.EVP_PKEY_CTX_free(ctx);

    if (ret != 1 || pkeyPtr.value == nullptr) {
      calloc.free(pkeyPtr);
      throw Exception('EVP_PKEY_fromdata falhou');
    }

    final pkey = pkeyPtr.value;
    calloc.free(pkeyPtr);
    return pkey;
  }

  Pointer<EVP_PKEY> _generateLegacyRsa() {
    final rsa = libcrypt.RSA_new();
    if (rsa == nullptr) {
      throw Exception('Falha ao criar RSA');
    }
    final bn = libcrypt.BN_new();
    if (bn == nullptr) {
      libcrypt.RSA_free(rsa);
      throw Exception('Falha ao criar BIGNUM');
    }
    const exponent = 65537;
    if (libcrypt.BN_set_word(bn, exponent) != 1) {
      libcrypt.BN_free(bn);
      libcrypt.RSA_free(rsa);
      throw Exception('Falha ao definir expoente RSA');
    }
    final generated = libcrypt.RSA_generate_key_ex(rsa, 2048, bn, nullptr);
    libcrypt.BN_free(bn);
    if (generated != 1) {
      libcrypt.RSA_free(rsa);
      throw Exception('RSA_generate_key_ex falhou');
    }

    final pkey = libcrypt.EVP_PKEY_new();
    if (pkey == nullptr) {
      libcrypt.RSA_free(rsa);
      throw Exception('Falha ao criar EVP_PKEY');
    }
    final setResult = libcrypt.EVP_PKEY_set1_RSA(pkey, rsa);
    if (setResult != 1) {
      libcrypt.RSA_free(rsa);
      libcrypt.EVP_PKEY_free(pkey);
      throw Exception('EVP_PKEY_set1_RSA falhou');
    }
    // set1 increments the RSA refcount, so we can free our local handle.
    libcrypt.RSA_free(rsa);
    return pkey;
  }

  /// Cria um certificado X509 autoassinado com validade em [validityDays] dias.
    Pointer<X509> createSelfSignedCertificate(Pointer<EVP_PKEY> key,
      {int validityDays = 365}) {
    final cert = libcrypt.X509_new();
    if (cert == nullptr) {
      throw Exception('Falha ao criar X509');
    }
    // Define a versão para X509v3 (valor 2).
    libcrypt.X509_set_version(cert, 2);

    // Define o número de série.
    final serial = libcrypt.ASN1_INTEGER_new();
    if (serial == nullptr) {
      throw Exception('Falha ao criar ASN1_INTEGER');
    }
    libcrypt.ASN1_INTEGER_set(serial, 1);
    libcrypt.X509_set_serialNumber(cert, serial);
    libcrypt.ASN1_INTEGER_free(serial);

    // Define o período de validade.
    libcrypt.X509_gmtime_adj(libcrypt.X509_getm_notBefore(cert), 0);
    libcrypt.X509_gmtime_adj(
      libcrypt.X509_getm_notAfter(cert), validityDays * 24 * 3600);

    // Cria um nome para emissor e sujeito (no caso autoassinado, são iguais).
    final name = libcrypt.X509_NAME_new();
    if (name == nullptr) {
      throw Exception('Falha ao criar X509_NAME');
    }
    const int MBSTRING_ASC = 0x1001; // Valor oficial para ASCII.
    final cnKey = 'CN'.toNativeUtf8();
    final cnValue = 'SelfSignedCert'.toNativeUtf8();
    final ret = libcrypt.X509_NAME_add_entry_by_txt(
        name, cnKey.cast(), MBSTRING_ASC, cnValue.cast(), -1, -1, 0);
    calloc.free(cnKey);
    calloc.free(cnValue);
    if (ret != 1) {
      throw Exception('X509_NAME_add_entry_by_txt falhou');
    }
    libcrypt.X509_set_issuer_name(cert, name);
    libcrypt.X509_set_subject_name(cert, name);
    libcrypt.X509_NAME_free(name);

    // Associa a chave pública.
    libcrypt.X509_set_pubkey(cert, key);

    // Assina o certificado com a chave privada usando SHA256.
    final signRet = libcrypt.X509_sign(cert, key, libcrypt.EVP_sha256());
    if (signRet <= 0) {
      throw Exception('X509_sign falhou');
    }
    return cert;
  }

  /// Converte o certificado X509 para uma String no formato PEM.
  String x509ToPem(Pointer<X509> cert) {
    final bio = libcrypt.BIO_new(libcrypt.BIO_s_mem());
    if (bio == nullptr) {
      throw Exception('Falha ao criar BIO');
    }
    try {
      final ret = libcrypt.PEM_write_bio_X509(bio, cert);
      if (ret != 1) {
        throw Exception('PEM_write_bio_X509 falhou');
      }
      return _readBio(bio);
    } finally {
      libcrypt.BIO_free_all(bio);
    }
  }

  /// Converte a chave privada para uma String no formato PEM.
  String privateKeyToPem(Pointer<EVP_PKEY> key) {
    final bio = libcrypt.BIO_new(libcrypt.BIO_s_mem());
    if (bio == nullptr) {
      throw Exception('Falha ao criar BIO');
    }
    try {
      final ret = libcrypt.PEM_write_bio_PrivateKey(
          bio, key, nullptr, nullptr, 0, nullptr, nullptr);
      if (ret != 1) {
        throw Exception('PEM_write_bio_PrivateKey falhou');
      }
      return _readBio(bio);
    } finally {
      libcrypt.BIO_free_all(bio);
    }
  }

  String _readBio(Pointer<BIO> bio) {
    final outPtr = calloc<Pointer<Int8>>();
    try {
      final length = libcrypt.BIO_ctrl(bio, BIO_CTRL_INFO, 0, outPtr.cast());
      if (length <= 0 || outPtr.value == nullptr) {
        throw Exception('BIO_get_mem_data falhou');
      }
      final data = outPtr.value.cast<Uint8>().asTypedList(length);
      return String.fromCharCodes(data);
    } finally {
      calloc.free(outPtr);
    }
  }
}
