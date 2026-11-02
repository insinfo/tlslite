import 'dart:ffi';
import 'package:tlslite/src/ffi/native_memory.dart';

import 'generated/ffi.dart';
import 'openssl_loader.dart';

/// Constants – the values below must match the values defined in the OpenSSL bindings.
const int osslParamUnsignedInteger = 1;
const int evpPkeyKeypair = 1; // Selection for key pair creation
const int bioCtrlInfo = 3;
const int evpPkeyRsa = 6;

/// Builds the OSSL_PARAM array for RSA key generation.
Pointer<OSSL_PARAM> constructParams(int bits, int pubexp) {
  // Allocate an array of 3 parameters: "rsa_bits", "rsa_pubexp" and the end marker.
  const paramCount = 3;
  final params = calloc<OSSL_PARAM>(paramCount);

  // First parameter: "rsa_bits"
  final keyBits = "rsa_bits".toNativeUtf8();
  params[0].key = keyBits.cast<Char>();
  params[0].data_type = osslParamUnsignedInteger;
  // Allocate memory to hold the bit count (uint32)
  final bitsPtr = calloc<Uint32>();
  bitsPtr.value = bits;
  params[0].data = bitsPtr.cast<Void>();
  params[0].data_size = sizeOf<Uint32>();

  // Second parameter: "rsa_pubexp"
  final keyPubexp = "rsa_pubexp".toNativeUtf8();
  params[1].key = keyPubexp.cast<Char>();
  params[1].data_type = osslParamUnsignedInteger;
  final pubexpPtr = calloc<Uint32>();
  pubexpPtr.value = pubexp;
  params[1].data = pubexpPtr.cast<Void>();
  params[1].data_size = sizeOf<Uint32>();

  // Third parameter: end marker (key == nullptr)
  params[2].key = nullptr;

  return params;
}

void freeParams(Pointer<OSSL_PARAM> params) {
  // Free the strings and the data allocated for the parameters
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

/// Helper class for creating a self-signed certificate with the OpenSSL 3 APIs.
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

  /// Generates an RSA key pair and returns a pointer to an EVP_PKEY, using EVP_PKEY_fromdata when available.
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
        evpPkeyRsa,
        nullptr.cast<ENGINE>(),
      );
    }

    if (ctx == nullptr) {
      throw Exception('Failed to create EVP_PKEY_CTX');
    }

    if (libcrypt.EVP_PKEY_fromdata_init(ctx) != 1) {
      libcrypt.EVP_PKEY_CTX_free(ctx);
      throw Exception('Failed to initialize EVP_PKEY_fromdata');
    }

    final params = constructParams(2048, 65537);
    final pkeyPtr = calloc<Pointer<EVP_PKEY>>();
    final ret =
        libcrypt.EVP_PKEY_fromdata(ctx, pkeyPtr, evpPkeyKeypair, params);
    freeParams(params);
    libcrypt.EVP_PKEY_CTX_free(ctx);

    if (ret != 1 || pkeyPtr.value == nullptr) {
      calloc.free(pkeyPtr);
      throw Exception('EVP_PKEY_fromdata failed');
    }

    final pkey = pkeyPtr.value;
    calloc.free(pkeyPtr);
    return pkey;
  }

  Pointer<EVP_PKEY> _generateLegacyRsa() {
    final rsa = libcrypt.RSA_new();
    if (rsa == nullptr) {
      throw Exception('Failed to create RSA');
    }
    final bn = libcrypt.BN_new();
    if (bn == nullptr) {
      libcrypt.RSA_free(rsa);
      throw Exception('Failed to create BIGNUM');
    }
    const exponent = 65537;
    if (libcrypt.BN_set_word(bn, exponent) != 1) {
      libcrypt.BN_free(bn);
      libcrypt.RSA_free(rsa);
      throw Exception('Failed to set the RSA exponent');
    }
    final generated = libcrypt.RSA_generate_key_ex(rsa, 2048, bn, nullptr);
    libcrypt.BN_free(bn);
    if (generated != 1) {
      libcrypt.RSA_free(rsa);
      throw Exception('RSA_generate_key_ex failed');
    }

    final pkey = libcrypt.EVP_PKEY_new();
    if (pkey == nullptr) {
      libcrypt.RSA_free(rsa);
      throw Exception('Failed to create EVP_PKEY');
    }
    final setResult = libcrypt.EVP_PKEY_set1_RSA(pkey, rsa);
    if (setResult != 1) {
      libcrypt.RSA_free(rsa);
      libcrypt.EVP_PKEY_free(pkey);
      throw Exception('EVP_PKEY_set1_RSA failed');
    }
    // set1 increments the RSA refcount, so we can free our local handle.
    libcrypt.RSA_free(rsa);
    return pkey;
  }

  /// Creates a self-signed X509 certificate valid for [validityDays] days.
    Pointer<X509> createSelfSignedCertificate(Pointer<EVP_PKEY> key,
      {int validityDays = 365}) {
    final cert = libcrypt.X509_new();
    if (cert == nullptr) {
      throw Exception('Failed to create X509');
    }
    // Set the version to X509v3 (value 2).
    libcrypt.X509_set_version(cert, 2);

    // Set the serial number.
    final serial = libcrypt.ASN1_INTEGER_new();
    if (serial == nullptr) {
      throw Exception('Failed to create ASN1_INTEGER');
    }
    libcrypt.ASN1_INTEGER_set(serial, 1);
    libcrypt.X509_set_serialNumber(cert, serial);
    libcrypt.ASN1_INTEGER_free(serial);

    // Set the validity period.
    libcrypt.X509_gmtime_adj(libcrypt.X509_getm_notBefore(cert), 0);
    libcrypt.X509_gmtime_adj(
      libcrypt.X509_getm_notAfter(cert), validityDays * 24 * 3600);

    // Create a name for issuer and subject (identical for a self-signed certificate).
    final name = libcrypt.X509_NAME_new();
    if (name == nullptr) {
      throw Exception('Failed to create X509_NAME');
    }
    const int mbstringAsc = 0x1001; // Official value for ASCII.
    final cnKey = 'CN'.toNativeUtf8();
    final cnValue = 'SelfSignedCert'.toNativeUtf8();
    final ret = libcrypt.X509_NAME_add_entry_by_txt(
        name, cnKey.cast(), mbstringAsc, cnValue.cast(), -1, -1, 0);
    calloc.free(cnKey);
    calloc.free(cnValue);
    if (ret != 1) {
      throw Exception('X509_NAME_add_entry_by_txt failed');
    }
    libcrypt.X509_set_issuer_name(cert, name);
    libcrypt.X509_set_subject_name(cert, name);
    libcrypt.X509_NAME_free(name);

    // Attach the public key.
    libcrypt.X509_set_pubkey(cert, key);

    // Sign the certificate with the private key using SHA256.
    final signRet = libcrypt.X509_sign(cert, key, libcrypt.EVP_sha256());
    if (signRet <= 0) {
      throw Exception('X509_sign failed');
    }
    return cert;
  }

  /// Converts the X509 certificate to a PEM-encoded String.
  String x509ToPem(Pointer<X509> cert) {
    final bio = libcrypt.BIO_new(libcrypt.BIO_s_mem());
    if (bio == nullptr) {
      throw Exception('Failed to create BIO');
    }
    try {
      final ret = libcrypt.PEM_write_bio_X509(bio, cert);
      if (ret != 1) {
        throw Exception('PEM_write_bio_X509 failed');
      }
      return _readBio(bio);
    } finally {
      libcrypt.BIO_free_all(bio);
    }
  }

  /// Converts the private key to a PEM-encoded String.
  String privateKeyToPem(Pointer<EVP_PKEY> key) {
    final bio = libcrypt.BIO_new(libcrypt.BIO_s_mem());
    if (bio == nullptr) {
      throw Exception('Failed to create BIO');
    }
    try {
      final ret = libcrypt.PEM_write_bio_PrivateKey(
          bio, key, nullptr, nullptr, 0, nullptr, nullptr);
      if (ret != 1) {
        throw Exception('PEM_write_bio_PrivateKey failed');
      }
      return _readBio(bio);
    } finally {
      libcrypt.BIO_free_all(bio);
    }
  }

  String _readBio(Pointer<BIO> bio) {
    final outPtr = calloc<Pointer<Int8>>();
    try {
      final length = libcrypt.BIO_ctrl(bio, bioCtrlInfo, 0, outPtr.cast());
      if (length <= 0 || outPtr.value == nullptr) {
        throw Exception('BIO_get_mem_data failed');
      }
      final data = outPtr.value.cast<Uint8>().asTypedList(length);
      return String.fromCharCodes(data);
    } finally {
      calloc.free(outPtr);
    }
  }
}
