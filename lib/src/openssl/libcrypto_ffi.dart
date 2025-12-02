import 'dart:ffi' as ffi;

const int EVP_PKEY_RSA = 6;

/// Tipos opacos adicionais (caso não estejam no binding)
final class bignum_st extends ffi.Opaque {}

typedef BIGNUM = bignum_st;

final class rsa_st extends ffi.Opaque {}

typedef RSA = rsa_st;

final class bn_gencb_st extends ffi.Opaque {}

typedef BN_GENCB = bn_gencb_st;

final class x509_st extends ffi.Opaque {}

typedef X509 = x509_st;

final class asn1_integer_st extends ffi.Opaque {}

typedef ASN1_INTEGER = asn1_integer_st;

final class asn1_time_st extends ffi.Opaque {}

typedef ASN1_TIME = asn1_time_st;

final class x509_name_st extends ffi.Opaque {}

typedef X509_NAME = x509_name_st;

final class evp_pkey_st extends ffi.Opaque {}

typedef EVP_PKEY = evp_pkey_st;

final class evp_md_st extends ffi.Opaque {}

typedef EVP_MD = evp_md_st;

final class evp_cipher_st extends ffi.Opaque {}

typedef EVP_CIPHER = evp_cipher_st;

final class bio_st extends ffi.Opaque {}

typedef BIO = bio_st;

final class bio_method_st extends ffi.Opaque {}

typedef BIO_METHOD = bio_method_st;

/// Nova estrutura OSSL_PARAM para passagem de parâmetros com EVP_PKEY_fromdata.
final class OSSL_PARAM extends ffi.Struct {
  external ffi.Pointer<ffi.Int8> key;
  @ffi.Int32()
  external int data_type;
  external ffi.Pointer<ffi.Void> data;
  @ffi.IntPtr()
  external int data_size;
  @ffi.IntPtr()
  external int return_size;
}

/// Tipo opaco para o contexto EVP_PKEY_FROMDATA_CTX.
final class evp_pkey_fromdata_ctx_st extends ffi.Opaque {}

typedef EVP_PKEY_FROMDATA_CTX = evp_pkey_fromdata_ctx_st;

typedef PemPasswordCbNative = ffi.Int Function(
    ffi.Pointer<ffi.Char>, // buf
    ffi.Int, // size
    ffi.Int, // rwflag
    ffi.Pointer<ffi.Void> // userdata
    );
typedef PemPasswordCbDart = int Function(
    ffi.Pointer<ffi.Char>, int, int, ffi.Pointer<ffi.Void>);

extension OpenSslExtension1 on OpenSslCrypto {
  ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
      getLookup() => _lookup;
}

/// Classe que encapsula os símbolos da libcrypto-3-x64.dll.
class OpenSslCrypto {
  /// Holds the symbol lookup function.
  final ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
      _lookup;

  /// The symbols are looked up in [dynamicLibrary].
  OpenSslCrypto(ffi.DynamicLibrary dynamicLibrary)
      : _lookup = dynamicLibrary.lookup;

  /// The symbols are looked up with [lookup].
  OpenSslCrypto.fromLookup(
      ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
          lookup)
      : _lookup = lookup;

  // Funções de BIGNUM
  ffi.Pointer<BIGNUM> BN_new() {
    final fn =
        _lookup<ffi.NativeFunction<ffi.Pointer<BIGNUM> Function()>>('BN_new');
    return fn.asFunction<ffi.Pointer<BIGNUM> Function()>()();
  }

  int BN_set_word(ffi.Pointer<BIGNUM> bn, int word) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Int Function(
                ffi.Pointer<BIGNUM>, ffi.UnsignedLong)>>('BN_set_word');
    return fn.asFunction<int Function(ffi.Pointer<BIGNUM>, int)>()(bn, word);
  }

  void BN_free(ffi.Pointer<BIGNUM> bn) {
    final fn =
        _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<BIGNUM>)>>(
            'BN_free');
    fn.asFunction<void Function(ffi.Pointer<BIGNUM>)>()(bn);
  }

  // Funções RSA
  ffi.Pointer<RSA> RSA_new() {
    final fn =
        _lookup<ffi.NativeFunction<ffi.Pointer<RSA> Function()>>('RSA_new');
    return fn.asFunction<ffi.Pointer<RSA> Function()>()();
  }

  void RSA_free(ffi.Pointer<RSA> rsa) {
    final fn =
        _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<RSA>)>>(
            'RSA_free');
    fn.asFunction<void Function(ffi.Pointer<RSA>)>()(rsa);
  }

  int RSA_generate_key_ex(ffi.Pointer<RSA> rsa, int bits, ffi.Pointer<BIGNUM> e,
      ffi.Pointer<BN_GENCB> cb) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Int Function(ffi.Pointer<RSA>, ffi.Int, ffi.Pointer<BIGNUM>,
                ffi.Pointer<BN_GENCB>)>>('RSA_generate_key_ex');
    return fn.asFunction<
        int Function(ffi.Pointer<RSA>, int, ffi.Pointer<BIGNUM>,
            ffi.Pointer<BN_GENCB>)>()(rsa, bits, e, cb);
  }

  // Funções EVP_PKEY
  ffi.Pointer<EVP_PKEY> EVP_PKEY_new() {
    final fn = _lookup<ffi.NativeFunction<ffi.Pointer<EVP_PKEY> Function()>>(
        'EVP_PKEY_new');
    return fn.asFunction<ffi.Pointer<EVP_PKEY> Function()>()();
  }

    int EVP_PKEY_set1_RSA(ffi.Pointer<EVP_PKEY> pkey, ffi.Pointer<RSA> rsa) {
    final fn = _lookup<
      ffi.NativeFunction<
        ffi.Int Function(ffi.Pointer<EVP_PKEY>,
          ffi.Pointer<RSA>)>>('EVP_PKEY_set1_RSA');
    return fn.asFunction<
      int Function(ffi.Pointer<EVP_PKEY>, ffi.Pointer<RSA>)>()(pkey, rsa);
    }

  void EVP_PKEY_free(ffi.Pointer<EVP_PKEY> pkey) {
    final fn =
        _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<EVP_PKEY>)>>(
            'EVP_PKEY_free');
    fn.asFunction<void Function(ffi.Pointer<EVP_PKEY>)>()(pkey);
  }

  // Funções X509
  ffi.Pointer<X509> X509_new() {
    final fn =
        _lookup<ffi.NativeFunction<ffi.Pointer<X509> Function()>>('X509_new');
    return fn.asFunction<ffi.Pointer<X509> Function()>()();
  }

  void X509_free(ffi.Pointer<X509> x) {
    final fn =
        _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<X509>)>>(
            'X509_free');
    fn.asFunction<void Function(ffi.Pointer<X509>)>()(x);
  }

  int X509_set_version(ffi.Pointer<X509> x, int version) {
    final fn = _lookup<
            ffi.NativeFunction<ffi.Int Function(ffi.Pointer<X509>, ffi.Long)>>(
        'X509_set_version');
    return fn.asFunction<int Function(ffi.Pointer<X509>, int)>()(x, version);
  }

  ffi.Pointer<ASN1_INTEGER> ASN1_INTEGER_new() {
    final fn =
        _lookup<ffi.NativeFunction<ffi.Pointer<ASN1_INTEGER> Function()>>(
            'ASN1_INTEGER_new');
    return fn.asFunction<ffi.Pointer<ASN1_INTEGER> Function()>()();
  }

  int ASN1_INTEGER_set(ffi.Pointer<ASN1_INTEGER> a, int v) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Int Function(
                ffi.Pointer<ASN1_INTEGER>, ffi.Long)>>('ASN1_INTEGER_set');
    return fn.asFunction<int Function(ffi.Pointer<ASN1_INTEGER>, int)>()(a, v);
  }

  void ASN1_INTEGER_free(ffi.Pointer<ASN1_INTEGER> a) {
    final fn =
        _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ASN1_INTEGER>)>>(
            'ASN1_INTEGER_free');
    fn.asFunction<void Function(ffi.Pointer<ASN1_INTEGER>)>()(a);
  }

  int X509_set_serialNumber(
      ffi.Pointer<X509> x, ffi.Pointer<ASN1_INTEGER> serial) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Int Function(ffi.Pointer<X509>,
                ffi.Pointer<ASN1_INTEGER>)>>('X509_set_serialNumber');
    return fn.asFunction<
        int Function(
            ffi.Pointer<X509>, ffi.Pointer<ASN1_INTEGER>)>()(x, serial);
  }

    ffi.Pointer<ASN1_TIME> X509_getm_notBefore(ffi.Pointer<X509> x) {
    final fn = _lookup<
      ffi.NativeFunction<
        ffi.Pointer<ASN1_TIME> Function(
          ffi.Pointer<X509>)>>('X509_getm_notBefore');
    return fn
      .asFunction<ffi.Pointer<ASN1_TIME> Function(ffi.Pointer<X509>)>()(x);
    }

    ffi.Pointer<ASN1_TIME> X509_getm_notAfter(ffi.Pointer<X509> x) {
    final fn = _lookup<
      ffi.NativeFunction<
        ffi.Pointer<ASN1_TIME> Function(
          ffi.Pointer<X509>)>>('X509_getm_notAfter');
    return fn
      .asFunction<ffi.Pointer<ASN1_TIME> Function(ffi.Pointer<X509>)>()(x);
    }

  ffi.Pointer<ASN1_TIME> X509_gmtime_adj(ffi.Pointer<ASN1_TIME> s, int adj) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Pointer<ASN1_TIME> Function(
                ffi.Pointer<ASN1_TIME>, ffi.Long)>>('X509_gmtime_adj');
    return fn.asFunction<
        ffi.Pointer<ASN1_TIME> Function(ffi.Pointer<ASN1_TIME>, int)>()(s, adj);
  }

  ffi.Pointer<X509_NAME> X509_NAME_new() {
    final fn = _lookup<ffi.NativeFunction<ffi.Pointer<X509_NAME> Function()>>(
        'X509_NAME_new');
    return fn.asFunction<ffi.Pointer<X509_NAME> Function()>()();
  }

  void X509_NAME_free(ffi.Pointer<X509_NAME> name) {
    final fn =
        _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<X509_NAME>)>>(
            'X509_NAME_free');
    fn.asFunction<void Function(ffi.Pointer<X509_NAME>)>()(name);
  }

  int X509_NAME_add_entry_by_txt(
      ffi.Pointer<X509_NAME> nm,
      ffi.Pointer<ffi.Char> field,
      int type,
      ffi.Pointer<ffi.Char> bytes,
      int len,
      int loc,
      int set) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Int Function(
              ffi.Pointer<X509_NAME>,
              ffi.Pointer<ffi.Char>,
              ffi.Int,
              ffi.Pointer<ffi.Char>,
              ffi.Int,
              ffi.Int,
              ffi.Int,
            )>>('X509_NAME_add_entry_by_txt');
    return fn.asFunction<
        int Function(
          ffi.Pointer<X509_NAME>,
          ffi.Pointer<ffi.Char>,
          int,
          ffi.Pointer<ffi.Char>,
          int,
          int,
          int,
        )>()(nm, field, type, bytes, len, loc, set);
  }

  int X509_set_issuer_name(ffi.Pointer<X509> x, ffi.Pointer<X509_NAME> name) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Int Function(ffi.Pointer<X509>,
                ffi.Pointer<X509_NAME>)>>('X509_set_issuer_name');
    return fn.asFunction<
        int Function(ffi.Pointer<X509>, ffi.Pointer<X509_NAME>)>()(x, name);
  }

  int X509_set_subject_name(ffi.Pointer<X509> x, ffi.Pointer<X509_NAME> name) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Int Function(ffi.Pointer<X509>,
                ffi.Pointer<X509_NAME>)>>('X509_set_subject_name');
    return fn.asFunction<
        int Function(ffi.Pointer<X509>, ffi.Pointer<X509_NAME>)>()(x, name);
  }

  int X509_set_pubkey(ffi.Pointer<X509> x, ffi.Pointer<EVP_PKEY> pkey) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Int Function(
                ffi.Pointer<X509>, ffi.Pointer<EVP_PKEY>)>>('X509_set_pubkey');
    return fn.asFunction<
        int Function(ffi.Pointer<X509>, ffi.Pointer<EVP_PKEY>)>()(x, pkey);
  }

  int X509_sign(
      ffi.Pointer<X509> x, ffi.Pointer<EVP_PKEY> pkey, ffi.Pointer<EVP_MD> md) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Int Function(ffi.Pointer<X509>, ffi.Pointer<EVP_PKEY>,
                ffi.Pointer<EVP_MD>)>>('X509_sign');
    return fn.asFunction<
        int Function(ffi.Pointer<X509>, ffi.Pointer<EVP_PKEY>,
            ffi.Pointer<EVP_MD>)>()(x, pkey, md);
  }

  ffi.Pointer<EVP_MD> EVP_sha256() {
    final fn = _lookup<ffi.NativeFunction<ffi.Pointer<EVP_MD> Function()>>(
        'EVP_sha256');
    return fn.asFunction<ffi.Pointer<EVP_MD> Function()>()();
  }

  int PEM_write_bio_X509(ffi.Pointer<BIO> bp, ffi.Pointer<X509> x) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Int Function(
                ffi.Pointer<BIO>, ffi.Pointer<X509>)>>('PEM_write_bio_X509');
    return fn.asFunction<int Function(ffi.Pointer<BIO>, ffi.Pointer<X509>)>()(
        bp, x);
  }

  int PEM_write_bio_PrivateKey(
    ffi.Pointer<BIO> bp,
    ffi.Pointer<EVP_PKEY> x,
    ffi.Pointer<EVP_CIPHER> enc,
    ffi.Pointer<ffi.Char> kstr, // Passphrase
    int klen,
    ffi.Pointer<ffi.NativeFunction<PemPasswordCbNative>> cb,
    ffi.Pointer<ffi.Void> u,
  ) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Int Function(
              ffi.Pointer<BIO>,
              ffi.Pointer<EVP_PKEY>,
              ffi.Pointer<EVP_CIPHER>,
              ffi.Pointer<ffi.Char>,
              ffi.Int,
              ffi.Pointer<ffi.NativeFunction<PemPasswordCbNative>>,
              ffi.Pointer<ffi.Void>,
            )>>('PEM_write_bio_PrivateKey');

    return fn.asFunction<
        int Function(
          ffi.Pointer<BIO>,
          ffi.Pointer<EVP_PKEY>,
          ffi.Pointer<EVP_CIPHER>,
          ffi.Pointer<ffi.Char>,
          int,
          ffi.Pointer<ffi.NativeFunction<PemPasswordCbNative>>,
          ffi.Pointer<ffi.Void>,
        )>()(bp, x, enc, kstr, klen, cb, u);
  }

  void BIO_free_all(ffi.Pointer<BIO> a) {
    final fn = _lookup<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<BIO>)>>(
        'BIO_free_all');
    fn.asFunction<void Function(ffi.Pointer<BIO>)>()(a);
  }

  ffi.Pointer<BIO> BIO_new(ffi.Pointer<BIO_METHOD> type) {
    final fn = _lookup<
        ffi.NativeFunction<ffi.Pointer<BIO> Function(ffi.Pointer<BIO_METHOD>)>>(
        'BIO_new');
    return fn.asFunction<
        ffi.Pointer<BIO> Function(ffi.Pointer<BIO_METHOD>)>()(type);
  }

  int BIO_ctrl(
      ffi.Pointer<BIO> bp, int cmd, int larg, ffi.Pointer<ffi.Void> parg) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Long Function(ffi.Pointer<BIO>, ffi.Int, ffi.Long,
                ffi.Pointer<ffi.Void>)>>('BIO_ctrl');
    return fn.asFunction<
        int Function(ffi.Pointer<BIO>, int, int, ffi.Pointer<ffi.Void>)>()(
        bp, cmd, larg, parg);
  }

  ffi.Pointer<BIO_METHOD> BIO_s_mem() {
    final fn = _lookup<
        ffi.NativeFunction<ffi.Pointer<BIO_METHOD> Function()>>('BIO_s_mem');
    return fn.asFunction<ffi.Pointer<BIO_METHOD> Function()>()();
  }

  // ********** Novos Bindings para EVP_PKEY_fromdata **********

  /// Cria um contexto para criação de chave via EVP_PKEY_fromdata.
  ffi.Pointer<EVP_PKEY_FROMDATA_CTX> EVP_PKEY_FROMDATA_CTX_new_id(
      int id, ffi.Pointer<ffi.Void> unused) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Pointer<EVP_PKEY_FROMDATA_CTX> Function(ffi.Int,
                ffi.Pointer<ffi.Void>)>>('EVP_PKEY_FROMDATA_CTX_new_id');
    return fn.asFunction<
        ffi.Pointer<EVP_PKEY_FROMDATA_CTX> Function(
            int, ffi.Pointer<ffi.Void>)>()(
      id,
      unused,
    );
  }

  /// Inicializa o contexto criado para EVP_PKEY_fromdata.
  int EVP_PKEY_fromdata_init(ffi.Pointer<EVP_PKEY_FROMDATA_CTX> ctx) {
    final fn = _lookup<
        ffi
        .NativeFunction<ffi.Int Function(ffi.Pointer<EVP_PKEY_FROMDATA_CTX>)>>(
      'EVP_PKEY_fromdata_init',
    );
    return fn
        .asFunction<int Function(ffi.Pointer<EVP_PKEY_FROMDATA_CTX>)>()(ctx);
  }

  /// Cria um EVP_PKEY a partir dos dados fornecidos em params.
  int EVP_PKEY_fromdata(
      ffi.Pointer<EVP_PKEY_FROMDATA_CTX> ctx,
      ffi.Pointer<ffi.Pointer<EVP_PKEY>> pkey,
      int selection,
      ffi.Pointer<OSSL_PARAM> params) {
    final fn = _lookup<
        ffi.NativeFunction<
            ffi.Int Function(
                ffi.Pointer<EVP_PKEY_FROMDATA_CTX>,
                ffi.Pointer<ffi.Pointer<EVP_PKEY>>,
                ffi.Int,
                ffi.Pointer<OSSL_PARAM>)>>('EVP_PKEY_fromdata');
    return fn.asFunction<
        int Function(
            ffi.Pointer<EVP_PKEY_FROMDATA_CTX>,
            ffi.Pointer<ffi.Pointer<EVP_PKEY>>,
            int,
            ffi.Pointer<OSSL_PARAM>)>()(ctx, pkey, selection, params);
  }

  /// Libera o contexto criado para EVP_PKEY_fromdata.
  void EVP_PKEY_FROMDATA_CTX_free(ffi.Pointer<EVP_PKEY_FROMDATA_CTX> ctx) {
    final fn = _lookup<
        ffi
        .NativeFunction<ffi.Void Function(ffi.Pointer<EVP_PKEY_FROMDATA_CTX>)>>(
      'EVP_PKEY_FROMDATA_CTX_free',
    );
    fn.asFunction<void Function(ffi.Pointer<EVP_PKEY_FROMDATA_CTX>)>()(ctx);
  }
}
