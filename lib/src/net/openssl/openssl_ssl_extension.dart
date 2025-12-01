import 'dart:ffi' as ffi;
import 'openssl_ffi.dart';

/// Extension que encapsula os símbolos da libssl-3-x64.dll.
extension OpenSslExtension2 on OpenSSL {
  ffi.Pointer<SSL_METHOD> TLS_client_method() {
    // Precisamos de NativeFunction<Pointer<SSL_METHOD> Function()>
    final fn =
        getLookup()<ffi.NativeFunction<ffi.Pointer<SSL_METHOD> Function()>>(
      'TLS_client_method',
    );
    // Convertendo para a função Dart:
    return fn.asFunction<ffi.Pointer<SSL_METHOD> Function()>()();
  }

  int SSL_CTX_use_certificate_file(
      ffi.Pointer<ssl_ctx_st> ctx, ffi.Pointer<ffi.Char> file, int type) {
    final ptr = getLookup()<
        ffi.NativeFunction<
            ffi.Int Function(ffi.Pointer<ssl_ctx_st>, ffi.Pointer<ffi.Char>,
                ffi.Int)>>('SSL_CTX_use_certificate_file');
    return ptr.asFunction<
        int Function(ffi.Pointer<ssl_ctx_st>, ffi.Pointer<ffi.Char>,
            int)>()(ctx, file, type);
  }

  int SSL_CTX_use_PrivateKey_file(
      ffi.Pointer<ssl_ctx_st> ctx, ffi.Pointer<ffi.Char> file, int type) {
    final ptr = getLookup()<
        ffi.NativeFunction<
            ffi.Int Function(ffi.Pointer<ssl_ctx_st>, ffi.Pointer<ffi.Char>,
                ffi.Int)>>('SSL_CTX_use_PrivateKey_file');
    return ptr.asFunction<
        int Function(ffi.Pointer<ssl_ctx_st>, ffi.Pointer<ffi.Char>,
            int)>()(ctx, file, type);
  }

  ffi.Pointer<SSL_METHOD> TLS_server_method() {
    final fn =
        getLookup()<ffi.NativeFunction<ffi.Pointer<SSL_METHOD> Function()>>(
      'TLS_server_method',
    );
    return fn.asFunction<ffi.Pointer<SSL_METHOD> Function()>()();
  }

  int SSL_set_fd(ffi.Pointer<ssl_st> ssl, int fd) {
    // Precisamos de NativeFunction<Int Function(Pointer<ssl_st>, Int)>
    final fn = getLookup()<
        ffi.NativeFunction<ffi.Int Function(ffi.Pointer<ssl_st>, ffi.Int)>>(
      'SSL_set_fd',
    );
    return fn.asFunction<int Function(ffi.Pointer<ssl_st>, int)>()(ssl, fd);
  }

  ffi.Pointer<SSL> SSL_new(ffi.Pointer<ssl_ctx_st> ctx) {
    // Precisamos de NativeFunction<Pointer<SSL> Function(Pointer<ssl_ctx_st>)>
    final fn = getLookup()<
        ffi.NativeFunction<ffi.Pointer<SSL> Function(ffi.Pointer<ssl_ctx_st>)>>(
      'SSL_new',
    );
    return fn
        .asFunction<ffi.Pointer<SSL> Function(ffi.Pointer<ssl_ctx_st>)>()(ctx);
  }

  int SSL_connect(ffi.Pointer<ssl_st> ssl) {
    // Precisamos de NativeFunction<Int Function(Pointer<ssl_st>)>
    final fn =
        getLookup()<ffi.NativeFunction<ffi.Int Function(ffi.Pointer<ssl_st>)>>(
      'SSL_connect',
    );
    return fn.asFunction<int Function(ffi.Pointer<ssl_st>)>()(ssl);
  }

  int SSL_accept(ffi.Pointer<ssl_st> ssl) {
    final fn =
        getLookup()<ffi.NativeFunction<ffi.Int Function(ffi.Pointer<ssl_st>)>>(
      'SSL_accept',
    );
    return fn.asFunction<int Function(ffi.Pointer<ssl_st>)>()(ssl);
  }

  int SSL_read(ffi.Pointer<ssl_st> ssl, ffi.Pointer<ffi.Void> buf, int num) {
    final fn = getLookup()<
        ffi.NativeFunction<
            ffi.Int Function(
                ffi.Pointer<ssl_st>, ffi.Pointer<ffi.Void>, ffi.Int)>>(
      'SSL_read',
    );
    return fn.asFunction<
        int Function(
            ffi.Pointer<ssl_st>, ffi.Pointer<ffi.Void>, int)>()(ssl, buf, num);
  }

  int SSL_write(ffi.Pointer<ssl_st> ssl, ffi.Pointer<ffi.Void> buf, int num) {
    final fn = getLookup()<
        ffi.NativeFunction<
            ffi.Int Function(
                ffi.Pointer<ssl_st>, ffi.Pointer<ffi.Void>, ffi.Int)>>(
      'SSL_write',
    );
    return fn.asFunction<
        int Function(
            ffi.Pointer<ssl_st>, ffi.Pointer<ffi.Void>, int)>()(ssl, buf, num);
  }

  int SSL_shutdown(ffi.Pointer<ssl_st> ssl) {
    final fn =
        getLookup()<ffi.NativeFunction<ffi.Int Function(ffi.Pointer<ssl_st>)>>(
      'SSL_shutdown',
    );
    return fn.asFunction<int Function(ffi.Pointer<ssl_st>)>()(ssl);
  }
}
