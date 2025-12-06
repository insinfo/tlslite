// ignore_for_file: camel_case_types, non_constant_identifier_names
// ignore_for_file: constant_identifier_names, public_member_api_docs
// ignore_for_file: unused_field, lines_longer_than_80_chars

import 'dart:async';
import 'dart:ffi' as ffi;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:tlslite/src/net_ffi/socket_exceptions.dart';
import 'package:tlslite/src/net_ffi/native_buffer_utils.dart';

import '../../openssl/generated/ffi.dart';
import '../../openssl/openssl_loader.dart';
import '../secure_socket_constants.dart';


typedef CiphertextWriter = Future<void> Function(Uint8List chunk);
typedef CiphertextReader = Future<Uint8List?> Function(int preferredLength);

/// Exposes a BIO-backed TLS engine that can be wired into async protocols such
/// as SQL Server TDS, where TLS records must be encapsulated in custom frames.
class SecureFFISocketOpenSSLAsync {
  SecureFFISocketOpenSSLAsync._({
    required bool isServer,
    String? certFile,
    String? keyFile,
    required CiphertextWriter writer,
    required CiphertextReader reader,
  })  : _isServer = isServer,
        _certFile = certFile,
        _keyFile = keyFile,
        _writeCiphertext = writer,
        _readCiphertext = reader {
    _initOpenSsl();
    _initializeSSL(certFile: certFile, keyFile: keyFile);
    _attachSslObject();
  }

  factory SecureFFISocketOpenSSLAsync.client({
    required CiphertextWriter writer,
    required CiphertextReader reader,
  }) =>
      SecureFFISocketOpenSSLAsync._(
        isServer: false,
        writer: writer,
        reader: reader,
      );

  factory SecureFFISocketOpenSSLAsync.server({
    required CiphertextWriter writer,
    required CiphertextReader reader,
    required String certFile,
    required String keyFile,
  }) =>
      SecureFFISocketOpenSSLAsync._(
        isServer: true,
        certFile: certFile,
        keyFile: keyFile,
        writer: writer,
        reader: reader,
      );

  final bool _isServer;
  final CiphertextWriter _writeCiphertext;
  final CiphertextReader _readCiphertext;
  final String? _certFile;
  final String? _keyFile;
  late final OpenSsl _openSsl;
  late final OpenSsl _openSslCrypto;
  ffi.Pointer<ssl_ctx_st>? _ctx;
  ffi.Pointer<ssl_st>? _ssl;
  ffi.Pointer<BIO>? _networkReadBio;
  ffi.Pointer<BIO>? _networkWriteBio;
  bool _sslInitialized = false;

  bool get isHandshakeComplete => _sslInitialized;

  Future<void> ensureHandshakeCompleted() async {
    if (_sslInitialized) {
      return;
    }
    while (true) {
      final result = _openSsl.SSL_do_handshake(_sslPtr);
      await _drainWriteBioAsync();
      if (result == 1) {
        _sslInitialized = true;
        return;
      }
      final error = _openSsl.SSL_get_error(_sslPtr, result);
      if (error == kSslErrorWantRead) {
        final filled = await _fillReadBioFromCallbacks();
        if (!filled) {
            throw SocketException(
              'TLS handshake aborted: encrypted channel yielded no bytes.');
        }
        continue;
      }
      if (error == kSslErrorWantWrite) {
        continue;
      }
        throw SocketException(
          'Asynchronous TLS handshake failed (OpenSSL code $error).');
    }
  }

  Future<int> send(Uint8List data) async {
    if (data.isEmpty) {
      return 0;
    }
    await ensureHandshakeCompleted();
    final buffer = NativeUint8Buffer.fromBytes(
      data,
      pool: NativeUint8BufferPool.global,
    );
    var written = 0;
    try {
      while (written < data.length) {
        final remaining = data.length - written;
        final ptr = buffer.slice(written).cast<ffi.Void>();
        final result = _openSsl.SSL_write(_sslPtr, ptr, remaining);
        await _drainWriteBioAsync();
        if (result > 0) {
          written += result;
          continue;
        }
        final error = _openSsl.SSL_get_error(_sslPtr, result);
        if (error == kSslErrorWantRead) {
          final filled = await _fillReadBioFromCallbacks();
          if (!filled) {
            throw SocketException(
              'Encrypted channel closed while SSL_write was in progress.');
          }
          continue;
        }
        if (error == kSslErrorWantWrite) {
          continue;
        }
        throw SocketException(
          'Asynchronous SSL write failed (OpenSSL code $error).');
      }
    } finally {
      buffer.release();
    }
    return data.length;
  }

  Future<Uint8List> recv(int bufferSize) async {
    await ensureHandshakeCompleted();
    final buffer = NativeUint8Buffer.pooled(bufferSize);
    try {
      while (true) {
        final received =
            _openSsl.SSL_read(_sslPtr, buffer.pointer.cast(), bufferSize);
        if (received > 0) {
          return buffer.copyToDart(received);
        }
        final error = _openSsl.SSL_get_error(_sslPtr, received);
        if (error == kSslErrorWantRead) {
          final filled = await _fillReadBioFromCallbacks(
            preferredSize: bufferSize,
          );
          if (!filled) {
            return Uint8List(0);
          }
          continue;
        }
        if (error == kSslErrorWantWrite) {
          await _drainWriteBioAsync();
          continue;
        }
        if (error == kSslErrorZeroReturn) {
          return Uint8List(0);
        }
        throw SocketException(
            'Asynchronous SSL read failed (OpenSSL code $error).');
      }
    } finally {
      buffer.release();
    }
  }

  Future<void> shutdown() async {
    if (_ssl == null || _ssl == ffi.nullptr || !_sslInitialized) {
      return;
    }
    final result = _openSsl.SSL_shutdown(_sslPtr);
    if (result == 0) {
      await _drainWriteBioAsync();
      await _fillReadBioFromCallbacks();
      _openSsl.SSL_shutdown(_sslPtr);
    }
    await _drainWriteBioAsync();
    _sslInitialized = false;
  }

  Future<void> close() async {
    await shutdown();
    final ssl = _ssl;
    if (ssl != null && ssl != ffi.nullptr) {
      _openSsl.SSL_free(ssl);
      _ssl = null;
      _networkReadBio = null;
      _networkWriteBio = null;
    }
    final ctx = _ctx;
    if (ctx != null && ctx != ffi.nullptr) {
      _openSsl.SSL_CTX_free(ctx);
      _ctx = null;
    }
  }

  Future<bool> _fillReadBioFromCallbacks({int? preferredSize}) async {
    final bio = _networkReadBio;
    if (bio == null || bio == ffi.nullptr) {
      throw SocketException('TLS read BIO is unavailable.');
    }
    final chunkSize =
        (preferredSize == null || preferredSize <= 0)
            ? kDefaultCiphertextChunk
            : preferredSize;
    final ciphertext = await _readCiphertext(chunkSize);
    if (ciphertext == null || ciphertext.isEmpty) {
      return false;
    }
    final buffer = NativeUint8Buffer.fromBytes(
      ciphertext,
      pool: NativeUint8BufferPool.global,
    );
    try {
      final written = _openSslCrypto.BIO_write(
        bio,
        buffer.pointer.cast(),
        ciphertext.length,
      );
      if (written <= 0) {
        throw SocketException('Failed to feed the asynchronous TLS read BIO.');
      }
    } finally {
      buffer.release();
    }
    return true;
  }

  Future<void> _drainWriteBioAsync() async {
    final bio = _networkWriteBio;
    if (bio == null || bio == ffi.nullptr) {
      return;
    }
    while (true) {
      final pending = _openSslCrypto.BIO_ctrl(
        bio,
        kBioCtrlPending,
        0,
        ffi.nullptr.cast<ffi.Void>(),
      );
      if (pending <= 0) {
        return;
      }
      final chunkSize = pending < kDefaultCiphertextChunk
          ? pending
          : kDefaultCiphertextChunk;
      final buffer = NativeUint8Buffer.pooled(
        chunkSize,
        pool: NativeUint8BufferPool.global,
      );
      try {
        final read =
          _openSslCrypto.BIO_read(bio, buffer.pointer.cast(), chunkSize);
        if (read <= 0) {
          return;
        }
        final ciphertext = buffer.copyToDart(read);
        await _writeCiphertext(ciphertext);
      } finally {
        buffer.release();
      }
    }
  }

  void _initOpenSsl() {
    final bindings = OpenSslBindings.load();
    _openSsl = bindings.ssl;
    _openSslCrypto = bindings.crypto;
  }

  void _initializeSSL({String? certFile, String? keyFile}) {
    ffi.Pointer<SSL_METHOD> method =
        _isServer ? _openSsl.TLS_server_method() : _openSsl.TLS_client_method();
    _ctx = _openSsl.SSL_CTX_new(method);
    if (_ctx == ffi.nullptr || _ctx == null) {
      throw SocketException('Failed to create the SSL context.');
    }
    if (_isServer) {
      if (certFile == null || keyFile == null) {
        throw SocketException(
            'Certificate and private key are required in server mode.');
      }
      final certFilePtr = certFile.toNativeUtf8();
      final keyFilePtr = keyFile.toNativeUtf8();
      final ctxPtr = _ctxPtr;
      final certResult = _openSsl.SSL_CTX_use_certificate_file(
          ctxPtr, certFilePtr.cast(), 1);
      final keyResult =
          _openSsl.SSL_CTX_use_PrivateKey_file(ctxPtr, keyFilePtr.cast(), 1);
      calloc.free(certFilePtr);
      calloc.free(keyFilePtr);
      if (certResult != 1) {
        throw SocketException('Failed to load the certificate file.');
      }
      if (keyResult != 1) {
        throw SocketException('Failed to load the private key file.');
      }
    }
  }

  void _attachSslObject() {
    final ctxPtr = _ctxPtr;
    _ssl = _openSsl.SSL_new(ctxPtr);
    if (_ssl == ffi.nullptr || _ssl == null) {
      throw SocketException('Failed to create the SSL instance.');
    }
    _networkReadBio = _openSslCrypto.BIO_new(_openSslCrypto.BIO_s_mem());
    _networkWriteBio = _openSslCrypto.BIO_new(_openSslCrypto.BIO_s_mem());
    if (_networkReadBio == ffi.nullptr || _networkWriteBio == ffi.nullptr) {
      throw SocketException('Failed to create the TLS transport BIOs.');
    }
    _openSsl.SSL_set_bio(_sslPtr, _networkReadBioPtr, _networkWriteBioPtr);
    if (_isServer) {
      _openSsl.SSL_set_accept_state(_sslPtr);
    } else {
      _openSsl.SSL_set_connect_state(_sslPtr);
    }
  }

  ffi.Pointer<ssl_ctx_st> get _ctxPtr {
    final ctx = _ctx;
    if (ctx == null || ctx == ffi.nullptr) {
      throw SocketException('SSL context is unavailable.');
    }
    return ctx;
  }

  ffi.Pointer<ssl_st> get _sslPtr {
    final ssl = _ssl;
    if (ssl == null || ssl == ffi.nullptr) {
      throw SocketException('SSL object is unavailable.');
    }
    return ssl;
  }

  ffi.Pointer<BIO> get _networkReadBioPtr {
    final bio = _networkReadBio;
    if (bio == null || bio == ffi.nullptr) {
      throw SocketException('TLS read BIO is unavailable.');
    }
    return bio;
  }

  ffi.Pointer<BIO> get _networkWriteBioPtr {
    final bio = _networkWriteBio;
    if (bio == null || bio == ffi.nullptr) {
      throw SocketException('TLS write BIO is unavailable.');
    }
    return bio;
  }
}
