import 'dart:ffi' as ffi;
import 'dart:io';

import 'libcrypto_ffi.dart';
import 'openssl_ffi.dart';

/// Thrown when OpenSSL shared libraries cannot be discovered or do not
/// implement the required symbols.
class OpenSslLoadException implements Exception {
  OpenSslLoadException(this.message);

  final String message;

  @override
  String toString() => 'OpenSslLoadException: $message';
}

/// Encapsulates the libssl/libcrypto bindings that higher level code consumes.
class OpenSslBindings {
  OpenSslBindings._(
    this.cryptoLibrary,
    this.sslLibrary,
    this.crypto,
    this.ssl,
    this.supportsFromDataKeygen,
  );

  final ffi.DynamicLibrary cryptoLibrary;
  final ffi.DynamicLibrary sslLibrary;
  final OpenSslCrypto crypto;
  final OpenSSL ssl;
  final bool supportsFromDataKeygen;

  /// Attempts to load libssl/libcrypto using the provided overrides and
  /// platform defaults.
  factory OpenSslBindings.load({
    String? cryptoPath,
    String? sslPath,
    bool requireKeyGeneration = false,
  }) {
    final cryptoLib = _loadLibrary(
      description: 'libcrypto',
      explicitPath: cryptoPath ?? Platform.environment['OPENSSL_LIBCRYPTO_PATH'],
      candidates: _cryptoCandidates(),
    );

    final sslLib = _loadLibrary(
      description: 'libssl',
      explicitPath: sslPath ?? Platform.environment['OPENSSL_LIBSSL_PATH'],
      candidates: _sslCandidates(),
    );

    final crypto = OpenSslCrypto(cryptoLib);
    final ssl = OpenSSL(sslLib);
    final supportsFromData = _supportsFromDataKeygen(crypto);
    if (requireKeyGeneration && !supportsFromData) {
      throw OpenSslLoadException(
        'Loaded OpenSSL build does not expose EVP_PKEY_fromdata symbols.\n'
        'Provide OpenSSL 3.x DLLs or pass explicit paths via OPENSSL_LIBCRYPTO_PATH/OPENSSL_LIBSSL_PATH.',
      );
    }
    return OpenSslBindings._(
      cryptoLib,
      sslLib,
      crypto,
      ssl,
      supportsFromData,
    );
  }

  static bool _supportsFromDataKeygen(OpenSslCrypto crypto) {
    final lookup = crypto.getLookup();
    const symbols = [
      'EVP_PKEY_FROMDATA_CTX_new_id',
      'EVP_PKEY_fromdata_init',
      'EVP_PKEY_fromdata',
    ];
    for (final symbol in symbols) {
      try {
        lookup<ffi.NativeFunction<ffi.Void Function()>>(symbol);
      } on ArgumentError {
        return false;
      }
    }
    return true;
  }
}

ffi.DynamicLibrary _loadLibrary({
  required String description,
  String? explicitPath,
  required List<String> candidates,
}) {
  final attempted = <String>[];
  final Iterable<String> resolvedCandidates = () sync* {
    if (explicitPath != null && explicitPath.isNotEmpty) {
      yield explicitPath;
    }
    final fromEnv = Platform.environment['OPENSSL_LIB_DIR'];
    if (fromEnv != null && fromEnv.isNotEmpty) {
      for (final name in candidates) {
        yield _joinIfDir(fromEnv, name);
      }
    }
    if (Platform.isWindows) {
      final systemRoot = Platform.environment['SystemRoot'];
      if (systemRoot != null && systemRoot.isNotEmpty) {
        final sysDir = Directory(systemRoot).uri.resolve('System32/').toFilePath(windows: true);
        for (final name in candidates) {
          yield _joinIfDir(sysDir, name);
        }
      }
    }
    yield* candidates;
  }();

  for (final candidate in resolvedCandidates) {
    attempted.add(candidate);
    try {
      return ffi.DynamicLibrary.open(candidate);
    } on ArgumentError {
      continue;
    }
  }

  throw OpenSslLoadException(
    'Unable to load $description. Tried: ${attempted.join(', ')}',
  );
}

String _joinIfDir(String dir, String name) {
  if (name.contains(Platform.pathSeparator)) {
    return name;
  }
  return Directory(dir).uri.resolve(name).toFilePath(windows: Platform.isWindows);
}

List<String> _sslCandidates() {
  if (Platform.isWindows) {
    return const ['libssl-3-x64.dll', 'libssl-1_1-x64.dll'];
  }
  if (Platform.isMacOS) {
    return const [
      '/usr/local/opt/openssl@3/lib/libssl.3.dylib',
      '/usr/local/opt/openssl@1.1/lib/libssl.1.1.dylib',
      '/opt/homebrew/lib/libssl.dylib',
      'libssl.3.dylib',
      'libssl.1.1.dylib',
    ];
  }
  return const ['libssl.so', 'libssl.so.3'];
}

List<String> _cryptoCandidates() {
  if (Platform.isWindows) {
    return const ['libcrypto-3-x64.dll', 'libcrypto-1_1-x64.dll'];
  }
  if (Platform.isMacOS) {
    return const [
      '/usr/local/opt/openssl@3/lib/libcrypto.3.dylib',
      '/usr/local/opt/openssl@1.1/lib/libcrypto.1.1.dylib',
      '/opt/homebrew/lib/libcrypto.dylib',
      'libcrypto.3.dylib',
      'libcrypto.1.1.dylib',
    ];
  }
  return const ['libcrypto.so', 'libcrypto.so.3'];
}
