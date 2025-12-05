import 'dart:ffi' as ffi;
import 'dart:io';

import '../dtls_openssl/src/openssl_load_exception.dart';
import 'generated/ffi.dart';

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
  final OpenSsl crypto;
  final OpenSsl ssl;
  final bool supportsFromDataKeygen;

  /// Attempts to load libssl/libcrypto using the provided overrides and
  /// platform defaults.
  factory OpenSslBindings.load({
    String? cryptoPath,
    String? sslPath,
    bool requireKeyGeneration = false,
  }) {
    final cryptoLib = _loadDynamicLibrary(
      description: 'libcrypto',
      explicitPath: cryptoPath ?? Platform.environment['OPENSSL_LIBCRYPTO_PATH'],
      candidates: _cryptoCandidates(),
    );

    final sslLib = _loadDynamicLibrary(
      description: 'libssl',
      explicitPath: sslPath ?? Platform.environment['OPENSSL_LIBSSL_PATH'],
      candidates: _sslCandidates(),
    );

    final supportsFromData = _supportsFromDataKeygen(cryptoLib);
    if (requireKeyGeneration && !supportsFromData) {
      throw OpenSslLoadException(
        'Loaded OpenSSL build does not expose EVP_PKEY_fromdata symbols.\n'
        'Provide OpenSSL 3.x DLLs or pass explicit paths via OPENSSL_LIBCRYPTO_PATH/OPENSSL_LIBSSL_PATH.',
      );
    }

    return OpenSslBindings._(
      cryptoLib,
      sslLib,
      OpenSsl(cryptoLib),
      OpenSsl(sslLib),
      supportsFromData,
    );
  }

  static bool _supportsFromDataKeygen(ffi.DynamicLibrary cryptoLib) {
    const symbols = [
      'EVP_PKEY_CTX_new_from_name',
      'EVP_PKEY_CTX_free',
      'EVP_PKEY_fromdata_init',
      'EVP_PKEY_fromdata',
    ];
    for (final symbol in symbols) {
      try {
        cryptoLib.lookup<ffi.NativeFunction<ffi.Void Function()>>(symbol);
      } on ArgumentError {
        return false;
      }
    }
    return true;
  }
}

final OpenSsl _defaultLibSsl = _createDefaultBinding(
  description: 'libssl',
  envVar: 'OPENSSL_LIBSSL_PATH',
  candidates: _sslCandidates(),
);

final OpenSsl _defaultLibCrypto = _createDefaultBinding(
  description: 'libcrypto',
  envVar: 'OPENSSL_LIBCRYPTO_PATH',
  candidates: _cryptoCandidates(),
);

/// Tries to load libcrypto from a [dynamicLibrary].
///
/// If that fails, the function tries to load libcrypto from a default location.
OpenSsl loadLibCrypto(ffi.DynamicLibrary? dynamicLibrary) =>
    dynamicLibrary != null ? OpenSsl(dynamicLibrary) : _defaultLibCrypto;

/// Tries to load libssl from a [dynamicLibrary].
///
/// If that fails, the function tries to load libssl from a default location.
OpenSsl loadLibSsl(ffi.DynamicLibrary? dynamicLibrary) =>
    dynamicLibrary != null ? OpenSsl(dynamicLibrary) : _defaultLibSsl;

OpenSsl _createDefaultBinding({
  required String description,
  required String envVar,
  required List<String> candidates,
}) {
  final lib = _loadDynamicLibrary(
    description: description,
    explicitPath: Platform.environment[envVar],
    candidates: candidates,
  );
  return OpenSsl(lib);
}

ffi.DynamicLibrary _loadDynamicLibrary({
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
