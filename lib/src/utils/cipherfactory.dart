import 'dart:typed_data';

import 'aes.dart';
import 'aesccm.dart';
import 'aesgcm.dart';
import 'chacha20_poly1305.dart';
import 'python_aes.dart' as python_aes;
import 'python_aesgcm.dart' as python_aesgcm;
import 'python_aesccm.dart' as python_aesccm;
import 'python_chacha20_poly1305.dart' as python_chacha20_poly1305;
import 'python_rc4.dart' as python_rc4;
import 'python_tripledes.dart' as python_tripledes;
import 'rc4.dart';
import 'tripledes.dart';

AES createAES(Uint8List key, Uint8List iv, {List<String>? implementations}) {
  final implList = implementations ?? const ['python'];
  for (final impl in implList) {
    if (impl == 'python') {
      if (iv.length != 16) {
        throw ArgumentError('AES CBC IV must be exactly 16 bytes long');
      }
      return python_aes.newAES(
        Uint8List.fromList(key),
        aesModeCBC,
        Uint8List.fromList(iv),
      );
    }
  }
  throw UnsupportedError('No supported AES implementation found for $implList');
}

AES createAESCTR(Uint8List key, Uint8List iv, {List<String>? implementations}) {
  final implList = implementations ?? const ['python'];
  for (final impl in implList) {
    if (impl == 'python') {
      if (iv.isEmpty || iv.length >= 16) {
        throw ArgumentError('AES CTR nonce must be between 1 and 15 bytes');
      }
      return python_aes.newAES(
        Uint8List.fromList(key),
        aesModeCTR_OR_GCM,
        Uint8List.fromList(iv),
      );
    }
  }
  throw UnsupportedError(
      'No supported AES-CTR implementation found for $implList');
}

AESGCM createAESGCM(Uint8List key, {List<String>? implementations}) {
  final implList = implementations ?? const ['python'];
  for (final impl in implList) {
    if (impl == 'python') {
      return python_aesgcm.newAESGCM(Uint8List.fromList(key));
    }
  }
  throw UnsupportedError(
      'No supported AES-GCM implementation found for $implList');
}

AESCCM createAESCCM(Uint8List key, {List<String>? implementations}) {
  final implList = implementations ?? const ['python'];
  for (final impl in implList) {
    if (impl == 'python') {
      return python_aesccm.newAESCCM(Uint8List.fromList(key));
    }
  }
  throw UnsupportedError(
      'No supported AES-CCM implementation found for $implList');
}

AESCCM createAESCCM8(Uint8List key, {List<String>? implementations}) {
  final implList = implementations ?? const ['python'];
  for (final impl in implList) {
    if (impl == 'python') {
      return python_aesccm.newAESCCM(Uint8List.fromList(key), tagLength: 8);
    }
  }
  throw UnsupportedError(
      'No supported AES-CCM-8 implementation found for $implList');
}

Chacha20Poly1305 createCHACHA20(Uint8List key,
    {List<String>? implementations}) {
  final implList = implementations ?? const ['python'];
  for (final impl in implList) {
    if (impl == 'python') {
      return python_chacha20_poly1305
          .newChaCha20Poly1305(Uint8List.fromList(key));
    }
  }
  throw UnsupportedError(
      'No supported ChaCha20-Poly1305 implementation found for $implList');
}

RC4 createRC4(Uint8List key, Uint8List iv, {List<String>? implementations}) {
  if (iv.isNotEmpty) {
    throw ArgumentError(
        'RC4 ignores IV; pass an empty list to match Python semantics');
  }
  final implList = implementations ?? const ['python'];
  for (final impl in implList) {
    if (impl == 'python') {
      return python_rc4.newRC4(Uint8List.fromList(key));
    }
  }
  throw UnsupportedError('No supported RC4 implementation found for $implList');
}

TripleDES createTripleDES(Uint8List key, Uint8List iv,
    {List<String>? implementations}) {
  final implList = implementations ?? const ['python'];
  for (final impl in implList) {
    if (impl == 'python') {
      return python_tripledes.newTripleDES(
        Uint8List.fromList(key),
        Uint8List.fromList(iv),
      );
    }
  }
  throw UnsupportedError(
      'No supported TripleDES implementation found for $implList');
}
