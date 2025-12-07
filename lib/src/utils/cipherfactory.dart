import 'dart:typed_data';

import 'aes.dart';
import 'aesccm.dart';
import 'aesgcm.dart';
import 'chacha20_poly1305.dart';
import 'dart_aes.dart' as dart_aes;
import 'dart_aesgcm.dart' as dart_aesgcm;
import 'dart_aesccm.dart' as dart_aesccm;
import 'dart_chacha20_poly1305.dart' as dart_chacha20_poly1305;
import 'dart_rc4.dart' as dart_rc4;
import 'dart_tripledes.dart' as dart_tripledes;
import 'rc4.dart';
import 'tripledes.dart';

AES createAES(Uint8List key, Uint8List iv, {List<String>? implementations}) {
  final implList = implementations ?? const ['dart'];
  for (final impl in implList) {
    if (impl == 'dart') {
      if (iv.length != 16) {
        throw ArgumentError('AES CBC IV must be exactly 16 bytes long');
      }
      return dart_aes.newAES(
        Uint8List.fromList(key),
        aesModeCBC,
        Uint8List.fromList(iv),
      );
    }
  }
  throw UnsupportedError('No supported AES implementation found for $implList');
}

AES createAESCTR(Uint8List key, Uint8List iv, {List<String>? implementations}) {
  final implList = implementations ?? const ['dart'];
  for (final impl in implList) {
    if (impl == 'dart') {
      if (iv.isEmpty || iv.length >= 16) {
        throw ArgumentError('AES CTR nonce must be between 1 and 15 bytes');
      }
      return dart_aes.newAES(
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
  final implList = implementations ?? const ['dart'];
  for (final impl in implList) {
    if (impl == 'dart') {
      return dart_aesgcm.newAESGCM(Uint8List.fromList(key));
    }
  }
  throw UnsupportedError(
      'No supported AES-GCM implementation found for $implList');
}

AESCCM createAESCCM(Uint8List key, {List<String>? implementations}) {
  final implList = implementations ?? const ['dart'];
  for (final impl in implList) {
    if (impl == 'dart') {
      return dart_aesccm.newAESCCM(Uint8List.fromList(key));
    }
  }
  throw UnsupportedError(
      'No supported AES-CCM implementation found for $implList');
}

AESCCM createAESCCM8(Uint8List key, {List<String>? implementations}) {
  final implList = implementations ?? const ['dart'];
  for (final impl in implList) {
    if (impl == 'dart') {
      return dart_aesccm.newAESCCM(Uint8List.fromList(key), tagLength: 8);
    }
  }
  throw UnsupportedError(
      'No supported AES-CCM-8 implementation found for $implList');
}

Chacha20Poly1305 createCHACHA20(Uint8List key,
    {List<String>? implementations}) {
  final implList = implementations ?? const ['dart'];
  for (final impl in implList) {
    if (impl == 'dart') {
      return dart_chacha20_poly1305.newChaCha20Poly1305(Uint8List.fromList(key));
    }
  }
  throw UnsupportedError(
      'No supported ChaCha20-Poly1305 implementation found for $implList');
}

RC4 createRC4(Uint8List key, Uint8List iv, {List<String>? implementations}) {
  if (iv.isNotEmpty) {
    throw ArgumentError(
        'RC4 ignores IV; pass an empty list to match dart semantics');
  }
  final implList = implementations ?? const ['dart'];
  for (final impl in implList) {
    if (impl == 'dart') {
      return dart_rc4.newRC4(Uint8List.fromList(key));
    }
  }
  throw UnsupportedError('No supported RC4 implementation found for $implList');
}

TripleDES createTripleDES(Uint8List key, Uint8List iv,
    {List<String>? implementations}) {
  final implList = implementations ?? const ['dart'];
  for (final impl in implList) {
    if (impl == 'dart') {
      return dart_tripledes.newTripleDES(
        Uint8List.fromList(key),
        Uint8List.fromList(iv),
      );
    }
  }
  throw UnsupportedError(
      'No supported TripleDES implementation found for $implList');
}
