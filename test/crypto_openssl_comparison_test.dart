// Test file to compare pure Dart crypto implementations with OpenSSL
// This ensures our implementations produce identical results to OpenSSL

import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:test/test.dart';
import 'package:tlslite/src/openssl/generated/ffi.dart';
import 'package:tlslite/src/openssl/openssl_loader.dart';
import 'package:tlslite/src/utils/chacha20_poly1305.dart';
import 'package:tlslite/src/utils/dart_aesgcm.dart' as dart_aesgcm;
import 'package:tlslite/src/utils/poly1305.dart';
import 'package:tlslite/src/utils/tlshashlib.dart';
import 'package:tlslite/src/utils/tlshmac.dart';

/// Helper to convert hex string to Uint8List
Uint8List hex(String hexStr) {
  final cleaned = hexStr.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
  if (cleaned.length.isOdd) {
    throw ArgumentError('Hex string must have even length');
  }
  final out = Uint8List(cleaned.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    final byte = cleaned.substring(i * 2, i * 2 + 2);
    out[i] = int.parse(byte, radix: 16);
  }
  return out;
}

/// Helper to convert Uint8List to hex string
String toHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// OpenSSL crypto wrapper for comparison tests
class OpenSslCrypto {
  late final OpenSsl _crypto;
  bool _initialized = false;

  void init() {
    if (_initialized) return;
    try {
      final bindings = OpenSslBindings.load();
      _crypto = bindings.crypto;
      _initialized = true;
      // print('OpenSSL version: ${_crypto.OPENSSL_version_major()}.${_crypto.OPENSSL_version_minor()}.${_crypto.OPENSSL_version_patch()}');
    } catch (e) {
      // print('Failed to load OpenSSL: $e');
      rethrow;
    }
  }

  bool get isAvailable => _initialized;

  /// ChaCha20-Poly1305 AEAD seal using OpenSSL
  Uint8List chacha20Poly1305Seal(Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List aad) {
    if (!_initialized) throw StateError('OpenSSL not initialized');

    final ctx = _crypto.EVP_CIPHER_CTX_new();
    if (ctx.address == 0) throw StateError('Failed to create cipher context');

    try {
      // Initialize cipher
      final cipher = _crypto.EVP_chacha20_poly1305();
      if (cipher.address == 0) throw StateError('Failed to get chacha20-poly1305 cipher');

      // Use ffi.Pointer<ffi.UnsignedChar> for key and IV
      final keyPtr = calloc<ffi.UnsignedChar>(key.length);
      final noncePtr = calloc<ffi.UnsignedChar>(nonce.length);
      
      for (int i = 0; i < key.length; i++) {
        keyPtr[i] = key[i];
      }
      for (int i = 0; i < nonce.length; i++) {
        noncePtr[i] = nonce[i];
      }

      // Init encryption
      var result = _crypto.EVP_EncryptInit_ex(ctx, cipher, ffi.nullptr, ffi.nullptr, ffi.nullptr);
      if (result != 1) throw StateError('EVP_EncryptInit_ex (1) failed');

      // Set IV length
      result = _crypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce.length, ffi.nullptr);
      if (result != 1) throw StateError('EVP_CIPHER_CTX_ctrl (ivlen) failed');

      // Set key and IV
      result = _crypto.EVP_EncryptInit_ex(ctx, ffi.nullptr, ffi.nullptr, keyPtr, noncePtr);
      if (result != 1) throw StateError('EVP_EncryptInit_ex (2) failed');

      // Add AAD if present
      if (aad.isNotEmpty) {
        final aadPtr = calloc<ffi.UnsignedChar>(aad.length);
        for (int i = 0; i < aad.length; i++) {
          aadPtr[i] = aad[i];
        }
        final outLen = calloc<ffi.Int>();
        result = _crypto.EVP_EncryptUpdate(ctx, ffi.nullptr, outLen, aadPtr, aad.length);
        calloc.free(aadPtr);
        calloc.free(outLen);
        if (result != 1) throw StateError('EVP_EncryptUpdate (aad) failed');
      }

      // Encrypt plaintext
      final ciphertextPtr = calloc<ffi.UnsignedChar>(plaintext.length + 16); // +16 for potential expansion
      final outLen = calloc<ffi.Int>();
      
      if (plaintext.isNotEmpty) {
        final plaintextPtr = calloc<ffi.UnsignedChar>(plaintext.length);
        for (int i = 0; i < plaintext.length; i++) {
          plaintextPtr[i] = plaintext[i];
        }
        result = _crypto.EVP_EncryptUpdate(ctx, ciphertextPtr, outLen, plaintextPtr, plaintext.length);
        calloc.free(plaintextPtr);
        if (result != 1) throw StateError('EVP_EncryptUpdate (plaintext) failed');
      }

      int ciphertextLen = outLen.value;

      // Finalize
      final tmpOutLen = calloc<ffi.Int>();
      result = _crypto.EVP_EncryptFinal_ex(ctx, ciphertextPtr + ciphertextLen, tmpOutLen);
      ciphertextLen += tmpOutLen.value;
      calloc.free(tmpOutLen);
      if (result != 1) throw StateError('EVP_EncryptFinal_ex failed');

      // Get tag
      final tagPtr = calloc<ffi.UnsignedChar>(16);
      result = _crypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tagPtr.cast());
      if (result != 1) throw StateError('EVP_CIPHER_CTX_ctrl (get tag) failed');

      // Combine ciphertext + tag
      final output = Uint8List(ciphertextLen + 16);
      for (int i = 0; i < ciphertextLen; i++) {
        output[i] = ciphertextPtr[i];
      }
      for (int i = 0; i < 16; i++) {
        output[ciphertextLen + i] = tagPtr[i];
      }

      // Cleanup
      calloc.free(keyPtr);
      calloc.free(noncePtr);
      calloc.free(ciphertextPtr);
      calloc.free(outLen);
      calloc.free(tagPtr);

      return output;
    } finally {
      _crypto.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// AES-128-GCM seal using OpenSSL
  Uint8List aes128GcmSeal(Uint8List key, Uint8List nonce, Uint8List plaintext, Uint8List aad) {
    if (!_initialized) throw StateError('OpenSSL not initialized');
    if (key.length != 16) throw ArgumentError('Key must be 16 bytes for AES-128');

    final ctx = _crypto.EVP_CIPHER_CTX_new();
    if (ctx.address == 0) throw StateError('Failed to create cipher context');

    try {
      final cipher = _crypto.EVP_aes_128_gcm();
      if (cipher.address == 0) throw StateError('Failed to get AES-128-GCM cipher');

      final keyPtr = calloc<ffi.UnsignedChar>(key.length);
      final noncePtr = calloc<ffi.UnsignedChar>(nonce.length);
      
      for (int i = 0; i < key.length; i++) {
        keyPtr[i] = key[i];
      }
      for (int i = 0; i < nonce.length; i++) {
        noncePtr[i] = nonce[i];
      }

      var result = _crypto.EVP_EncryptInit_ex(ctx, cipher, ffi.nullptr, ffi.nullptr, ffi.nullptr);
      if (result != 1) throw StateError('EVP_EncryptInit_ex (1) failed');

      result = _crypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.length, ffi.nullptr);
      if (result != 1) throw StateError('EVP_CIPHER_CTX_ctrl (ivlen) failed');

      result = _crypto.EVP_EncryptInit_ex(ctx, ffi.nullptr, ffi.nullptr, keyPtr, noncePtr);
      if (result != 1) throw StateError('EVP_EncryptInit_ex (2) failed');

      if (aad.isNotEmpty) {
        final aadPtr = calloc<ffi.UnsignedChar>(aad.length);
        for (int i = 0; i < aad.length; i++) {
          aadPtr[i] = aad[i];
        }
        final outLen = calloc<ffi.Int>();
        result = _crypto.EVP_EncryptUpdate(ctx, ffi.nullptr, outLen, aadPtr, aad.length);
        calloc.free(aadPtr);
        calloc.free(outLen);
        if (result != 1) throw StateError('EVP_EncryptUpdate (aad) failed');
      }

      final ciphertextPtr = calloc<ffi.UnsignedChar>(plaintext.length + 16);
      final outLen = calloc<ffi.Int>();
      
      if (plaintext.isNotEmpty) {
        final plaintextPtr = calloc<ffi.UnsignedChar>(plaintext.length);
        for (int i = 0; i < plaintext.length; i++) {
          plaintextPtr[i] = plaintext[i];
        }
        result = _crypto.EVP_EncryptUpdate(ctx, ciphertextPtr, outLen, plaintextPtr, plaintext.length);
        calloc.free(plaintextPtr);
        if (result != 1) throw StateError('EVP_EncryptUpdate (plaintext) failed');
      }

      int ciphertextLen = outLen.value;

      final tmpOutLen = calloc<ffi.Int>();
      result = _crypto.EVP_EncryptFinal_ex(ctx, ciphertextPtr + ciphertextLen, tmpOutLen);
      ciphertextLen += tmpOutLen.value;
      calloc.free(tmpOutLen);
      if (result != 1) throw StateError('EVP_EncryptFinal_ex failed');

      final tagPtr = calloc<ffi.UnsignedChar>(16);
      result = _crypto.EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tagPtr.cast());
      if (result != 1) throw StateError('EVP_CIPHER_CTX_ctrl (get tag) failed');

      final output = Uint8List(ciphertextLen + 16);
      for (int i = 0; i < ciphertextLen; i++) {
        output[i] = ciphertextPtr[i];
      }
      for (int i = 0; i < 16; i++) {
        output[ciphertextLen + i] = tagPtr[i];
      }

      calloc.free(keyPtr);
      calloc.free(noncePtr);
      calloc.free(ciphertextPtr);
      calloc.free(outLen);
      calloc.free(tagPtr);

      return output;
    } finally {
      _crypto.EVP_CIPHER_CTX_free(ctx);
    }
  }

  /// SHA-256 hash using OpenSSL
  Uint8List sha256(Uint8List data) {
    if (!_initialized) throw StateError('OpenSSL not initialized');

    final ctx = _crypto.EVP_MD_CTX_new();
    if (ctx.address == 0) throw StateError('Failed to create MD context');

    try {
      final md = _crypto.EVP_sha256();
      if (md.address == 0) throw StateError('Failed to get SHA-256 digest');

      var result = _crypto.EVP_DigestInit_ex(ctx, md, ffi.nullptr);
      if (result != 1) throw StateError('EVP_DigestInit_ex failed');

      if (data.isNotEmpty) {
        final dataPtr = calloc<ffi.UnsignedChar>(data.length);
        final bytePtr = dataPtr;
        for (int i = 0; i < data.length; i++) {
          bytePtr[i] = data[i];
        }
        result = _crypto.EVP_DigestUpdate(ctx, dataPtr.cast(), data.length);
        calloc.free(dataPtr);
        if (result != 1) throw StateError('EVP_DigestUpdate failed');
      }

      final hashPtr = calloc<ffi.UnsignedChar>(32);
      final hashLen = calloc<ffi.UnsignedInt>();
      result = _crypto.EVP_DigestFinal_ex(ctx, hashPtr, hashLen);
      if (result != 1) throw StateError('EVP_DigestFinal_ex failed');

      final hash = Uint8List(32);
      for (int i = 0; i < 32; i++) {
        hash[i] = hashPtr[i];
      }

      calloc.free(hashPtr);
      calloc.free(hashLen);

      return hash;
    } finally {
      _crypto.EVP_MD_CTX_free(ctx);
    }
  }

  /// HMAC-SHA256 using OpenSSL
  Uint8List hmacSha256(Uint8List key, Uint8List data) {
    if (!_initialized) throw StateError('OpenSSL not initialized');

    final keyPtr = calloc<ffi.UnsignedChar>(key.length);
    final keyBytePtr = keyPtr;
    for (int i = 0; i < key.length; i++) {
      keyBytePtr[i] = key[i];
    }

    final dataPtr = calloc<ffi.UnsignedChar>(data.length);
    for (int i = 0; i < data.length; i++) {
      dataPtr[i] = data[i];
    }

    final md = _crypto.EVP_sha256();
    if (md.address == 0) throw StateError('Failed to get SHA-256 digest');

    final outPtr = calloc<ffi.UnsignedChar>(32);
    final outLen = calloc<ffi.UnsignedInt>();

    final result = _crypto.HMAC(md, keyPtr.cast(), key.length, dataPtr, data.length, outPtr, outLen);

    final hmac = Uint8List(32);
    if (result.address != 0) {
      for (int i = 0; i < 32; i++) {
        hmac[i] = outPtr[i];
      }
    }

    calloc.free(keyPtr);
    calloc.free(dataPtr);
    calloc.free(outPtr);
    calloc.free(outLen);

    if (result.address == 0) throw StateError('HMAC failed');

    return hmac;
  }
}

void main() {
  late OpenSslCrypto openssl;
  bool opensslAvailable = false;

  setUpAll(() {
    openssl = OpenSslCrypto();
    try {
      openssl.init();
      opensslAvailable = true;
      // print('OpenSSL is available for comparison tests');
    } catch (e) {
      // print('OpenSSL not available: $e');
      // print('Tests will only run pure Dart implementations');
    }
  });

  group('ChaCha20-Poly1305 comparison', () {
    // RFC 7539 test vectors
    final testVectors = [
      // Test Vector 1 - RFC 7539 Section 2.8.2
      {
        'key': '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f',
        'nonce': '070000004041424344454647',
        'aad': '50515253c0c1c2c3c4c5c6c7',
        'plaintext': '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e',
        'expected': 'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691',
      },
      // Test Vector 2 - Empty plaintext
      {
        'key': '0000000000000000000000000000000000000000000000000000000000000000',
        'nonce': '000000000000000000000000',
        'aad': '',
        'plaintext': '',
        'expected': null, // Will be computed by OpenSSL if available
      },
      // Test Vector 3 - No AAD
      {
        'key': '0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20',
        'nonce': '000000000000000000000001',
        'aad': '',
        'plaintext': '48656c6c6f20576f726c6421', // "Hello World!"
        'expected': null,
      },
    ];

    test('Dart implementation matches RFC 7539 vector', () {
      final v = testVectors[0];
      final key = hex(v['key']!);
      final nonce = hex(v['nonce']!);
      final aad = hex(v['aad']!);
      final plaintext = hex(v['plaintext']!);
      final expected = hex(v['expected']!);

      final dart = Chacha20Poly1305(key, 'dart');
      final dartResult = dart.seal(nonce, plaintext, aad);

      expect(dartResult, equals(expected), reason: 'Dart ChaCha20-Poly1305 should match RFC 7539');
    });

    test('Dart implementation matches OpenSSL', () {
      if (!opensslAvailable) {
        print('Skipping OpenSSL comparison - not available');
        return;
      }

      for (int i = 0; i < testVectors.length; i++) {
        final v = testVectors[i];
        final key = hex(v['key']!);
        final nonce = hex(v['nonce']!);
        final aad = v['aad']!.isNotEmpty ? hex(v['aad']!) : Uint8List(0);
        final plaintext = v['plaintext']!.isNotEmpty ? hex(v['plaintext']!) : Uint8List(0);

        final dart = Chacha20Poly1305(key, 'dart');
        final dartResult = dart.seal(nonce, plaintext, aad);

        final opensslResult = openssl.chacha20Poly1305Seal(key, nonce, plaintext, aad);

        expect(dartResult, equals(opensslResult), 
          reason: 'Test vector $i: Dart ChaCha20-Poly1305 should match OpenSSL\n'
                  'Dart:    ${toHex(dartResult)}\n'
                  'OpenSSL: ${toHex(opensslResult)}');
      }
    });

    test('Dart decryption works with OpenSSL encrypted data', () {
      if (!opensslAvailable) {
        print('Skipping OpenSSL comparison - not available');
        return;
      }

      final key = hex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
      final nonce = hex('070000004041424344454647');
      final aad = hex('50515253c0c1c2c3c4c5c6c7');
      final plaintext = hex('48656c6c6f20576f726c6421'); // "Hello World!"

      // Encrypt with OpenSSL
      final opensslCiphertext = openssl.chacha20Poly1305Seal(key, nonce, plaintext, aad);

      // Decrypt with Dart
      final dart = Chacha20Poly1305(key, 'dart');
      final decrypted = dart.open(nonce, opensslCiphertext, aad);

      expect(decrypted, isNotNull, reason: 'Decryption should succeed');
      expect(decrypted, equals(plaintext), reason: 'Decrypted data should match original');
    });
  });

  group('AES-GCM comparison', () {
    // Test vectors
    final testVectors = [
      // RFC 5116 vector
      {
        'key': '00000000000000000000000000000000',
        'nonce': '000000000000000000000000',
        'aad': '',
        'plaintext': '',
        'expected': '58e2fccefa7e3061367f1d57a4e7455a',
      },
      // RFC 5116 vector 2
      {
        'key': '00000000000000000000000000000000',
        'nonce': '000000000000000000000000',
        'aad': '',
        'plaintext': '00000000000000000000000000000000',
        'expected': '0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf',
      },
      // Custom test
      {
        'key': '01010101010101010101010101010101',
        'nonce': '020202020202020202020202',
        'aad': '',
        'plaintext': '7465787420746f20656e63727970742e', // "text to encrypt."
        'expected': '27816817e65a295cf28e6d46cb910e757a313af67da75c40ba11d872df234bd4',
      },
    ];

    test('Dart implementation matches known vectors', () {
      for (int i = 0; i < testVectors.length; i++) {
        final v = testVectors[i];
        final key = hex(v['key']!);
        final nonce = hex(v['nonce']!);
        final aad = v['aad']!.isNotEmpty ? hex(v['aad']!) : Uint8List(0);
        final plaintext = v['plaintext']!.isNotEmpty ? hex(v['plaintext']!) : Uint8List(0);
        final expected = hex(v['expected']!);

        final aes = dart_aesgcm.newAESGCM(key);
        final result = aes.seal(nonce, plaintext, aad);

        expect(result, equals(expected),
          reason: 'Test vector $i: Dart AES-GCM should match expected\n'
                  'Got:      ${toHex(result)}\n'
                  'Expected: ${toHex(expected)}');
      }
    });

    test('Dart implementation matches OpenSSL', () {
      if (!opensslAvailable) {
        print('Skipping OpenSSL comparison - not available');
        return;
      }

      for (int i = 0; i < testVectors.length; i++) {
        final v = testVectors[i];
        final key = hex(v['key']!);
        final nonce = hex(v['nonce']!);
        final aad = v['aad']!.isNotEmpty ? hex(v['aad']!) : Uint8List(0);
        final plaintext = v['plaintext']!.isNotEmpty ? hex(v['plaintext']!) : Uint8List(0);

        final aes = dart_aesgcm.newAESGCM(key);
        final dartResult = aes.seal(nonce, plaintext, aad);

        final opensslResult = openssl.aes128GcmSeal(key, nonce, plaintext, aad);

        expect(dartResult, equals(opensslResult),
          reason: 'Test vector $i: Dart AES-GCM should match OpenSSL\n'
                  'Dart:    ${toHex(dartResult)}\n'
                  'OpenSSL: ${toHex(opensslResult)}');
      }
    });

    test('Dart decryption works with OpenSSL encrypted data', () {
      if (!opensslAvailable) {
        print('Skipping OpenSSL comparison - not available');
        return;
      }

      final key = hex('01010101010101010101010101010101');
      final nonce = hex('020202020202020202020202');
      final aad = Uint8List(0);
      final plaintext = hex('48656c6c6f20576f726c6421'); // "Hello World!"

      // Encrypt with OpenSSL
      final opensslCiphertext = openssl.aes128GcmSeal(key, nonce, plaintext, aad);

      // Decrypt with Dart
      final aes = dart_aesgcm.newAESGCM(key);
      final decrypted = aes.open(nonce, opensslCiphertext, aad);

      expect(decrypted, isNotNull, reason: 'Decryption should succeed');
      expect(decrypted, equals(plaintext), reason: 'Decrypted data should match original');
    });
  });

  group('SHA-256 comparison', () {
    final testVectors = [
      // Empty string
      {
        'input': '',
        'expected': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      },
      // "abc"
      {
        'input': '616263',
        'expected': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      },
      // "Hello World!"
      {
        'input': '48656c6c6f20576f726c6421',
        'expected': '7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069',
      },
    ];

    test('Dart implementation matches known vectors', () {
      for (int i = 0; i < testVectors.length; i++) {
        final v = testVectors[i];
        final input = v['input']!.isNotEmpty ? hex(v['input']!) : Uint8List(0);
        final expected = hex(v['expected']!);

        final hashObj = newHash('sha256', input.toList());
        final hash = hashObj.digest();

        expect(hash, equals(expected),
          reason: 'Test vector $i: Dart SHA-256 should match expected\n'
                  'Got:      ${toHex(hash)}\n'
                  'Expected: ${toHex(expected)}');
      }
    });

    test('Dart implementation matches OpenSSL', () {
      if (!opensslAvailable) {
        print('Skipping OpenSSL comparison - not available');
        return;
      }

      for (int i = 0; i < testVectors.length; i++) {
        final v = testVectors[i];
        final input = v['input']!.isNotEmpty ? hex(v['input']!) : Uint8List(0);

        final hashObj = newHash('sha256', input.toList());
        final dartResult = hashObj.digest();
        final opensslResult = openssl.sha256(input);

        expect(dartResult, equals(opensslResult),
          reason: 'Test vector $i: Dart SHA-256 should match OpenSSL\n'
                  'Dart:    ${toHex(dartResult)}\n'
                  'OpenSSL: ${toHex(opensslResult)}');
      }
    });
  });

  group('HMAC-SHA256 comparison', () {
    final testVectors = [
      // RFC 4231 Test Case 1
      {
        'key': '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
        'data': '4869205468657265', // "Hi There"
        'expected': 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
      },
      // RFC 4231 Test Case 2
      {
        'key': '4a656665', // "Jefe"
        'data': '7768617420646f2079612077616e7420666f72206e6f7468696e673f', // "what do ya want for nothing?"
        'expected': '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
      },
    ];

    test('Dart implementation matches known vectors', () {
      for (int i = 0; i < testVectors.length; i++) {
        final v = testVectors[i];
        final key = hex(v['key']!);
        final data = hex(v['data']!);
        final expected = hex(v['expected']!);

        final hmac = TlsHmac(key.toList(), digestmod: 'sha256');
        hmac.update(data.toList());
        final result = hmac.digest();

        expect(result, equals(expected),
          reason: 'Test vector $i: Dart HMAC-SHA256 should match expected\n'
                  'Got:      ${toHex(result)}\n'
                  'Expected: ${toHex(expected)}');
      }
    });

    test('Dart implementation matches OpenSSL', () {
      if (!opensslAvailable) {
        print('Skipping OpenSSL comparison - not available');
        return;
      }

      for (int i = 0; i < testVectors.length; i++) {
        final v = testVectors[i];
        final key = hex(v['key']!);
        final data = hex(v['data']!);

        final hmac = TlsHmac(key.toList(), digestmod: 'sha256');
        hmac.update(data.toList());
        final dartResult = hmac.digest();

        final opensslResult = openssl.hmacSha256(key, data);

        expect(dartResult, equals(opensslResult),
          reason: 'Test vector $i: Dart HMAC-SHA256 should match OpenSSL\n'
                  'Dart:    ${toHex(dartResult)}\n'
                  'OpenSSL: ${toHex(opensslResult)}');
      }
    });
  });

  group('Poly1305 comparison', () {
    // RFC 7539 Test Vector
    test('Dart implementation matches RFC 7539 vector', () {
      final key = hex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
      final message = hex('43727970746f6772617068696320466f72756d2052657365617263682047726f7570');
      final expected = hex('a8061dc1305136c6c22b8baf0c0127a9');

      final poly = Poly1305(key);
      final tag = poly.createTag(message);

      expect(tag, equals(expected),
        reason: 'Poly1305 should match RFC 7539 test vector\n'
                'Got:      ${toHex(tag)}\n'
                'Expected: ${toHex(expected)}');
    });
  });

  group('Random data comparison (stress test)', () {
    test('ChaCha20-Poly1305 with random data', () {
      if (!opensslAvailable) {
        print('Skipping OpenSSL comparison - not available');
        return;
      }

      final random = List.generate(32, (i) => i);
      final key = Uint8List.fromList(random);
      final nonce = Uint8List.fromList(List.generate(12, (i) => i * 2));

      // Test various plaintext sizes
      for (final size in [0, 1, 15, 16, 17, 63, 64, 65, 100, 1000]) {
        final plaintext = Uint8List.fromList(List.generate(size, (i) => i % 256));
        final aad = Uint8List.fromList(List.generate(13, (i) => i * 3));

        final dart = Chacha20Poly1305(key, 'dart');
        final dartResult = dart.seal(nonce, plaintext, aad);

        final opensslResult = openssl.chacha20Poly1305Seal(key, nonce, plaintext, aad);

        expect(dartResult, equals(opensslResult),
          reason: 'Plaintext size $size: Dart ChaCha20-Poly1305 should match OpenSSL');

        // Verify decryption
        final decrypted = dart.open(nonce, dartResult, aad);
        expect(decrypted, equals(plaintext),
          reason: 'Plaintext size $size: Decryption should recover original plaintext');
      }
    });

    test('AES-GCM with random data', () {
      if (!opensslAvailable) {
        print('Skipping OpenSSL comparison - not available');
        return;
      }

      final key = Uint8List.fromList(List.generate(16, (i) => i));
      final nonce = Uint8List.fromList(List.generate(12, (i) => i * 2));

      // Test various plaintext sizes
      for (final size in [0, 1, 15, 16, 17, 63, 64, 65, 100, 1000]) {
        final plaintext = Uint8List.fromList(List.generate(size, (i) => i % 256));
        final aad = Uint8List.fromList(List.generate(13, (i) => i * 3));

        final aes = dart_aesgcm.newAESGCM(key);
        final dartResult = aes.seal(nonce, plaintext, aad);

        final opensslResult = openssl.aes128GcmSeal(key, nonce, plaintext, aad);

        expect(dartResult, equals(opensslResult),
          reason: 'Plaintext size $size: Dart AES-GCM should match OpenSSL');

        // Verify decryption
        final decrypted = aes.open(nonce, dartResult, aad);
        expect(decrypted, equals(plaintext),
          reason: 'Plaintext size $size: Decryption should recover original plaintext');
      }
    });
  });
}
