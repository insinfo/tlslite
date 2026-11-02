// dart format width=5000
// Tests for the PCLMULQDQ-optimized AES-GCM

import 'dart:typed_data';
import 'package:test/test.dart';

import 'package:tlslite/src/experimental/aesgcm_asm_x86_64.dart';
import 'package:tlslite/src/experimental/rijndael_fast_asm_x86_64.dart';

void main() {
  group('PclmulqdqSupport', () {
    test('detects PCLMULQDQ support', () {
      final supported = PclmulqdqSupport.isSupported;
      print('PCLMULQDQ supported: $supported');
      // Should be true on modern processors (since 2010)
      expect(supported, isA<bool>());
    });
  });

  group('GhashAsm', () {
    test('GHASH of zeros returns zeros', () {
      if (!PclmulqdqSupport.isSupported) {
        print('Skipping test - PCLMULQDQ not supported');
        return;
      }

      final h = Uint8List(16); // H = 0
      final ghash = GhashAsm(h);

      try {
        ghash.update(Uint8List(16)); // data = 0
        final result = ghash.finalize(0, 16);

        // 0 * 0 = 0 in GF(2^128)
        expect(result, equals(Uint8List(16)));
      } finally {
        ghash.dispose();
      }
    });

    test('GHASH produces a consistent result', () {
      if (!PclmulqdqSupport.isSupported) {
        print('Skipping test - PCLMULQDQ not supported');
        return;
      }

      // H = hash key (non-zero)
      final h = Uint8List.fromList([
        0x66,
        0xe9,
        0x4b,
        0xd4,
        0xef,
        0x8a,
        0x2c,
        0x3b,
        0x88,
        0x4c,
        0xfa,
        0x59,
        0xca,
        0x34,
        0x2b,
        0x2e
      ]);

      final ghash = GhashAsm(h);

      try {
        // Test data
        final data = Uint8List.fromList([
          0x00,
          0x01,
          0x02,
          0x03,
          0x04,
          0x05,
          0x06,
          0x07,
          0x08,
          0x09,
          0x0a,
          0x0b,
          0x0c,
          0x0d,
          0x0e,
          0x0f
        ]);

        ghash.update(data);
        final result1 = ghash.finalize(0, 16);

        // Reset and repeat - must give the same result
        ghash.reset();
        ghash.update(data);
        final result2 = ghash.finalize(0, 16);

        expect(result1, equals(result2));
        print(
            'GHASH result: ${result1.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
      } finally {
        ghash.dispose();
      }
    });
  });

  // These tests encrypt blocks with RijndaelAsmX8664 (AES-NI, Win64 only).
  group('AESGCMAsm',
      skip: AesNiSupport.isSupported ? null : 'AES-NI not available', () {
    test('checks availability', () {
      final supported = AESGCMAsm.isSupported;
      print('AES-GCM ASM supported: $supported');
      expect(supported, isA<bool>());
    });

    test('seal and open work correctly', () {
      if (!AESGCMAsm.isSupported || !AesNiSupport.isSupported) {
        print('Skipping test - hardware not supported');
        return;
      }

      // Key AES-128
      final key = Uint8List.fromList([
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b,
        0x0c,
        0x0d,
        0x0e,
        0x0f
      ]);

      // Nonce 12 bytes
      final nonce = Uint8List.fromList([
        0x00,
        0x01,
        0x02,
        0x03,
        0x04,
        0x05,
        0x06,
        0x07,
        0x08,
        0x09,
        0x0a,
        0x0b
      ]);

      // Plaintext
      final plaintext = Uint8List.fromList([
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff
      ]);

      // AAD
      final aad = Uint8List.fromList([0xfe, 0xed, 0xfa, 0xce]);

      // Create an AES-NI instance for block encryption
      final aes = RijndaelAsmX8664(key);
      final rawAesEncrypt = (Uint8List block) => aes.encrypt(block);

      final gcm = AESGCMAsm(key, rawAesEncrypt);

      try {
        // Encrypt
        final ciphertextWithTag = gcm.seal(nonce, plaintext, aad);
        print('Ciphertext+Tag length: ${ciphertextWithTag.length}');
        expect(ciphertextWithTag.length, equals(plaintext.length + 16));

        // Decrypt
        final decrypted = gcm.open(nonce, ciphertextWithTag, aad);
        expect(decrypted, isNotNull);
        expect(decrypted, equals(plaintext));
      } finally {
        gcm.dispose();
      }
    });

    test('detects a modified ciphertext', () {
      if (!AESGCMAsm.isSupported || !AesNiSupport.isSupported) {
        print('Skipping test - hardware not supported');
        return;
      }

      final key = Uint8List.fromList(List.generate(16, (i) => i));
      final nonce = Uint8List.fromList(List.generate(12, (i) => i));
      final plaintext = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final aad = Uint8List(0);

      final aes = RijndaelAsmX8664(key);
      final gcm = AESGCMAsm(key, (block) => aes.encrypt(block));

      try {
        final ciphertextWithTag = gcm.seal(nonce, plaintext, aad);

        // Modify one ciphertext byte
        ciphertextWithTag[0] ^= 0x01;

        final decrypted = gcm.open(nonce, ciphertextWithTag, aad);
        expect(decrypted, isNull); // Must fail
      } finally {
        gcm.dispose();
      }
    });

    test('detects a modified tag', () {
      if (!AESGCMAsm.isSupported || !AesNiSupport.isSupported) {
        print('Skipping test - hardware not supported');
        return;
      }

      final key = Uint8List.fromList(List.generate(16, (i) => i));
      final nonce = Uint8List.fromList(List.generate(12, (i) => i));
      final plaintext = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final aad = Uint8List(0);

      final aes = RijndaelAsmX8664(key);
      final gcm = AESGCMAsm(key, (block) => aes.encrypt(block));

      try {
        final ciphertextWithTag = gcm.seal(nonce, plaintext, aad);

        // Modify the last byte (tag)
        ciphertextWithTag[ciphertextWithTag.length - 1] ^= 0x01;

        final decrypted = gcm.open(nonce, ciphertextWithTag, aad);
        expect(decrypted, isNull);
      } finally {
        gcm.dispose();
      }
    });

    test('detects a modified AAD', () {
      if (!AESGCMAsm.isSupported || !AesNiSupport.isSupported) {
        print('Skipping test - hardware not supported');
        return;
      }

      final key = Uint8List.fromList(List.generate(16, (i) => i));
      final nonce = Uint8List.fromList(List.generate(12, (i) => i));
      final plaintext = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      final aad = Uint8List.fromList([0xfe, 0xed]);

      final aes = RijndaelAsmX8664(key);
      final gcm = AESGCMAsm(key, (block) => aes.encrypt(block));

      try {
        final ciphertextWithTag = gcm.seal(nonce, plaintext, aad);

        // Modify the AAD on decryption
        final modifiedAad = Uint8List.fromList([0xde, 0xad]);
        final decrypted = gcm.open(nonce, ciphertextWithTag, modifiedAad);
        expect(decrypted, isNull);
      } finally {
        gcm.dispose();
      }
    });
  });
}
