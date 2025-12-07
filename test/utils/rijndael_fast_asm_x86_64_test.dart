import 'dart:io' show Platform;
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/rijndael_fast.dart';
import 'package:tlslite/src/utils/rijndael_fast_asm_x86_64.dart';

Uint8List _hex(String s) {
  s = s.replaceAll(' ', '');
  final result = Uint8List(s.length ~/ 2);
  for (int i = 0; i < result.length; i++) {
    result[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return result;
}

String _toHex(Uint8List data) {
  return data.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

class _AesVector {
  final String name;
  final String keyHex;
  final String plaintextHex;
  final String ciphertextHex;

  const _AesVector(
    this.name,
    this.keyHex,
    this.plaintextHex,
    this.ciphertextHex,
  );
}

void main() {
  // Verifica se AES-NI está disponível
  final aesNiAvailable = AesNiSupport.isSupported;

  group('AesNiSupport', () {
    test('isSupported returns bool', () {
      expect(AesNiSupport.isSupported, isA<bool>());
      print('AES-NI support: ${AesNiSupport.isSupported}');
      print('Platform: ${Platform.operatingSystem} ${Platform.version}');
    });

    test('isSupported is consistent', () {
      // Deve retornar o mesmo valor em chamadas subsequentes
      final first = AesNiSupport.isSupported;
      final second = AesNiSupport.isSupported;
      expect(first, equals(second));
    });
  });

  // Pula os testes de encriptação/decriptação se AES-NI não estiver disponível
  group('RijndaelAsmX8664',
      skip: !aesNiAvailable ? 'AES-NI not available' : null, () {
    // Vetores de teste FIPS 197 e outros padrão
    final vectors = <_AesVector>[
      // AES-128 test vectors
      const _AesVector(
        'AES-128 zero block',
        '00000000000000000000000000000000',
        '00000000000000000000000000000000',
        '66e94bd4ef8a2c3b884cfa59ca342b2e',
      ),
      const _AesVector(
        'AES-128 sequential block',
        '000102030405060708090a0b0c0d0e0f',
        '000102030405060708090a0b0c0d0e0f',
        '0a940bb5416ef045f1c39458c653ea5a',
      ),
      const _AesVector(
        'AES-128 FIPS 197 C.1',
        '000102030405060708090a0b0c0d0e0f',
        '00112233445566778899aabbccddeeff',
        '69c4e0d86a7b0430d8cdb78070b4c55a',
      ),
      // AES-192 test vectors
      const _AesVector(
        'AES-192 zero block',
        '000000000000000000000000000000000000000000000000',
        '00000000000000000000000000000000',
        'aae06992acbf52a3e8f4a96ec9300bd7',
      ),
      const _AesVector(
        'AES-192 sequential block',
        '000102030405060708090a0b0c0d0e0f1011121314151617',
        '000102030405060708090a0b0c0d0e0f',
        '0060bffe46834bb8da5cf9a61ff220ae',
      ),
      const _AesVector(
        'AES-192 FIPS 197 C.2',
        '000102030405060708090a0b0c0d0e0f1011121314151617',
        '00112233445566778899aabbccddeeff',
        'dda97ca4864cdfe06eaf70a0ec0d7191',
      ),
      // AES-256 test vectors
      const _AesVector(
        'AES-256 zero block',
        '0000000000000000000000000000000000000000000000000000000000000000',
        '00000000000000000000000000000000',
        'dc95c078a2408989ad48a21492842087',
      ),
      const _AesVector(
        'AES-256 sequential block',
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '000102030405060708090a0b0c0d0e0f',
        '5a6e045708fb7196f02e553d02c3a692',
      ),
      const _AesVector(
        'AES-256 FIPS 197 C.3',
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
        '00112233445566778899aabbccddeeff',
        '8ea2b7ca516745bfeafc49904b496089',
      ),
    ];

    for (final vector in vectors) {
      final key = _hex(vector.keyHex);
      final plaintext = _hex(vector.plaintextHex);
      final ciphertext = _hex(vector.ciphertextHex);

      test('${vector.name} encrypt', () {
        final r = RijndaelAsmX8664(key);
        try {
          final result = r.encrypt(plaintext);
          expect(result, equals(ciphertext),
              reason:
                  'Expected: ${_toHex(ciphertext)}, Got: ${_toHex(result)}');
        } finally {
          r.dispose();
        }
      });

      test('${vector.name} decrypt', () {
        final r = RijndaelAsmX8664(key);
        try {
          final result = r.decrypt(ciphertext);
          expect(result, equals(plaintext),
              reason: 'Expected: ${_toHex(plaintext)}, Got: ${_toHex(result)}');
        } finally {
          r.dispose();
        }
      });

      test('${vector.name} encryptInto / decryptInto', () {
        final r = RijndaelAsmX8664(key);
        final out = Uint8List(16);
        try {
          r.encryptInto(plaintext, out);
          expect(out, equals(ciphertext));

          final out2 = Uint8List(16);
          r.decryptInto(out, out2);
          expect(out2, equals(plaintext));
        } finally {
          r.dispose();
        }
      });
    }

    test('Invalid Key Size (20 bytes)', () {
      final key = Uint8List(20);
      expect(() => RijndaelAsmX8664(key), throwsArgumentError);
    });

    test('Invalid Key Size (15 bytes)', () {
      final key = Uint8List(15);
      expect(() => RijndaelAsmX8664(key), throwsArgumentError);
    });

    test('Encrypt Invalid Block Length', () {
      final key = Uint8List(16);
      final r = RijndaelAsmX8664(key);
      try {
        expect(() => r.encrypt(Uint8List(15)), throwsArgumentError);
        expect(() => r.encrypt(Uint8List(17)), throwsArgumentError);
      } finally {
        r.dispose();
      }
    });

    test('Decrypt Invalid Block Length', () {
      final key = Uint8List(16);
      final r = RijndaelAsmX8664(key);
      try {
        expect(() => r.decrypt(Uint8List(15)), throwsArgumentError);
        expect(() => r.decrypt(Uint8List(17)), throwsArgumentError);
      } finally {
        r.dispose();
      }
    });

    test('Use after dispose throws', () {
      final key = Uint8List(16);
      final plaintext = Uint8List(16);
      final r = RijndaelAsmX8664(key);
      r.dispose();
      expect(() => r.encrypt(plaintext), throwsStateError);
      expect(() => r.decrypt(plaintext), throwsStateError);
    });

    test('Multiple dispose is safe', () {
      final key = Uint8List(16);
      final r = RijndaelAsmX8664(key);
      r.dispose();
      r.dispose(); // Não deve lançar exceção
    });

    test('Roundtrip with random data', () {
      final key = Uint8List(16);
      for (int i = 0; i < 16; i++) {
        key[i] = (i * 17 + 5) & 0xFF;
      }

      final plaintext = Uint8List(16);
      for (int i = 0; i < 16; i++) {
        plaintext[i] = (i * 13 + 7) & 0xFF;
      }

      final r = RijndaelAsmX8664(key);
      try {
        final ciphertext = r.encrypt(plaintext);
        expect(ciphertext, isNot(equals(plaintext))); // Deve ser diferente

        final decrypted = r.decrypt(ciphertext);
        expect(decrypted, equals(plaintext));
      } finally {
        r.dispose();
      }
    });

    test('Multiple blocks with same key', () {
      final key = _hex('000102030405060708090a0b0c0d0e0f');
      final r = RijndaelAsmX8664(key);

      try {
        // Encripta vários blocos
        for (int block = 0; block < 10; block++) {
          final plaintext = Uint8List(16);
          for (int i = 0; i < 16; i++) {
            plaintext[i] = (block * 16 + i) & 0xFF;
          }

          final ciphertext = r.encrypt(plaintext);
          final decrypted = r.decrypt(ciphertext);
          expect(decrypted, equals(plaintext),
              reason: 'Failed at block $block');
        }
      } finally {
        r.dispose();
      }
    });
  });

  // Testes de comparação com RijndaelFast
  group('Comparison with RijndaelFast',
      skip: !aesNiAvailable ? 'AES-NI not available' : null, () {
    test('AES-128 produces same results', () {
      final key = _hex('000102030405060708090a0b0c0d0e0f');
      final plaintext = _hex('00112233445566778899aabbccddeeff');

      final fast = RijndaelFast(key, blockSize: 16);
      final asm = RijndaelAsmX8664(key);

      try {
        final fastCiphertext = fast.encrypt(plaintext);
        final asmCiphertext = asm.encrypt(plaintext);

        expect(asmCiphertext, equals(fastCiphertext),
            reason:
                'Encrypt mismatch: fast=${_toHex(fastCiphertext)}, asm=${_toHex(asmCiphertext)}');

        final fastDecrypted = fast.decrypt(fastCiphertext);
        final asmDecrypted = asm.decrypt(asmCiphertext);

        expect(asmDecrypted, equals(fastDecrypted), reason: 'Decrypt mismatch');
        expect(asmDecrypted, equals(plaintext));
      } finally {
        fast.dispose();
        asm.dispose();
      }
    });

    test('AES-192 produces same results', () {
      final key = _hex('000102030405060708090a0b0c0d0e0f1011121314151617');
      final plaintext = _hex('00112233445566778899aabbccddeeff');

      final fast = RijndaelFast(key, blockSize: 16);
      final asm = RijndaelAsmX8664(key);

      try {
        final fastCiphertext = fast.encrypt(plaintext);
        final asmCiphertext = asm.encrypt(plaintext);

        expect(asmCiphertext, equals(fastCiphertext),
            reason:
                'Encrypt mismatch: fast=${_toHex(fastCiphertext)}, asm=${_toHex(asmCiphertext)}');

        final fastDecrypted = fast.decrypt(fastCiphertext);
        final asmDecrypted = asm.decrypt(asmCiphertext);

        expect(asmDecrypted, equals(fastDecrypted));
        expect(asmDecrypted, equals(plaintext));
      } finally {
        fast.dispose();
        asm.dispose();
      }
    });

    test('AES-256 produces same results', () {
      final key = _hex(
          '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
      final plaintext = _hex('00112233445566778899aabbccddeeff');

      final fast = RijndaelFast(key, blockSize: 16);
      final asm = RijndaelAsmX8664(key);

      try {
        final fastCiphertext = fast.encrypt(plaintext);
        final asmCiphertext = asm.encrypt(plaintext);

        expect(asmCiphertext, equals(fastCiphertext),
            reason:
                'Encrypt mismatch: fast=${_toHex(fastCiphertext)}, asm=${_toHex(asmCiphertext)}');

        final fastDecrypted = fast.decrypt(fastCiphertext);
        final asmDecrypted = asm.decrypt(asmCiphertext);

        expect(asmDecrypted, equals(fastDecrypted));
        expect(asmDecrypted, equals(plaintext));
      } finally {
        fast.dispose();
        asm.dispose();
      }
    });

    test('Multiple random blocks produce same results', () {
      // Testa com várias chaves e blocos aleatórios
      for (int keySize in [16, 24, 32]) {
        final key = Uint8List(keySize);
        for (int i = 0; i < keySize; i++) {
          key[i] = (i * 7 + keySize) & 0xFF;
        }

        final fast = RijndaelFast(key, blockSize: 16);
        final asm = RijndaelAsmX8664(key);

        try {
          for (int block = 0; block < 5; block++) {
            final plaintext = Uint8List(16);
            for (int i = 0; i < 16; i++) {
              plaintext[i] = (block * 16 + i * 3 + keySize) & 0xFF;
            }

            final fastCiphertext = fast.encrypt(plaintext);
            final asmCiphertext = asm.encrypt(plaintext);

            expect(asmCiphertext, equals(fastCiphertext),
                reason: 'Encrypt mismatch at keySize=$keySize, block=$block');

            final asmDecrypted = asm.decrypt(asmCiphertext);
            expect(asmDecrypted, equals(plaintext),
                reason: 'Decrypt mismatch at keySize=$keySize, block=$block');
          }
        } finally {
          fast.dispose();
          asm.dispose();
        }
      }
    });
  });

  // Testes de helper functions
  group('Helper functions',
      skip: !aesNiAvailable ? 'AES-NI not available' : null, () {
    test('encryptBlockAsmX8664', () {
      final key = _hex('000102030405060708090a0b0c0d0e0f');
      final plaintext = _hex('00112233445566778899aabbccddeeff');
      final expected = _hex('69c4e0d86a7b0430d8cdb78070b4c55a');

      final result = encryptBlockAsmX8664(key, plaintext);
      expect(result, equals(expected));
    });

    test('decryptBlockAsmX8664', () {
      final key = _hex('000102030405060708090a0b0c0d0e0f');
      final ciphertext = _hex('69c4e0d86a7b0430d8cdb78070b4c55a');
      final expected = _hex('00112233445566778899aabbccddeeff');

      final result = decryptBlockAsmX8664(key, ciphertext);
      expect(result, equals(expected));
    });
  });

  // Benchmark simples
  group('Performance', skip: !aesNiAvailable ? 'AES-NI not available' : null,
      () {
    test('Benchmark encrypt 10000 blocks', () {
      final key = Uint8List(16);
      final plaintext = Uint8List(16);
      final output = Uint8List(16);
      const iterations = 10000;

      final r = RijndaelAsmX8664(key);
      try {
        final sw = Stopwatch()..start();
        for (int i = 0; i < iterations; i++) {
          r.encryptInto(plaintext, output);
        }
        sw.stop();

        final blocksPerSecond = iterations / (sw.elapsedMicroseconds / 1000000);
        final mbPerSecond = (iterations * 16) /
            (sw.elapsedMicroseconds / 1000000) /
            (1024 * 1024);

        print(
            'AES-NI Encrypt: ${sw.elapsedMicroseconds / iterations} us/block');
        print(
            'AES-NI Encrypt: ${blocksPerSecond.toStringAsFixed(0)} blocks/sec');
        print('AES-NI Encrypt: ${mbPerSecond.toStringAsFixed(2)} MB/sec');
      } finally {
        r.dispose();
      }
    });

    test('Compare performance with RijndaelFast', () {
      final key = Uint8List(16);
      final plaintext = Uint8List(16);
      final output = Uint8List(16);
      const iterations = 10000;

      // RijndaelFast
      final fast = RijndaelFast(key, blockSize: 16);
      final swFast = Stopwatch()..start();
      for (int i = 0; i < iterations; i++) {
        fast.encryptInto(plaintext, output);
      }
      swFast.stop();
      fast.dispose();

      // RijndaelAsmX8664
      final asm = RijndaelAsmX8664(key);
      final swAsm = Stopwatch()..start();
      for (int i = 0; i < iterations; i++) {
        asm.encryptInto(plaintext, output);
      }
      swAsm.stop();
      asm.dispose();

      final fastUsPerBlock = swFast.elapsedMicroseconds / iterations;
      final asmUsPerBlock = swAsm.elapsedMicroseconds / iterations;
      final speedup = fastUsPerBlock / asmUsPerBlock;

      print('RijndaelFast: ${fastUsPerBlock.toStringAsFixed(3)} us/block');
      print('RijndaelAsmX8664: ${asmUsPerBlock.toStringAsFixed(3)} us/block');
      print('Speedup: ${speedup.toStringAsFixed(2)}x');

      // AES-NI deve ser mais rápido (ou pelo menos não muito mais lento)
      // Nota: Em alguns sistemas com overhead de FFI, pode não ser mais rápido
    });
  });
}
