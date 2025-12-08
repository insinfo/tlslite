/// Testes para Montgomery 
/// Compara resultados com BigInt nativo para validação

import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/src/experimental/montgomery_limbs.dart';

void main() {
  group('BN Basic Operations', () {
    test('BN.fromBytes e toBytes round-trip', () {
      final bytes = Uint8List.fromList([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
      final bn = BN.fromBytes(bytes);
      final result = bn.toBytes();
      expect(result, equals(bytes));
    });

    test('BN.fromBytes single byte', () {
      final bytes = Uint8List.fromList([0x42]);
      final bn = BN.fromBytes(bytes);
      expect(bn.d[0], equals(0x42));
      expect(bn.top, equals(1));
    });

    test('BN.fromBytes 4 bytes', () {
      final bytes = Uint8List.fromList([0x12, 0x34, 0x56, 0x78]);
      final bn = BN.fromBytes(bytes);
      expect(bn.d[0], equals(0x12345678));
      expect(bn.top, equals(1));
    });

    test('BN.numBits', () {
      final bn = BN.fromBytes(Uint8List.fromList([0x80]));
      expect(bn.numBits, equals(8));
      
      final bn2 = BN.fromBytes(Uint8List.fromList([0x01, 0x00]));
      expect(bn2.numBits, equals(9));
    });
  });

  group('bnAddWords and bnSubWords', () {
    test('add simple', () {
      final a = Uint32List.fromList([0xFFFFFFFF, 0]);
      final b = Uint32List.fromList([1, 0]);
      final r = Uint32List(2);
      
      final carry = bnAddWords(r, 0, a, 0, b, 0, 2);
      expect(r[0], equals(0));
      expect(r[1], equals(1));
      expect(carry, equals(0));
    });

    test('sub simple', () {
      final a = Uint32List.fromList([0, 1]);
      final b = Uint32List.fromList([1, 0]);
      final r = Uint32List(2);
      
      final borrow = bnSubWords(r, 0, a, 0, b, 0, 2);
      expect(r[0], equals(0xFFFFFFFF));
      expect(r[1], equals(0));
      expect(borrow, equals(0));
    });
  });

  group('Montgomery Context', () {
    test('n0inv calculation correctness', () {
      // Para módulo típico RSA (ímpar)
      final mod = BN.fromBytes(Uint8List.fromList([
        0xE9, 0x5F, 0x7A, 0x3B, // Alguns bytes ímpares
        0xC1, 0xD2, 0xE3, 0xF5,
      ]));
      
      final ctx = MontgomeryCtx.fromModulus(mod);
      
      // Verifica que n0 * n[0] ≡ -1 (mod 2^32)
      final product = (ctx.n0 * mod.d[0]) & 0xFFFFFFFF;
      expect(product, equals(0xFFFFFFFF), reason: 'n0 * n[0] should be -1 mod 2^32');
    });
  });

  group('Montgomery Multiplication', () {
    test('montMul basic correctness', () {
      // Módulo pequeno para teste
      final mod = BN.fromBytes(Uint8List.fromList([
        0x00, 0x00, 0x00, 0xFD, // 253 (primo)
      ]));
      
      final ctx = MontgomeryCtx.fromModulus(mod);
      
      final a = BN.fromBytes(Uint8List.fromList([5]));
      final b = BN.fromBytes(Uint8List.fromList([7]));
      
      // Converte para Montgomery form
      final aMont = BN(mod.top);
      final bMont = BN(mod.top);
      bnToMont(aMont, a, ctx);
      bnToMont(bMont, b, ctx);
      
      // Multiplica
      final resultMont = BN(mod.top);
      bnMontMul(resultMont, aMont, bMont, ctx);
      
      // Converte de volta
      final result = BN(mod.top);
      bnFromMont(result, resultMont, ctx);
      
      // Esperado: 5 * 7 mod 253 = 35
      expect(result.d[0], equals(35));
    });
  });

  group('ModPow vs BigInt', () {
    test('modPow small numbers', () {
      final base = BigInt.from(3);
      final exp = BigInt.from(7);
      final mod = BigInt.from(11);
      
      // BigInt reference
      final expected = base.modPow(exp, mod);
      
      // Nossa implementação
      final baseBN = BN.fromBytes(_bigIntToBytes(base));
      final expBN = BN.fromBytes(_bigIntToBytes(exp));
      final modBN = BN.fromBytes(_bigIntToBytes(mod));
      
      final mont = MontgomeryModPow(modBN);
      final result = mont.modPow(baseBN, expBN);
      
      final resultBigInt = _bytesToBigInt(result.toBytes());
      expect(resultBigInt, equals(expected));
    });

    test('modPow medium numbers', () {
      final base = BigInt.parse('123456789');
      final exp = BigInt.parse('65537');
      final mod = BigInt.parse('0xFFFFFFFFFFFFFFFF'); // 2^64 - 1
      
      // BigInt reference
      final expected = base.modPow(exp, mod);
      
      // Nossa implementação
      final baseBN = BN.fromBytes(_bigIntToBytes(base));
      final expBN = BN.fromBytes(_bigIntToBytes(exp));
      final modBN = BN.fromBytes(_bigIntToBytes(mod));
      
      final mont = MontgomeryModPow(modBN);
      final result = mont.modPow(baseBN, expBN);
      
      final resultBigInt = _bytesToBigInt(result.toBytes());
      expect(resultBigInt, equals(expected));
    });

    test('modPow RSA-like (256-bit)', () {
      // Módulo 256-bit típico (gerado como produto de dois primos)
      final mod = BigInt.parse(
        '0xD4BCD52406F2244BA94D6D0C8BFCF43C'
        '13E8F14E4D6E7B4A0E8F9C5B3A2D1E0F1'
      );
      final base = BigInt.parse('0x123456789ABCDEF0123456789ABCDEF0');
      final exp = BigInt.from(65537);
      
      // BigInt reference
      final expected = base.modPow(exp, mod);
      
      // Nossa implementação
      final baseBN = BN.fromBytes(_bigIntToBytes(base));
      final expBN = BN.fromBytes(_bigIntToBytes(exp));
      final modBN = BN.fromBytes(_bigIntToBytes(mod));
      
      final mont = MontgomeryModPow(modBN);
      final result = mont.modPow(baseBN, expBN);
      
      final resultBigInt = _bytesToBigInt(result.toBytes());
      expect(resultBigInt, equals(expected));
    });

    test('modPowBytes convenience function', () {
      final base = BigInt.parse('123456');
      final exp = BigInt.from(17);
      final mod = BigInt.parse('0x10001'); // 65537
      
      final expected = base.modPow(exp, mod);
      
      final resultBytes = modPowBytes(
        _bigIntToBytes(base),
        _bigIntToBytes(exp),
        _bigIntToBytes(mod),
      );
      
      final resultBigInt = _bytesToBigInt(resultBytes);
      expect(resultBigInt, equals(expected));
    });
  });

  group('Edge Cases', () {
    test('exp = 0 should return 1', () {
      final base = BN.fromBytes(Uint8List.fromList([42]));
      final exp = BN(1);
      exp.zero();
      final mod = BN.fromBytes(Uint8List.fromList([0x65])); // 101
      
      final mont = MontgomeryModPow(mod);
      final result = mont.modPow(base, exp);
      
      expect(result.d[0], equals(1));
    });

    test('exp = 1 should return base mod n', () {
      final base = BN.fromBytes(Uint8List.fromList([200]));
      final exp = BN.fromBytes(Uint8List.fromList([1]));
      final mod = BN.fromBytes(Uint8List.fromList([101]));
      
      final mont = MontgomeryModPow(mod);
      final result = mont.modPow(base, exp);
      
      // 200 mod 101 = 99
      expect(result.d[0], equals(99));
    });
  });
}

/// Converte BigInt para bytes big-endian
Uint8List _bigIntToBytes(BigInt n) {
  if (n == BigInt.zero) return Uint8List(1);
  
  var hex = n.toRadixString(16);
  if (hex.length % 2 != 0) hex = '0$hex';
  
  final bytes = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}

/// Converte bytes big-endian para BigInt
BigInt _bytesToBigInt(Uint8List bytes) {
  if (bytes.isEmpty) return BigInt.zero;
  final hex = bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  return BigInt.parse(hex, radix: 16);
}
