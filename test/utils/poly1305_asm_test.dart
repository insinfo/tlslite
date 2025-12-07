// dart format width=5000
// Testes para Poly1305 otimizado

import 'dart:typed_data';
import 'package:test/test.dart';

import 'package:tlslite/src/utils/poly1305_fast.dart';
import 'package:tlslite/src/utils/poly1305.dart' as original;

void main() {
  group('Poly1305Asm', () {
    test('tag de dados vazios', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final data = Uint8List(0);

      final poly = Poly1305Asm(key);
      final result = poly.createTag(data);

      // Compara com implementação original
      final origPoly = original.Poly1305(key);
      final expected = origPoly.createTag(data);

      expect(result, equals(expected));
    });

    test('tag de dados curtos', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i + 1));
      final data = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);

      final poly = Poly1305Asm(key);
      final result = poly.createTag(data);

      final origPoly = original.Poly1305(key);
      final expected = origPoly.createTag(data);

      expect(result, equals(expected));
    });

    test('tag de bloco completo (16 bytes)', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i * 2));
      final data = Uint8List.fromList(List.generate(16, (i) => i));

      final poly = Poly1305Asm(key);
      final result = poly.createTag(data);

      final origPoly = original.Poly1305(key);
      final expected = origPoly.createTag(data);

      expect(result, equals(expected));
    });

    test('tag de múltiplos blocos', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final data = Uint8List.fromList(List.generate(64, (i) => i & 0xFF));

      final poly = Poly1305Asm(key);
      final result = poly.createTag(data);

      final origPoly = original.Poly1305(key);
      final expected = origPoly.createTag(data);

      expect(result, equals(expected));
    });

    test('tag de dados grandes', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final data = Uint8List.fromList(List.generate(1000, (i) => i & 0xFF));

      final poly = Poly1305Asm(key);
      final result = poly.createTag(data);

      final origPoly = original.Poly1305(key);
      final expected = origPoly.createTag(data);

      expect(result, equals(expected));
    });

    test('atualização incremental', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final data1 = Uint8List.fromList([1, 2, 3, 4, 5]);
      final data2 = Uint8List.fromList([6, 7, 8, 9, 10]);
      final fullData = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

      // Incremental
      final poly1 = Poly1305Asm(key);
      poly1.update(data1);
      poly1.update(data2);
      final result1 = poly1.finalize();

      // One-shot
      final poly2 = Poly1305Asm(key);
      final result2 = poly2.createTag(fullData);

      expect(result1, equals(result2));
    });

    test('reset funciona', () {
      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final data1 = Uint8List.fromList([1, 2, 3]);
      final data2 = Uint8List.fromList([4, 5, 6]);

      final poly = Poly1305Asm(key);

      // Primeira tag
      poly.update(data1);
      poly.finalize();

      // Reset e segunda tag
      poly.reset();
      poly.update(data2);
      final result = poly.finalize();

      // Deve ser igual a calcular direto
      final poly2 = Poly1305Asm(key);
      final expected = poly2.createTag(data2);

      expect(result, equals(expected));
    });
  });

  group('RFC 8439 Test Vectors', () {
    test('Test Vector #1 from RFC 8439', () {
      // Key
      final key = Uint8List.fromList([
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33,
        0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8,
        0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd,
        0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b,
      ]);

      // Message: "Cryptographic Forum Research Group"
      final data = Uint8List.fromList([
        0x43, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x67, 0x72,
        0x61, 0x70, 0x68, 0x69, 0x63, 0x20, 0x46, 0x6f,
        0x72, 0x75, 0x6d, 0x20, 0x52, 0x65, 0x73, 0x65,
        0x61, 0x72, 0x63, 0x68, 0x20, 0x47, 0x72, 0x6f,
        0x75, 0x70,
      ]);

      // Expected tag
      final expectedTag = Uint8List.fromList([
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6,
        0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27, 0xa9,
      ]);

      final poly = Poly1305Asm(key);
      final result = poly.createTag(data);

      expect(result, equals(expectedTag));
    });
  });
}
