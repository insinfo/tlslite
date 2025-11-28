import 'dart:convert';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/chacha20_poly1305.dart';

void main() {
  group('ChaCha20-Poly1305', () {
    test('constructor accepts 32-byte key', () {
      expect(() => Chacha20Poly1305(Uint8List(32), 'python'), returnsNormally);
    });

    test('constructor rejects invalid key size', () {
      expect(
          () => Chacha20Poly1305(Uint8List(16), 'python'), throwsArgumentError);
    });

    test('constructor rejects unsupported implementation', () {
      expect(() => Chacha20Poly1305(Uint8List(32), 'pycrypto'),
          throwsArgumentError);
    });

    test('seal matches RFC 7539 vector', () {
      final key = hex(
        '808182838485868788898a8b8c8d8e8f'
        '909192939495969798999a9b9c9d9e9f',
      );
      final nonce = hex('070000004041424344454647');
      final aad = hex('50515253c0c1c2c3c4c5c6c7');
      final plaintext = asciiBytes(
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
      );
      final aead = Chacha20Poly1305(key, 'python');
      final result = aead.seal(nonce, plaintext, aad);
      expect(
          result,
          equals(hex(
            'd31a8d34648e60db7b86afbc53ef7ec2'
            'a4aded51296e08fea9e2b5a736ee62d6'
            '3dbea45e8ca9671282fafb69da92728b'
            '1a71de0a9e060b2905d6a5b67ecd3b36'
            '92ddbd7f2d778b8c9803aee328091b58'
            'fab324e4fad675945585808b4831d7bc'
            '3ff4def08e4b7a9de576d26586cec64b'
            '61161ae10b594f09e26a7e902ecbd0600691',
          )));
    });

    test('seal throws with invalid nonce length', () {
      final aead = Chacha20Poly1305(Uint8List(32), 'python');
      expect(() => aead.seal(Uint8List(16), Uint8List(0), Uint8List(0)),
          throwsArgumentError);
    });

    test('open matches RFC 7539 vector', () {
      final key = hex(
        '1c9240a5eb55d38af333888604f6b5f0'
        '473917c1402b80099dca5cbc207075c0',
      );
      final nonce = hex('000000000102030405060708');
      final aad = hex('f33388860000000000004e91');
      final ciphertext = hex(
        '64a0861575861af460f062c79be643bd'
        '5e805cfd345cf389f108670ac76c8cb2'
        '4c6cfc18755d43eea09ee94e382d26b0'
        'bdb7b73c321b0100d4f03b7f355894cf'
        '332f830e710b97ce98c8a84abd0b9481'
        '14ad176e008d33bd60f982b1ff37c855'
        '9797a06ef4f0ef61c186324e2b350638'
        '3606907b6a7c02b0f9f6157b53c867e4'
        'b9166c767b804d46a59b5216cde7a4e9'
        '9040c5a40433225ee282a1b0a06c523e'
        'af4534d7f83fa1155b0047718cbc546a'
        '0d072b04b3564eea1b422273f548271a'
        '0bb2316053fa76991955ebd63159434e'
        'cebb4e466dae5a1073a6727627097a10'
        '49e617d91d361094fa68f0ff77987130'
        '305beaba2eda04df997b714d6c6f2c29'
        'a6ad5cb4022b02709b',
      );
      final tag = hex('eead9d67890cbb22392336fea1851f38');
      final aead = Chacha20Poly1305(key, 'python');
      final combined = Uint8List(ciphertext.length + tag.length)
        ..setRange(0, ciphertext.length, ciphertext)
        ..setRange(ciphertext.length, ciphertext.length + tag.length, tag);
      final plaintext = aead.open(nonce, combined, aad);
      const expected =
          'Internet-Drafts are draft documents valid for a maximum of six months '
          'and may be updated, replaced, or obsoleted by other documents at any time. '
          'It is inappropriate to use Internet-Drafts as reference material or to cite '
          'them other than as /\u201cwork in progress./\u201d';
      expect(plaintext, equals(asciiBytes(expected)));
    });

    test('open throws with invalid nonce length', () {
      final aead = Chacha20Poly1305(Uint8List(32), 'python');
      expect(() => aead.open(Uint8List(8), Uint8List(16), Uint8List(0)),
          throwsArgumentError);
    });

    test('open returns null when ciphertext too short', () {
      final aead = Chacha20Poly1305(Uint8List(32), 'python');
      expect(aead.open(Uint8List(12), Uint8List(15), Uint8List(0)), isNull);
    });

    test('open returns null when tag mismatches', () {
      final aead = Chacha20Poly1305(Uint8List(32), 'python');
      expect(aead.open(Uint8List(12), Uint8List(32), Uint8List(0)), isNull);
    });
  });
}

Uint8List asciiBytes(String value) => Uint8List.fromList(utf8.encode(value));

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
