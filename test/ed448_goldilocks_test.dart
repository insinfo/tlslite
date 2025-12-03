import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/src/ed448/ed448.dart' as ed448;
import 'package:tlslite/src/ed448/src/ed448_point.dart' as curve;
import 'package:tlslite/src/ed448/src/fp448.dart' as fp;
import 'package:tlslite/src/ed448/src/scalar448.dart';

void main() {
  // Helper to parse hex string into bytes
  Uint8List hexToBytes(String hex) {
    final cleaned = hex.replaceAll(RegExp(r"\s"), "");
    final bytes = <int>[];
    for (var i = 0; i < cleaned.length; i += 2) {
      bytes.add(int.parse(cleaned.substring(i, i + 2), radix: 16));
    }
    return Uint8List.fromList(bytes);
  }

  Uint32List hexToField(String hex) {
    final bytes = hexToBytes(hex);
    if (bytes.length != 56) {
      throw ArgumentError('Field elements must be 56 bytes, got ${bytes.length}');
    }
    final little = Uint8List(56);
    for (var i = 0; i < 56; i++) {
      little[i] = bytes[55 - i];
    }
    return fp.Fp448.decode(little);
  }

  String fieldToHex(Uint32List value) {
    final little = fp.Fp448.encode(value);
    final buffer = StringBuffer();
    for (var i = 55; i >= 0; i--) {
      buffer.write(little[i].toRadixString(16).padLeft(2, '0'));
    }
    return buffer.toString();
  }

  curve.Ed448Point pointFromHex(String xHex, String yHex) {
    final x = hexToField(xHex);
    final y = hexToField(yHex);
    return curve.Ed448Point.fromAffine(x, y);
  }

  group('Ed448 Goldilocks vectors', () {
    test('decompress/compress roundtrip for known vector', () {
      // From Rust test: bytes = hex!("649c6a53...780")
      final bytes = hexToBytes(
          '649c6a53b109897d962d033f23d01fd4e1053dddf3746d2ddce9bd66aea38ccf'
          'c3df061df03ca399eb806312ab3037c0c31523142956ada780');
      expect(bytes.length, equals(57));
      final pk = ed448.Ed448PublicKeyImpl(bytes);
      expect(pk.bytes, equals(bytes));
      final point = curve.Ed448Point.decompress(bytes);
      expect(point, isNotNull);
      expect(point!.compress(), equals(bytes));
    });

    test('decompress/compress identity-like vector', () {
      final bytes = Uint8List(57);
      bytes[0] = 0x01;
      final pk = ed448.Ed448PublicKeyImpl(bytes);
      final enc = pk.bytes;
      expect(enc, equals(bytes));

      final point = curve.Ed448Point.decompress(enc);
      expect(point, isNotNull);
      expect(point!.isIdentity, isTrue);
      expect(point.isOnCurve(), isTrue);
    });

    test('decompress/compress basepoint', () {
      final generator = curve.Ed448Point.generator;
      final compressed = generator.compress();
      final decompressed = curve.Ed448Point.decompress(compressed);
      expect(decompressed, isNotNull);
      expect(decompressed, equals(generator));

      final pk = ed448.Ed448PublicKeyImpl(compressed);
      expect(pk.bytes, equals(compressed));
    });

    test('is_on_curve for identity', () {
      final bytes = Uint8List(57);
      bytes[0] = 1; // y = 1, x = 0 -> identity
      final pk = ed448.Ed448PublicKeyImpl(bytes);
      expect(pk.bytes, equals(bytes));
      final point = curve.Ed448Point.decompress(bytes);
      expect(point, isNotNull);
      expect(point!.isOnCurve(), isTrue);
    });

    test('legacy and RFC base points decode correctly', () {
      final legacyX =
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa955555555555555555555555555555555555555555555555555555555';
      final legacyY =
        'ae05e9634ad7048db359d6205086c2b0036ed7a035884dd7b7e36d728ad8c4b80d6565833a2a3098bbbcb2bed1cda06bdaeafbcdea9386ed';
      final rfcX =
        '4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e';
      final rfcY =
        '693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14';

      final legacyBase = pointFromHex(legacyX, legacyY);
      final rfcBase = pointFromHex(rfcX, rfcY);

      expect(legacyBase.isOnCurve(), isTrue);
      expect(rfcBase.isOnCurve(), isTrue);
      expect(legacyBase, isNot(equals(rfcBase)));
      expect(curve.Ed448Point.generator, equals(rfcBase));
    });

    test('compress/decompress generator round trip', () {
      final compressed = curve.Ed448Point.generator.compress();
      final decoded = curve.Ed448Point.decompress(compressed);
      expect(decoded, equals(curve.Ed448Point.generator));
    });

    test('isogeny equivalence evidence', () {
        final xHex =
          '4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e';
        final yHex =
          '693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14';
      final point = pointFromHex(xHex, yHex);
      final doubleTwice = point.double_().double_();
      expect(doubleTwice.isOnCurve(), isTrue);
    });

    test('torsion-free check', () {
      final generator = curve.Ed448Point.generator;
      // [order]G = identity
      final mul = generator.scalarMul(Scalar448.order);
      expect(mul.isIdentity, isTrue);

      final torsionBytes = hexToBytes(
          '13b6714c7a5f53101bbec88f2f17cd30f42e37fae363a5474efb4197ed6005df'
          '5861ae178a0c2c16ad378b7befed0d0904b7ced35e9f674180');
      final torsionPoint = curve.Ed448Point.decompress(torsionBytes);
      expect(torsionPoint, isNotNull);
      final torsionMul = torsionPoint!.scalarMul(Scalar448.order);
      expect(torsionMul.isIdentity, isFalse);
    });

    test('decompress/compress random vector', () {
      // Use a random 57-byte vector (not guaranteed to be valid)
      final bytes = Uint8List.fromList(List.generate(57, (i) => i));
      expect(() => ed448.Ed448PublicKeyImpl(bytes), throwsArgumentError);
      expect(curve.Ed448Point.decompress(bytes), isNull);
    });

    test('just decompress vectors', () {
      final bytes = hexToBytes(
          '649c6a53b109897d962d033f23d01fd4e1053dddf3746d2ddce9bd66aea38ccf'
          'c3df061df03ca399eb806312ab3037c0c31523142956ada780');
      final decompressed = curve.Ed448Point.decompress(bytes);
      expect(decompressed, isNotNull);
      final (x, y) = decompressed!.toAffine();
      expect(
        fieldToHex(x),
        equals('39c41cea305d737df00de8223a0d5f4d48c8e098e16e9b4b2f38ac353262e119cb5ff2afd6d02464702d9d01c9921243fc572f9c718e2527'),
      );
      expect(
        fieldToHex(y),
        equals('a7ad5629142315c3c03730ab126380eb99a33cf01d06dfc3cf8ca3ae66bde9dc2d6d74f3dd3d05e1d41fd0233f032d967d8909b1536a9c64'),
      );

        final identityBytes = Uint8List(57)..[0] = 1;
      final identityPoint = curve.Ed448Point.decompress(identityBytes);
      expect(identityPoint, isNotNull);
      final (ix, iy) = identityPoint!.toAffine();
      expect(fieldToHex(ix), equals('0' * 112));
      expect(fieldToHex(iy), equals(('0' * 111) + '1'));
    });

    test('sign/verify roundtrip with both generators', () {
      final seed = Uint8List.fromList(List<int>.generate(57, (i) => (i * 7) & 0xff));
      final message = Uint8List.fromList(List<int>.generate(32, (i) => i));

      final legacyKey = ed448.Ed448PrivateKeyImpl.fromSeed(
        seed,
        generator: ed448.Ed448Generator.legacy,
      );
      final legacySig = legacyKey.sign(message);
      final legacyPk = legacyKey.publicKey;

      expect(legacyPk.verify(message, legacySig), isTrue);
      expect(
        legacyPk.verify(
          message,
          legacySig,
          enableLegacyFallback: false,
        ),
        isFalse,
      );

      final rfcKey = ed448.Ed448PrivateKeyImpl.fromSeed(
        seed,
        generator: ed448.Ed448Generator.rfc8032,
      );
      final rfcSig = rfcKey.sign(message);
      final rfcPk = rfcKey.publicKey;

      expect(
        rfcPk.verify(
          message,
          rfcSig,
          enableLegacyFallback: false,
        ),
        isTrue,
      );
    });
  });
}
