import 'package:test/test.dart';
import 'package:tlslite/src/errors.dart';
import 'package:tlslite/src/utils/compression.dart';

class _DummyExtension {
  List<int>? algorithms;

  void changeAlgos(List<int>? algos) {
    algorithms = algos;
  }
}

void main() {
  group('compressionAlgoImpls', () {
    test('exposes expected keys', () {
      expect(compressionAlgoImpls, isNotNull);
      expect(compressionAlgoImpls, contains('brotli_compress'));
      expect(compressionAlgoImpls, contains('brotli_decompress'));
      expect(compressionAlgoImpls, contains('brotli_accepts_limit'));
      expect(compressionAlgoImpls, contains('zstd_compress'));
      expect(compressionAlgoImpls, contains('zstd_decompress'));
      expect(compressionAlgoImpls, contains('zstd_accepts_limit'));
    });

    test('wires zstd decompressor and limit flag', () {
      expect(compressionAlgoImpls['zstd_compress'], isNotNull);
      expect(compressionAlgoImpls['zstd_decompress'], isNotNull);
      expect(compressionAlgoImpls['zstd_accepts_limit'], isTrue);
    });
  });

  group('chooseCompressionSendAlgo', () {
    late _DummyExtension extension;

    setUp(() {
      extension = _DummyExtension();
    });

    test('returns negotiated value when TLS 1.3+ and common algo exists', () {
      extension.changeAlgos([1]);
      final algo = chooseCompressionSendAlgo((3, 4), extension, const ['zlib']);
      expect(algo, equals(1));
    });

    test('returns null for TLS versions earlier than 1.3', () {
      extension.changeAlgos([1]);
      final algo = chooseCompressionSendAlgo((3, 2), extension, const ['zlib']);
      expect(algo, isNull);
    });

    test('returns null when TLS version is missing', () {
      extension.changeAlgos([1]);
      final algo = chooseCompressionSendAlgo(null, extension, const ['zlib']);
      expect(algo, isNull);
    });

    test('selects first common algorithm', () {
      extension.changeAlgos([1, 2]);
      final algo = chooseCompressionSendAlgo(
        (3, 4),
        extension,
        const ['zlib', 'brotli'],
      );
      expect(algo, equals(1));
    });

    test('throws when extension advertises empty list', () {
      extension.changeAlgos([]);
      expect(
        () => chooseCompressionSendAlgo((3, 4), extension, const ['zlib']),
        throwsA(isA<TLSDecodeError>()),
      );
    });

    test('throws when extension advertises null', () {
      extension.changeAlgos(null);
      expect(
        () => chooseCompressionSendAlgo((3, 4), extension, const ['zlib']),
        throwsA(isA<TLSDecodeError>()),
      );
    });

    test('returns null when no accepted algorithms provided', () {
      extension.changeAlgos([1]);
      final algo = chooseCompressionSendAlgo((3, 4), extension, const []);
      expect(algo, isNull);
    });

    test('returns null when there is no common algorithm', () {
      extension.changeAlgos([2]);
      final algo = chooseCompressionSendAlgo((3, 4), extension, const ['zlib']);
      expect(algo, isNull);
    });
  });
}
