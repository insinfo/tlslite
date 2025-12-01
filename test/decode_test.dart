import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/src/utils/brotlidecpy/dec/BrotliInputStream.dart';
import 'package:tlslite/src/utils/brotlidecpy/dec/State.dart';

Uint8List readUniBytes(String s) {
  List<int> bytes = [];
  for (int i = 0; i < s.length; i++) {
    bytes.add(s.codeUnitAt(i) & 0xFF);
  }
  return Uint8List.fromList(bytes);
}

void main() {
  Uint8List decompress(Uint8List data, bool byByte) {
    final output = <int>[];
    final input = ByteArrayInputStream(data);
    final brotliInput = BrotliInputStream(input);
    if (byByte) {
      while (true) {
        int next = brotliInput.readByte();
        if (next == -1) {
          break;
        }
        output.add(next);
      }
    } else {
      final buffer = Uint8List(65536);
      while (true) {
        int len = brotliInput.read(buffer, 0, buffer.length);
        if (len <= 0) {
          break;
        }
        output.addAll(buffer.sublist(0, len));
      }
    }
    brotliInput.close();
    return Uint8List.fromList(output);
  }

  void checkDecodeResource(String expected, String compressed) {
    final expectedBytes = readUniBytes(expected);
    final compressedBytes = readUniBytes(compressed);
    final actual = decompress(compressedBytes, false);
    expect(actual, equals(expectedBytes));
    final actualByByte = decompress(compressedBytes, true);
    expect(actualByByte, equals(expectedBytes));
  }

  test('testEmpty', () {
    checkDecodeResource("", "\u0006");
  });

  test('testX', () {
    checkDecodeResource("X", "\u000B\u0000\u0080X\u0003");
  });

  test('testX10Y10', () {
    checkDecodeResource(
        "XXXXXXXXXXYYYYYYYYYY",
        "\u001B\u0013\u0000\u0000\u00A4\u00B0\u00B2\u00EA\u0081G\u0002\u008A");
  });

  test('testX64', () {
    checkDecodeResource(
        "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "\u001B?\u0000\u0000\$\u00B0\u00E2\u0099\u0080\u0012");
  });

  test('testUkkonooa', () {
    checkDecodeResource(
        "ukko nooa, ukko nooa oli kunnon mies, kun han meni saunaan, "
            + "pisti laukun naulaan, ukko nooa, ukko nooa oli kunnon mies.",
        "\u001Bv\u0000\u0000\u0014J\u00AC\u009Bz\u00BD\u00E1\u0097\u009D\u007F\u008E\u00C2\u0082"
            + "6\u000E\u009C\u00E0\u0090\u0003\u00F7\u008B\u009E8\u00E6\u00B6\u0000\u00AB\u00C3\u00CA"
            + "\u00A0\u00C2\u00DAf6\u00DC\u00CD\u0080\u008D.!\u00D7n\u00E3\u00EAL\u00B8\u00F0\u00D2"
            + "\u00B8\u00C7\u00C2pM:\u00F0i~\u00A1\u00B8Es\u00AB\u00C4W\u001E");
  });

  test('testFox', () {
    checkDecodeResource(
        "The quick brown fox jumps over the lazy dog",
        "\u001B*\u0000\u0000\u0004\u0004\u00BAF:\u0085\u0003\u00E9\u00FA\f\u0091\u0002H\u0011,"
            + "\u00F3\u008A:\u00A3V\u007F\u001A\u00AE\u00BF\u00A4\u00AB\u008EM\u00BF\u00ED\u00E2\u0004K"
            + "\u0091\u00FF\u0087\u00E9\u001E");
  });
}
