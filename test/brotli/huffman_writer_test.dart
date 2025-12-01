import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/bit_stream_writer.dart';
import 'package:tlslite/src/utils/brotlidecpy/bit_reader.dart';
import 'package:tlslite/src/utils/brotlidecpy/decode.dart';
import 'package:tlslite/src/utils/brotlidecpy/huffman.dart';
import 'package:tlslite/src/utils/brotlidecpy/huffman_builder.dart';
import 'package:tlslite/src/utils/brotlidecpy/huffman_writer.dart';

void main() {
  test('writer output round-trips through decoder', () {
    // Valid Huffman code lengths for 8 symbols
    // Sum of 2^(-len) must equal 1:
    // 1*2^(-2) + 2*2^(-3) + 4*2^(-4) + 1*2^(-4) = 0.25 + 0.25 + 0.25 + 0.0625 = 0.8125 - wrong
    // Let's use: [1, 2, 3, 4, 4, 4, 4, 4] - 1*2^-1 + 1*2^-2 + 1*2^-3 + 5*2^-4 = 0.5 + 0.25 + 0.125 + 0.3125 = 1.1875 - wrong
    // Let's use: [2, 2, 3, 3, 3, 3, 4, 4] - 2*2^-2 + 4*2^-3 + 2*2^-4 = 0.5 + 0.5 + 0.125 = 1.125 - wrong
    // Let's use: [2, 2, 2, 2, 3, 3, 3, 3] - 4*2^-2 + 4*2^-3 = 1.0 + 0.5 = 1.5 - wrong
    // Let's use: [3, 3, 3, 3, 3, 3, 3, 3] - 8*2^-3 = 1.0 - CORRECT!
    final codeLengths = Uint8List.fromList([
      3, 3, 3, 3, 3, 3, 3, 3,
    ]);
    final writer = BitStreamWriter();
    BrotliHuffmanTreeWriter.writeTree(codeLengths, writer);
    final canonicalCodes = convertBitDepthsToSymbols(codeLengths);
    final sample = [0, 1, 2, 3, 4, 5, 6, 7];
    for (final symbol in sample) {
      writer.writeBits(canonicalCodes[symbol], codeLengths[symbol]);
    }
    writer.alignToByte();

    final encoded = writer.takeBytes();
    print('encoded bytes: ' + encoded.map((b) => b.toRadixString(16).padLeft(2, '0')).join(' '));
    final debugReader = BrotliBitReader(Uint8List.fromList(encoded));
    print('first 20 bits: ' +
      List<int>.generate(20, (_) => debugReader.read_bits(1)).join());
    final peekReader = BrotliBitReader(Uint8List.fromList(encoded));
    peekReader.read_bits(2);
    final peekVal = peekReader.read_bits(4, bits_to_skip: 0);
    print('first peek nibble: $peekVal');
    final reader = BrotliBitReader(encoded);
    final table = List<HuffmanCode>.generate(
      huffmanMaxTableSize,
      (_) => HuffmanCode(0, 0),
    );
    final tableSize = readHuffmanCode(codeLengths.length, table, 0, reader);
    expect(tableSize, greaterThan(0));

    final decoded = <int>[];
    for (var i = 0; i < sample.length; i++) {
      decoded.add(readSymbol(table, 0, reader));
    }
    expect(decoded, equals(sample));
  });

  test('writer handles long zero/non-zero runs', () {
    final counts = List<int>.filled(48, 0);
    counts[0] = 40;
    counts[5] = 20;
    counts[10] = 10;
    counts[20] = 5;
    counts[30] = 3;
    counts[40] = 2;
    final codeLengths = buildLimitedHuffmanCodeLengths(counts, counts.length, MAX_LENGTH);
    final writer = BitStreamWriter();
    BrotliHuffmanTreeWriter.writeTree(codeLengths, writer);

    final canonicalCodes = convertBitDepthsToSymbols(codeLengths);
    final payload = [0, 5, 10, 20, 30, 40, 0, 5];
    for (final symbol in payload) {
      if (codeLengths[symbol] == 0) {
        fail('Symbol $symbol has zero code length');
      }
      writer.writeBits(canonicalCodes[symbol], codeLengths[symbol]);
    }
    writer.alignToByte();

    final reader = BrotliBitReader(writer.takeBytes());
    final table = List<HuffmanCode>.generate(
      huffmanMaxTableSize,
      (_) => HuffmanCode(0, 0),
    );
    final tableSize = readHuffmanCode(codeLengths.length, table, 0, reader);
    expect(tableSize, greaterThan(0));

    final decoded = <int>[];
    for (var i = 0; i < payload.length; i++) {
      decoded.add(readSymbol(table, 0, reader));
    }
    expect(decoded, equals(payload));
  });
}
