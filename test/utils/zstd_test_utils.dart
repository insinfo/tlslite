import 'dart:typed_data';

import 'package:tlslite/src/utils/zstd/dictionary.dart';
import 'package:tlslite/src/utils/zstd/sequences.dart';

ZstdDictionary buildSeededDictionary() {
  final lengths = Uint8List(256);
  lengths['X'.codeUnitAt(0)] = 2;
  lengths['Y'.codeUnitAt(0)] = 3;
  lengths['Z'.codeUnitAt(0)] = 3;
  lengths['W'.codeUnitAt(0)] = 2;
  lengths['V'.codeUnitAt(0)] = 2;
  lengths['U'.codeUnitAt(0)] = 2;

  return ZstdDictionary(
    dictId: 0x0C011EC7,
    content: Uint8List.fromList('UVWXYZUVWXYZUVWXYZUVWXYZ'.codeUnits),
    huffmanCodeLengths: lengths,
    huffmanMaxSymbol: 'Z'.codeUnitAt(0),
    sequenceTables: SequenceDecodingTables(
      literalLengthTable: defaultLiteralLengthDecodingTable,
      offsetTable: defaultOffsetDecodingTable,
      matchLengthTable: defaultMatchLengthDecodingTable,
    ),
  );
}
