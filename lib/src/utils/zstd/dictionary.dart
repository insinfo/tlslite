import 'dart:typed_data';

import 'byte_reader.dart';
import 'constants.dart';
import 'frame_header.dart';
import 'fse.dart';
import 'literals.dart';
import 'sequences.dart';

/// Supplies dictionary instances for a given dictionary ID.
typedef ZstdDictionaryProvider = ZstdDictionary? Function(int dictId);

class ZstdDictionary {
  ZstdDictionary({
    required this.dictId,
    required Uint8List content,
    this.huffmanTable,
    this.sequenceTables,
    List<int>? initialPrevOffsets,
  })  : content = Uint8List.fromList(content),
        initialPrevOffsets = _normalizePrevOffsets(initialPrevOffsets);

  /// Identifier advertised inside Zstd frames.
  final int dictId;

  /// Raw history bytes that seed the sliding window before decoding the first block.
  final Uint8List content;

  /// Optional Huffman table that can satisfy `repeat` literal sections before
  /// the stream transmits a table explicitly.
  final HuffmanDecodingTable? huffmanTable;

  /// Optional sequence decoding tables used when the first compressed block
  /// encodes LL/OF/ML descriptors in `repeat` mode.
  final SequenceDecodingTables? sequenceTables;

  /// Previous offsets that should be used before the first sequence header sends
  /// its own values. Defaults to the Zstd spec values `[1, 4, 8]`.
  final List<int> initialPrevOffsets;

  /// Convenience helper for raw dictionaries that only contain history bytes.
  factory ZstdDictionary.raw({
    required int dictId,
    required Uint8List content,
  }) {
    return ZstdDictionary(dictId: dictId, content: content);
  }

  static List<int> _normalizePrevOffsets(List<int>? offsets) {
    if (offsets == null) {
      return const [1, 4, 8];
    }
    if (offsets.length != 3) {
      throw ArgumentError.value(offsets.length, 'offsets', 'Zstd dictionaries require exactly three previous offsets');
    }
    return List<int>.from(offsets);
  }
}

/// Parses dictionary bytes produced by `zstd --train` (a formatted dictionary)
/// or falls back to treating the input as a raw history buffer when no magic
/// number is present. Raw dictionaries require [fallbackDictId].
ZstdDictionary parseZstdDictionary(
  Uint8List bytes, {
  int? fallbackDictId,
}) {
  if (_hasDictionaryMagic(bytes)) {
    return _parseFormattedDictionary(bytes);
  }

  final dictId = fallbackDictId;
  if (dictId == null || dictId == 0) {
    throw ZstdFrameFormatException(
      'Dictionary bytes do not start with the Zstd dictionary magic number. '
      'Pass fallbackDictId to load raw history dictionaries.',
    );
  }
  return ZstdDictionary(dictId: dictId, content: bytes);
}

bool _hasDictionaryMagic(Uint8List bytes) {
  if (bytes.length < 4) {
    return false;
  }
  final magic = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24);
  return magic == zstdDictionaryMagic;
}

ZstdDictionary _parseFormattedDictionary(Uint8List bytes) {
  final reader = ZstdByteReader(bytes);
  if (reader.remaining < 8) {
    throw ZstdFrameFormatException('Dictionary is too small to contain headers');
  }
  final magic = reader.readUint32LE();
  if (magic != zstdDictionaryMagic) {
    throw ZstdFrameFormatException('Unexpected dictionary magic 0x${magic.toRadixString(16)}');
  }

  final dictId = reader.readUint32LE();
  if (dictId == 0) {
    throw ZstdFrameFormatException('Dictionaries must advertise a non-zero ID');
  }

  final huffmanPayload = _readStandaloneHuffmanPayload(reader);
  final huffmanTable = readHuffmanTable(huffmanPayload).table;

  final offsetDescriptor = readFseTable(reader, ofBaseline.length - 1);
  final matchDescriptor = readFseTable(reader, mlBaseline.length - 1);
  final literalDescriptor = readFseTable(reader, llBaseline.length - 1);

  final sequenceTables = SequenceDecodingTables(
    literalLengthTable: buildSequenceDecodingTable(
      descriptor: literalDescriptor,
      baseValues: llBaseline,
      extraBits: llExtraBits,
    ),
    offsetTable: buildSequenceDecodingTable(
      descriptor: offsetDescriptor,
      baseValues: ofBaseline,
      extraBits: ofExtraBits,
    ),
    matchLengthTable: buildSequenceDecodingTable(
      descriptor: matchDescriptor,
      baseValues: mlBaseline,
      extraBits: mlExtraBits,
    ),
  );

  if (reader.remaining < 12) {
    throw ZstdFrameFormatException('Dictionary is missing previous offset table');
  }
  final prevOffsets = List<int>.generate(3, (_) => reader.readUint32LE());

  if (reader.remaining <= 0) {
    throw ZstdFrameFormatException('Dictionary is missing its history content');
  }
  final content = reader.readBytes(reader.remaining);

  for (final offset in prevOffsets) {
    if (offset <= 0 || offset > content.length) {
      throw ZstdFrameFormatException(
        'Dictionary previous offset $offset exceeds content length ${content.length}',
      );
    }
  }

  return ZstdDictionary(
    dictId: dictId,
    content: content,
    huffmanTable: huffmanTable,
    sequenceTables: sequenceTables,
    initialPrevOffsets: prevOffsets,
  );
}

Uint8List _readStandaloneHuffmanPayload(ZstdByteReader reader) {
  if (reader.remaining < 1) {
    throw ZstdFrameFormatException('Dictionary is truncated before the Huffman table');
  }
  final header = reader.readUint8();
  final payloadLength = header >= 128 ? ((header - 127) + 1) >> 1 : header;
  if (payloadLength < 0 || payloadLength > reader.remaining) {
    throw ZstdFrameFormatException('Dictionary Huffman table payload is truncated');
  }
  final payload = Uint8List(payloadLength + 1)..[0] = header;
  if (payloadLength > 0) {
    payload.setAll(1, reader.readBytes(payloadLength));
  }
  return payload;
}
