import 'dart:typed_data';

import 'block.dart';
import 'byte_reader.dart';
import 'frame_header.dart';
import 'literals.dart';
import 'sequences.dart';
import 'window.dart';

class ZstdDecodingError implements Exception {
  ZstdDecodingError(this.message);
  final String message;
  @override
  String toString() => 'ZstdDecodingError: $message';
}

/// Best-effort Zstd frame decoder that currently supports frames composed of
/// RAW/RLE blocks and compressed blocks with Huffman literals (no dictionaries
/// or content checksums yet).
Uint8List zstdDecompressFrame(Uint8List input) {
  final reader = ZstdByteReader(input);
  final header = parseFrameHeader(reader);

  if (header.dictId != 0) {
    throw ZstdDecodingError('Dictionaries are not supported yet');
  }
  if (header.checksumFlag) {
    throw ZstdDecodingError('Frames with content checksum are not supported yet');
  }

  reader.offset = header.headerSize;
  final output = <int>[];
  final window = ZstdWindow(header.windowSize);
  var prevOffsets = <int>[1, 4, 8];
  HuffmanDecodingTable? lastHuffmanTable;
  var finished = false;
  while (!reader.isEOF && !finished) {
    final blockHeader = readBlockHeader(reader);
    ensureBlockSizeWithinWindow(header, blockHeader);
    final blockDataStart = reader.offset;
    final blockDataEnd = blockDataStart + blockHeader.compressedSize;
    if (blockDataEnd > reader.buffer.length) {
      throw ZstdDecodingError('Block exceeds input size');
    }

    switch (blockHeader.type) {
      case ZstdBlockType.raw:
        if (reader.remaining < blockHeader.compressedSize) {
          throw ZstdDecodingError('Unexpected end of input while reading RAW block');
        }
        final raw = reader.readBytes(blockHeader.compressedSize);
        window.appendBytes(raw, output);
        break;
      case ZstdBlockType.rle:
        if (reader.remaining < 1) {
          throw ZstdDecodingError('Unexpected end of input while reading RLE block');
        }
        final value = reader.readUint8();
        window.repeatByte(value, blockHeader.rleOriginalSize, output);
        break;
      case ZstdBlockType.compressed:
        final literalsResult = decodeLiteralsBlock(
          reader,
          repeatTable: lastHuffmanTable,
        );
        if (literalsResult.huffmanTable != null) {
          lastHuffmanTable = literalsResult.huffmanTable;
        }
        if (reader.offset > blockDataEnd) {
          throw ZstdDecodingError('Literals section overruns block payload');
        }

        final sequencesHeader = parseSequencesHeader(reader);
        final payloadSize = blockDataEnd - reader.offset;
        if (payloadSize < 0) {
          throw ZstdDecodingError('Sequence payload underflow');
        }
        final sequencesResult = decodeSequencesSection(
          reader,
          sequencesHeader,
          payloadSize: payloadSize,
          initialPrevOffsets: prevOffsets,
        );
        prevOffsets = List<int>.from(sequencesResult.finalPrevOffsets);

        executeSequences(
          sequences: sequencesResult.sequences,
          literals: literalsResult.literals,
          window: window,
          outputBuffer: output,
        );
        break;
      case ZstdBlockType.reserved:
        throw ZstdDecodingError('Encountered reserved block type');
    }

    if (reader.offset != blockDataEnd) {
      reader.offset = blockDataEnd;
    }

    if (blockHeader.lastBlock) {
      finished = true;
    }
  }

  if (!finished) {
    throw ZstdDecodingError('Input terminated before the last block flag');
  }

  final result = Uint8List.fromList(output);
  if (header.frameContentSize != null && header.frameContentSize != result.length) {
    throw ZstdDecodingError('Frame content size mismatch: expected ${header.frameContentSize}, got ${result.length}');
  }

  return result;
}
