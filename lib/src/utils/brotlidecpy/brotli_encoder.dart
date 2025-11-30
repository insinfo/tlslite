import 'dart:typed_data';

import '../bit_stream_writer.dart';

/// Maximum payload that fits in a single uncompressed Brotli meta-block.
const int _maxMetaBlockLength = 0xFFFFFF + 1; // 24-bit length + 1
const int brotliRawMaxChunkLength = _maxMetaBlockLength;
const int _minWindowBits = 16;
const int _maxWindowBits = 24;

/// Emits a Brotli stream composed exclusively of uncompressed meta-blocks.
///
/// The encoder produces a standards-compliant bitstream that mirrors the
/// decode pipeline in `lib/src/utils/brotlidecpy`. The payload is chunked into
/// meta-blocks capped at 16,777,216 bytes so the length header fits in six
/// nibbles. Each chunk is flagged as "uncompressed" and a terminating empty
/// meta-block closes the stream.
Uint8List brotliCompressRaw(
  Uint8List input, {
  int windowBits = 16,
}) {
  if (windowBits < _minWindowBits || windowBits > _maxWindowBits) {
    throw ArgumentError.value(
      windowBits,
      'windowBits',
      'Brotli raw encoder supports window bits in the range $_minWindowBits-$_maxWindowBits.',
    );
  }

  final builder = BytesBuilder(copy: false);
  final writer = BitStreamWriter();
  _writeWindowBits(writer, windowBits);

  var offset = 0;
  while (offset < input.length) {
    final remaining = input.length - offset;
    final chunkLength = remaining > _maxMetaBlockLength ? _maxMetaBlockLength : remaining;
    _writeUncompressedMetaBlockHeader(writer, chunkLength);
    writer.alignToByte();
    final headerBytes = writer.takeBytes(includePartialByte: false);
    if (headerBytes.isNotEmpty) {
      builder.add(headerBytes);
    }
    builder.add(Uint8List.sublistView(input, offset, offset + chunkLength));
    offset += chunkLength;
  }

  _writeStreamTerminator(writer);
  writer.alignToByte();
  builder.add(writer.takeBytes());

  return builder.takeBytes();
}

void _writeWindowBits(BitStreamWriter writer, int windowBits) {
  if (windowBits == 16) {
    writer.writeBits(0, 1);
    return;
  }

  writer.writeBits(1, 1);
  if (windowBits == 17) {
    writer.writeBits(0, 3);
    writer.writeBits(0, 3);
    return;
  }

  final adjusted = windowBits - 17;
  if (adjusted <= 0 || adjusted > 7) {
    throw ArgumentError.value(windowBits, 'windowBits', 'Unsupported window bits for Brotli header');
  }
  writer.writeBits(adjusted, 3);
}

void _writeUncompressedMetaBlockHeader(BitStreamWriter writer, int length) {
  if (length <= 0) {
    throw ArgumentError.value(length, 'length', 'Meta-block length must be positive');
  }
  if (length > _maxMetaBlockLength) {
    throw ArgumentError('Meta-block length $length exceeds $_maxMetaBlockLength bytes');
  }

  writer.writeBool(false); // isLast
  final lengthMinusOne = length - 1;
  final sizeNibbles = _sizeNibblesFor(lengthMinusOne);
  writer.writeBits(sizeNibbles - 4, 2);
  for (var i = 0; i < sizeNibbles; i++) {
    final nibble = (lengthMinusOne >> (i * 4)) & 0xF;
    writer.writeBits(nibble, 4);
  }
  writer.writeBool(true); // isUncompressed
}

int _sizeNibblesFor(int value) {
  if (value <= 0xFFFF) {
    return 4;
  }
  if (value <= 0xFFFFF) {
    return 5;
  }
  if (value <= 0xFFFFFF) {
    return 6;
  }
  throw ArgumentError('Value $value does not fit in Brotli meta-block header');
}

void _writeStreamTerminator(BitStreamWriter writer) {
  writer.writeBool(true); // isLast
  writer.writeBool(false); // more header fields follow
  writer.writeBits(3, 2); // sizeNibbles indicator => 7 => metadata path
  writer.writeBool(false); // reserved bit must be zero
  writer.writeBits(0, 2); // sizeBytes = 0 (no metadata payload)
}
