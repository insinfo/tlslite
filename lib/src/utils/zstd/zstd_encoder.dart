import 'dart:typed_data';

import 'block.dart';
import 'constants.dart';
import 'literals.dart';
import 'xxhash64.dart';

class ZstdEncodingError implements Exception {
  ZstdEncodingError(this.message);
  final String message;
  @override
  String toString() => 'ZstdEncodingError: $message';
}

/// Encodes [input] into a single-segment Zstandard frame composed of raw blocks.
///
/// This implementation does not attempt to reduce the size of the payload yet;
/// it merely wraps the provided bytes into a valid frame so existing decoders
/// (including the Dart port) can round-trip the data. The encoder splits the
/// payload into chunks that respect the Zstd maximum block size and can
/// optionally append the 32-bit content checksum emitted by standard encoders.
Uint8List zstdCompress(
  Uint8List input, {
  bool includeChecksum = false,
}) {
  final builder = BytesBuilder(copy: false);
  builder.add(_zstdMagicBytes);

  final contentSize = input.length;
  final descriptor = _buildFrameDescriptor(
    contentSize: contentSize,
    includeChecksum: includeChecksum,
  );
  builder.add([descriptor]);
  builder.add(_encodeFrameContentSize(contentSize));

  final blockSizeLimit = contentSize < zstdBlockSizeMax ? contentSize : zstdBlockSizeMax;
  var offset = 0;
  if (contentSize == 0) {
    _encodeRawBlock(builder, Uint8List(0), isLastBlock: true);
  } else {
    while (offset < contentSize) {
      final runLength = _countRunLength(input, offset, zstdBlockSizeMax);
      if (runLength >= _minRleRunLength) {
        final isLast = offset + runLength == contentSize;
        _encodeRleBlock(
          builder,
          input[offset],
          runLength,
          isLastBlock: isLast,
        );
        offset += runLength;
        continue;
      }

      final remaining = contentSize - offset;
      var chunkSize = remaining > blockSizeLimit && blockSizeLimit > 0 ? blockSizeLimit : remaining;
      if (chunkSize <= 0) {
        chunkSize = remaining;
      }
      final chunk = Uint8List.sublistView(input, offset, offset + chunkSize);
      final isLast = offset + chunkSize == contentSize;
      if (_canUseLiteralOnlyBlock(chunk.length, blockSizeLimit)) {
        _encodeLiteralOnlyBlock(builder, chunk, isLastBlock: isLast);
      } else {
        _encodeRawBlock(builder, chunk, isLastBlock: isLast);
      }
      offset += chunkSize;
    }
  }

  if (includeChecksum) {
    final checksum = xxHash64(input) & 0xFFFFFFFF;
    builder.add(Uint8List(4)
      ..buffer.asByteData().setUint32(0, checksum, Endian.little));
  }

  return builder.takeBytes();
}

final Uint8List _zstdMagicBytes = Uint8List.fromList([
  zstdMagicNumber & 0xFF,
  (zstdMagicNumber >> 8) & 0xFF,
  (zstdMagicNumber >> 16) & 0xFF,
  (zstdMagicNumber >> 24) & 0xFF,
]);

int _buildFrameDescriptor({
  required int contentSize,
  required bool includeChecksum,
}) {
  if (contentSize < 0) {
    throw ZstdEncodingError('Content size cannot be negative');
  }
  final fcsId = _selectFrameContentSizeId(contentSize);
  var descriptor = 0x20 | (fcsId << 6); // single segment + content size flag
  if (includeChecksum) {
    descriptor |= 0x04;
  }
  return descriptor;
}

int _selectFrameContentSizeId(int contentSize) {
  if (contentSize <= 0xFF) {
    return 0;
  }
  if (contentSize <= (0xFFFF + 256)) {
    return 1;
  }
  if (contentSize <= 0xFFFFFFFF) {
    return 2;
  }
  return 3;
}

List<int> _encodeFrameContentSize(int contentSize) {
  final fcsId = _selectFrameContentSizeId(contentSize);
  switch (fcsId) {
    case 0:
      return [contentSize & 0xFF];
    case 1:
      final adjusted = contentSize - 256;
      if (adjusted < 0 || adjusted > 0xFFFF) {
        throw ZstdEncodingError('Frame size is invalid for fcsId=1');
      }
      return [adjusted & 0xFF, (adjusted >> 8) & 0xFF];
    case 2:
      return [
        contentSize & 0xFF,
        (contentSize >> 8) & 0xFF,
        (contentSize >> 16) & 0xFF,
        (contentSize >> 24) & 0xFF,
      ];
    case 3:
      final bytes = <int>[];
      var value = contentSize;
      for (var i = 0; i < 8; i++) {
        bytes.add(value & 0xFF);
        value = value >> 8;
      }
      return bytes;
    default:
      throw ZstdEncodingError('Unsupported frame content size flag: $fcsId');
  }
}

void _encodeRawBlock(BytesBuilder builder, Uint8List chunk, {required bool isLastBlock}) {
  if (chunk.length > zstdBlockSizeMax) {
    throw ZstdEncodingError('Chunk size ${chunk.length} exceeds block limit $zstdBlockSizeMax');
  }
  final headerValue = (chunk.length << 3) | (isLastBlock ? 1 : 0);
  builder.add([
    headerValue & 0xFF,
    (headerValue >> 8) & 0xFF,
    (headerValue >> 16) & 0xFF,
  ]);
  if (chunk.isNotEmpty) {
    builder.add(chunk);
  }
}

void _encodeRleBlock(BytesBuilder builder, int value, int literalCount, {required bool isLastBlock}) {
  if (literalCount <= 0 || literalCount > zstdBlockSizeMax) {
    throw ZstdEncodingError('Invalid RLE literal count $literalCount');
  }
  final headerValue =
      (literalCount << 3) | (ZstdBlockType.rle.index << 1) | (isLastBlock ? 1 : 0);
  builder.add([
    headerValue & 0xFF,
    (headerValue >> 8) & 0xFF,
    (headerValue >> 16) & 0xFF,
  ]);
  builder.add([value & 0xFF]);
}

const int _minRleRunLength = 2;

int _countRunLength(Uint8List input, int start, int maxLength) {
  if (start >= input.length) {
    return 0;
  }
  final byte = input[start];
  var length = 1;
  final limit = start + maxLength;
  while (start + length < input.length && start + length < limit) {
    if (input[start + length] != byte) {
      break;
    }
    length += 1;
  }
  return length;
}

bool _canUseLiteralOnlyBlock(int literalCount, int blockSizeLimit) {
  if (blockSizeLimit <= 0) {
    return false;
  }
  final headerLength = _literalHeaderLength(literalCount);
  final payloadSize = headerLength + literalCount + _sequencesZeroHeaderSize;
  return payloadSize <= blockSizeLimit;
}

void _encodeLiteralOnlyBlock(BytesBuilder builder, Uint8List chunk, {required bool isLastBlock}) {
  final literalHeader = _encodeRawLiteralHeader(chunk.length);
  final payloadSize = literalHeader.length + chunk.length + _sequencesZeroHeaderSize;
  if (payloadSize > zstdBlockSizeMax) {
    throw ZstdEncodingError('Literal block payload exceeds block limit: $payloadSize');
  }
  final headerValue =
      (payloadSize << 3) | (ZstdBlockType.compressed.index << 1) | (isLastBlock ? 1 : 0);
  builder.add([
    headerValue & 0xFF,
    (headerValue >> 8) & 0xFF,
    (headerValue >> 16) & 0xFF,
  ]);
  builder.add(literalHeader);
  if (chunk.isNotEmpty) {
    builder.add(chunk);
  }
  builder.add(const [0x00]);
}

const int _sequencesZeroHeaderSize = 1;

int _literalHeaderLength(int literalCount) {
  if (literalCount <= 0x1F) {
    return 1;
  }
  if (literalCount <= 0x0FFF) {
    return 2;
  }
  return 3;
}

Uint8List _encodeRawLiteralHeader(int literalCount) {
  if (literalCount < 0) {
    throw ZstdEncodingError('Literal count cannot be negative');
  }
  final sizeFormat = switch (_literalHeaderLength(literalCount)) {
    1 => 0,
    2 => 1,
    3 => 3,
    _ => throw StateError('Unsupported literal header length'),
  };
  final length = _literalHeaderLength(literalCount);
  final shift = length == 1 ? 3 : 4;
  final headerValue = (literalCount << shift) | (sizeFormat << 2) | LiteralsBlockType.raw.index;
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = (headerValue >> (8 * i)) & 0xFF;
  }
  return bytes;
}
