import 'byte_reader.dart';
import 'constants.dart';

class ZstdFrameHeader {
  const ZstdFrameHeader({
    required this.frameContentSize,
    required this.windowSize,
    required this.blockSizeMax,
    required this.singleSegment,
    required this.checksumFlag,
    required this.dictId,
    required this.headerSize,
  });

  final int? frameContentSize;
  final int windowSize;
  final int blockSizeMax;
  final bool singleSegment;
  final bool checksumFlag;
  final int dictId;
  final int headerSize;
}

class ZstdFrameFormatException implements Exception {
  ZstdFrameFormatException(this.message);
  final String message;
  @override
  String toString() => 'ZstdFrameFormatException: $message';
}

ZstdFrameHeader parseFrameHeader(ZstdByteReader reader) {
  final startOffset = reader.offset;
  final magic = reader.readUint32LE();
  if (magic != zstdMagicNumber) {
    if ((magic & zstdSkippableMask) == zstdSkippableStart) {
      throw ZstdFrameFormatException('Skippable frames are not supported yet');
    }
    throw ZstdFrameFormatException('Invalid Zstd magic: 0x${magic.toRadixString(16)}');
  }

  final descriptor = reader.readUint8();
  if ((descriptor & 0x18) != 0) {
    throw ZstdFrameFormatException('Reserved frame descriptor bits are set');
  }

  final int dictIdFlag = descriptor & 0x3;
  final bool checksumFlag = ((descriptor >> 2) & 0x1) == 1;
  final bool singleSegment = ((descriptor >> 5) & 0x1) == 1;
  final int fcsId = descriptor >> 6;

  int windowSize = 0;
  if (!singleSegment) {
    final wlByte = reader.readUint8();
    final int windowLog = (wlByte >> 3) + zstdWindowLogAbsoluteMin;
    if (windowLog > 0x7FFFFFFF) {
      throw ZstdFrameFormatException('Window log is too large');
    }
    windowSize = 1 << windowLog;
    windowSize += (windowSize >> 3) * (wlByte & 0x7);
  }

  final dictSize = dictIdFieldSize[dictIdFlag];
  int dictId = 0;
  switch (dictSize) {
    case 0:
      break;
    case 1:
      dictId = reader.readUint8();
      break;
    case 2:
      dictId = reader.readUint16LE();
      break;
    case 4:
      dictId = reader.readUint32LE();
      break;
    default:
      throw ZstdFrameFormatException('Unsupported dictionary id size: $dictSize');
  }

  int frameContentSizeValue = zstdContentSizeUnknown;
  bool hasFrameContentSize = false;
  switch (fcsId) {
    case 0:
      if (singleSegment) {
        frameContentSizeValue = reader.readUint8();
        hasFrameContentSize = true;
      }
      break;
    case 1:
      frameContentSizeValue = reader.readUint16LE() + 256;
      hasFrameContentSize = true;
      break;
    case 2:
      frameContentSizeValue = reader.readUint32LE();
      hasFrameContentSize = true;
      break;
    case 3:
      frameContentSizeValue = reader.readUint64LE();
      hasFrameContentSize = true;
      break;
    default:
      throw ZstdFrameFormatException('Invalid frame content size flag: $fcsId');
  }

  if (singleSegment) {
    if (!hasFrameContentSize) {
      throw ZstdFrameFormatException('Single-segment frame is missing a content size');
    }
    windowSize = frameContentSizeValue;
  } else if (windowSize == 0) {
    throw ZstdFrameFormatException('Window size is missing');
  }

  final blockSizeMaxValue = windowSize < zstdBlockSizeMax ? windowSize : zstdBlockSizeMax;
  final totalHeaderSize = reader.offset - startOffset;

  return ZstdFrameHeader(
    frameContentSize: hasFrameContentSize && frameContentSizeValue != zstdContentSizeUnknown
      ? frameContentSizeValue
      : null,
    windowSize: windowSize,
    blockSizeMax: blockSizeMaxValue,
    singleSegment: singleSegment,
    checksumFlag: checksumFlag,
    dictId: dictId,
    headerSize: totalHeaderSize,
  );
}
