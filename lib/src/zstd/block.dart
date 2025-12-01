import 'byte_reader.dart';
import 'frame_header.dart';

enum ZstdBlockType { raw, rle, compressed, reserved }

class ZstdBlockHeader {
  const ZstdBlockHeader({
    required this.lastBlock,
    required this.type,
    required this.compressedSize,
    required this.rleOriginalSize,
  });

  final bool lastBlock;
  final ZstdBlockType type;
  final int compressedSize;
  final int rleOriginalSize;
}

ZstdBlockHeader readBlockHeader(ZstdByteReader reader) {
  final header = reader.readUint24LE();
  final bool lastBlock = (header & 0x1) == 1;
  final int blockTypeBits = (header >> 1) & 0x3;
  final ZstdBlockType blockType = ZstdBlockType.values[blockTypeBits];
  final int cSize = header >> 3;

  if (blockType == ZstdBlockType.reserved) {
    throw ZstdFrameFormatException('Reserved Zstd block type encountered');
  }

  if (blockType == ZstdBlockType.rle) {
    return ZstdBlockHeader(
      lastBlock: lastBlock,
      type: blockType,
      compressedSize: 1,
      rleOriginalSize: cSize,
    );
  }

  return ZstdBlockHeader(
    lastBlock: lastBlock,
    type: blockType,
    compressedSize: cSize,
    rleOriginalSize: 0,
  );
}

void ensureBlockSizeWithinWindow(ZstdFrameHeader header, ZstdBlockHeader block) {
  final blockSize = block.type == ZstdBlockType.rle ? block.rleOriginalSize : block.compressedSize;
  if (blockSize > header.blockSizeMax) {
    throw ZstdFrameFormatException('Block size $blockSize exceeds frame maximum ${header.blockSizeMax}');
  }
}
