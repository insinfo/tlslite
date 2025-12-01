import 'dart:typed_data';
import 'Utils.dart';

abstract class InputStream {
  int read(Uint8List b, int off, int len);
  void close();
}

class ByteArrayInputStream implements InputStream {
  final Uint8List _data;
  int _pos = 0;

  ByteArrayInputStream(this._data);

  @override
  int read(Uint8List b, int off, int len) {
    if (_pos >= _data.length) return -1;
    int available = _data.length - _pos;
    int toRead = Utils.min(len, available);
    b.setRange(off, off + toRead, _data.sublist(_pos, _pos + toRead));
    _pos += toRead;
    return toRead;
  }
  
  @override
  void close() {}
}

class State {
  Uint8List ringBuffer = Uint8List(0);
  Uint8List contextModes = Uint8List(0);
  Uint8List contextMap = Uint8List(0);
  Uint8List distContextMap = Uint8List(0);
  Uint8List distExtraBits = Uint8List(0);
  Uint8List output = Uint8List(0);
  Uint8List byteBuffer = Uint8List(0);

  Int16List shortBuffer = Int16List(0);

  Int32List intBuffer = Int32List(0);
  Int32List rings = Int32List(10);
  Int32List blockTrees = Int32List(0);
  Int32List literalTreeGroup = Int32List(0);
  Int32List commandTreeGroup = Int32List(0);
  Int32List distanceTreeGroup = Int32List(0);
  Int32List distOffset = Int32List(0);

  int accumulator64 = 0;

  int runningState = 0;
  int nextRunningState = 0;
  int accumulator32 = 0;
  int bitOffset = 0;
  int halfOffset = 0;
  int tailBytes = 0;
  int endOfStreamReached = 0;
  int metaBlockLength = 0;
  int inputEnd = 0;
  int isUncompressed = 0;
  int isMetadata = 0;
  int literalBlockLength = 0;
  int numLiteralBlockTypes = 0;
  int commandBlockLength = 0;
  int numCommandBlockTypes = 0;
  int distanceBlockLength = 0;
  int numDistanceBlockTypes = 0;
  int pos = 0;
  int maxDistance = 0;
  int distRbIdx = 0;
  int trivialLiteralContext = 0;
  int literalTreeIdx = 0;
  int commandTreeIdx = 0;
  int j = 0;
  int insertLength = 0;
  int contextMapSlice = 0;
  int distContextMapSlice = 0;
  int contextLookupOffset1 = 0;
  int contextLookupOffset2 = 0;
  int distanceCode = 0;
  int numDirectDistanceCodes = 0;
  int distancePostfixBits = 0;
  int distance = 0;
  int copyLength = 0;
  int maxBackwardDistance = 0;
  int maxRingBufferSize = 0;
  int ringBufferSize = 0;
  int expectedTotalSize = 0;
  int outputOffset = 0;
  int outputLength = 0;
  int outputUsed = 0;
  int ringBufferBytesWritten = 0;
  int ringBufferBytesReady = 0;
  int isEager = 0;
  int isLargeWindow = 0;

  int cdNumChunks = 0;
  int cdTotalSize = 0;
  int cdBrIndex = 0;
  int cdBrOffset = 0;
  int cdBrLength = 0;
  int cdBrCopied = 0;
  List<Uint8List> cdChunks = [];
  Int32List cdChunkOffsets = Int32List(0);
  int cdBlockBits = 0;
  Uint8List cdBlockMap = Uint8List(0);

  InputStream input = ByteArrayInputStream(Uint8List(0));

  State() {
    this.ringBuffer = Uint8List(0);
    this.rings = Int32List(10);
    this.rings[0] = 16;
    this.rings[1] = 15;
    this.rings[2] = 11;
    this.rings[3] = 4;
  }
}
