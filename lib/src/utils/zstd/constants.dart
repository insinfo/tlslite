const int zstdMagicNumber = 0xFD2FB528;
const int zstdSkippableMask = 0xFFFFFFF0;
const int zstdSkippableStart = 0x184D2A50;
const int zstdWindowLogAbsoluteMin = 10;
const int zstdBlockHeaderSize = 3;
const int zstdBlockSizeLogMax = 17;
const int zstdBlockSizeMax = 1 << zstdBlockSizeLogMax;
const int zstdContentSizeUnknown = -1;

const List<int> _dictIdFieldSize = [0, 1, 2, 4];
const List<int> _contentSizeFieldSize = [0, 2, 4, 8];

List<int> get dictIdFieldSize => _dictIdFieldSize;
List<int> get contentSizeFieldSize => _contentSizeFieldSize;
