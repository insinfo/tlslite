import 'dart:typed_data';

const int _mask64 = 0xFFFFFFFFFFFFFFFF;
const int _prime1 = -7046029254386353131; // 0x9E3779B185EBCA87
const int _prime2 = -5423576195223530945; // 0xC2B2AE3D27D4EB4F
const int _prime3 = 1609587929392839161;  // 0x165667B19E3779F9
const int _prime4 = -8796714831421723037; // 0x84CAA73B2DD7D2DD
const int _prime5 = 2870177450012600261;  // 0x27D4EB2F165667C5

int xxHash64(Uint8List data, {int seed = 0}) {
  var offset = 0;
  final length = data.length;
  int hash;

  if (length >= 32) {
    var v1 = (seed + _prime1 + _prime2) & _mask64;
    var v2 = (seed + _prime2) & _mask64;
    var v3 = seed & _mask64;
    var v4 = (seed - _prime1) & _mask64;

    final limit = length - 32;
    while (offset <= limit) {
      v1 = _round(v1, _readUint64(data, offset));
      offset += 8;
      v2 = _round(v2, _readUint64(data, offset));
      offset += 8;
      v3 = _round(v3, _readUint64(data, offset));
      offset += 8;
      v4 = _round(v4, _readUint64(data, offset));
      offset += 8;
    }

    hash = _rotateLeft(v1, 1) +
        _rotateLeft(v2, 7) +
        _rotateLeft(v3, 12) +
        _rotateLeft(v4, 18);

    hash = _mergeRound(hash, v1);
    hash = _mergeRound(hash, v2);
    hash = _mergeRound(hash, v3);
    hash = _mergeRound(hash, v4);
  } else {
    hash = (seed + _prime5) & _mask64;
  }

  hash = (hash + length) & _mask64;

  while (offset + 8 <= length) {
    final k1 = _readUint64(data, offset);
    offset += 8;
    hash ^= _round(0, k1);
    hash = (_rotateLeft(hash, 27) * _prime1 + _prime4) & _mask64;
  }

  if (offset + 4 <= length) {
    hash ^= (_readUint32(data, offset) * _prime1) & _mask64;
    hash = (_rotateLeft(hash, 23) * _prime2 + _prime3) & _mask64;
    offset += 4;
  }

  while (offset < length) {
    hash ^= ((data[offset] & 0xFF) * _prime5) & _mask64;
    hash = (_rotateLeft(hash, 11) * _prime1) & _mask64;
    offset++;
  }

  hash ^= (hash >> 33);
  hash = (hash * _prime2) & _mask64;
  hash ^= (hash >> 29);
  hash = (hash * _prime3) & _mask64;
  hash ^= (hash >> 32);

  return hash & _mask64;
}

int _round(int acc, int input) {
  var value = (acc + (input * _prime2)) & _mask64;
  value = _rotateLeft(value, 31);
  return (value * _prime1) & _mask64;
}

int _mergeRound(int acc, int value) {
  acc ^= _round(0, value);
  acc = (acc * _prime1 + _prime4) & _mask64;
  return acc;
}

int _rotateLeft(int value, int count) {
  return ((value << count) & _mask64) | ((value & _mask64) >> (64 - count));
}

int _readUint64(Uint8List data, int offset) {
  var result = 0;
  for (var i = 0; i < 8; i++) {
    result |= (data[offset + i] & 0xFF) << (8 * i);
  }
  return result & _mask64;
}

int _readUint32(Uint8List data, int offset) {
  var result = 0;
  for (var i = 0; i < 4; i++) {
    result |= (data[offset + i] & 0xFF) << (8 * i);
  }
  return result & 0xFFFFFFFF;
}
