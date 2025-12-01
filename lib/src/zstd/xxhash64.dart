import 'dart:typed_data';

final BigInt _mask64 = BigInt.parse('FFFFFFFFFFFFFFFF', radix: 16);
final BigInt _prime1 = BigInt.parse('9E3779B185EBCA87', radix: 16);
final BigInt _prime2 = BigInt.parse('C2B2AE3D27D4EB4F', radix: 16);
final BigInt _prime3 = BigInt.parse('165667B19E3779F9', radix: 16);
final BigInt _prime4 = BigInt.parse('85EBCA77C2B2AE63', radix: 16);
final BigInt _prime5 = BigInt.parse('27D4EB2F165667C5', radix: 16);

/// Computes xxHash64 for the provided [data].
///
/// The return value is a 64-bit unsigned integer represented as a [BigInt].
BigInt xxHash64(Uint8List data, {int seed = 0}) {
  var offset = 0;
  final length = data.length;
  BigInt hash;

  if (length >= 32) {
    var v1 = (BigInt.from(seed) + _prime1 + _prime2) & _mask64;
    var v2 = (BigInt.from(seed) + _prime2) & _mask64;
    var v3 = BigInt.from(seed) & _mask64;
    var v4 = (BigInt.from(seed) - _prime1) & _mask64;

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

    hash = (_rotateLeft(v1, 1) +
            _rotateLeft(v2, 7) +
            _rotateLeft(v3, 12) +
            _rotateLeft(v4, 18)) &
        _mask64;

    hash = _mergeRound(hash, v1);
    hash = _mergeRound(hash, v2);
    hash = _mergeRound(hash, v3);
    hash = _mergeRound(hash, v4);
  } else {
    hash = (BigInt.from(seed) + _prime5) & _mask64;
  }

  hash = (hash + BigInt.from(length)) & _mask64;

  while (offset + 8 <= length) {
    final k1 = _round(BigInt.zero, _readUint64(data, offset));
    offset += 8;
    hash ^= k1;
    hash = ((_rotateLeft(hash, 27) * _prime1) + _prime4) & _mask64;
  }

  if (offset + 4 <= length) {
    hash ^= (BigInt.from(_readUint32(data, offset)) * _prime1) & _mask64;
    hash = ((_rotateLeft(hash, 23) * _prime2) + _prime3) & _mask64;
    offset += 4;
  }

  while (offset < length) {
    hash ^= (BigInt.from(data[offset] & 0xFF) * _prime5) & _mask64;
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

BigInt _round(BigInt acc, BigInt input) {
  var value = (acc + input * _prime2) & _mask64;
  value = _rotateLeft(value, 31);
  return (value * _prime1) & _mask64;
}

BigInt _mergeRound(BigInt acc, BigInt value) {
  acc ^= _round(BigInt.zero, value);
  acc = (acc * _prime1 + _prime4) & _mask64;
  return acc;
}

BigInt _rotateLeft(BigInt value, int count) {
  final masked = value & _mask64;
  return ((masked << count) | (masked >> (64 - count))) & _mask64;
}

BigInt _readUint64(Uint8List data, int offset) {
  var result = BigInt.zero;
  for (var i = 0; i < 8; i++) {
    result |= BigInt.from(data[offset + i] & 0xFF) << (8 * i);
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
