import 'dart:typed_data';
import 'dart:math' as math;

const int _u32Mask = 0xffffffff;
const int _u16Mask = 0xffff;
const int _u8Mask = 0xff;

int _mask32(int value) => value & _u32Mask;

/// Returns 1 if [valA] < [valB] treating both as unsigned 32-bit integers.
int ctLtU32(int valA, int valB) {
  final a = _mask32(valA);
  final b = _mask32(valB);
  final diff = _mask32(a - b);
  final expr = a ^ ((a ^ b) | (diff ^ b));
  return (expr >> 31) & 1;
}

/// Returns 1 if [valA] > [valB] treating both as unsigned 32-bit integers.
int ctGtU32(int valA, int valB) {
  return ctLtU32(valB, valA);
}

/// Returns 1 if [valA] <= [valB] treating both as unsigned 32-bit integers.
int ctLeU32(int valA, int valB) {
  return 1 ^ ctGtU32(valA, valB);
}

/// Propagates the least significant bit of [value] across an 8-bit mask.
int ctLsbPropU8(int value) {
  var v = value & 0x01;
  v |= v << 1;
  v |= v << 2;
  v |= v << 4;
  return v & _u8Mask;
}

/// Propagates the least significant bit of [value] across a 16-bit mask.
int ctLsbPropU16(int value) {
  var v = value & 0x01;
  v |= v << 1;
  v |= v << 2;
  v |= v << 4;
  v |= v << 8;
  return v & _u16Mask;
}

/// Returns 1 when [value] is non-zero (unsigned 32-bit comparison), otherwise 0.
int ctIsNonZeroU32(int value) {
  final v = _mask32(value);
  final neg = _mask32(-v);
  return ((v | neg) >> 31) & 1;
}

/// Returns 1 if [valA] != [valB] treating both as unsigned 32-bit integers.
int ctNeqU32(int valA, int valB) {
  final a = _mask32(valA);
  final b = _mask32(valB);
  final diff1 = _mask32(a - b);
  final diff2 = _mask32(b - a);
  return ((diff1 | diff2) >> 31) & 1;
}

/// Returns 1 if [valA] == [valB] treating both as unsigned 32-bit integers.
int ctEqU32(int valA, int valB) {
  return 1 ^ ctNeqU32(valA, valB);
}

/// Constant-time comparison of two byte sequences.
bool ctCompareDigest(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  var result = 0;
  for (var i = 0; i < a.length; i++) {
    result |= (a[i] & _u8Mask) ^ (b[i] & _u8Mask);
  }
  return result == 0;
}

/// Check CBC cipher HMAC and padding. Close to constant time.
///
/// [data] contains the decrypted record data (including MAC and padding).
/// [mac] is the HMAC context (e.g. TlsHmac).
/// [seqnumBytes] is the sequence number.
/// [contentType] is the record content type.
/// [version] is the protocol version (major, minor).
/// [blockSize] is the cipher block size.
bool ctCheckCbcMacAndPad(
  Uint8List data,
  dynamic mac,
  Uint8List seqnumBytes,
  int contentType,
  List<int> version,
  {int blockSize = 16}
) {
  // assert version in ((3, 0), (3, 1), (3, 2), (3, 3))
  
  final dataLen = data.length;
  final digestSize = mac.digestSize as int;
  
  if (digestSize + 1 > dataLen) {
    return false;
  }

  var result = 0;

  // check padding
  final padLength = data[dataLen - 1];
  var padStart = dataLen - padLength - 1;
  padStart = math.max(0, padStart);

  if (version[0] == 3 && version[1] == 0) {
    // SSLv3
    final mask = ctLsbPropU8(ctLtU32(blockSize, padLength));
    result |= mask;
  } else {
    // TLS 1.0+
    final startPos = math.max(0, dataLen - 256);
    for (var i = startPos; i < dataLen; i++) {
      final mask = ctLsbPropU8(ctLeU32(padStart, i));
      result |= (data[i] ^ padLength) & mask;
    }
  }

  // check MAC
  var macStart = padStart - digestSize;
  macStart = math.max(0, macStart);

  final macBlockSize = mac.blockSize as int;
  var startPos = math.max(0, dataLen - (256 + digestSize)) ~/ macBlockSize;
  startPos *= macBlockSize;

  final dataMac = mac.copy();
  dataMac.update(seqnumBytes);
  dataMac.update(Uint8List.fromList([contentType]));
  
  if (!(version[0] == 3 && version[1] == 0)) {
    dataMac.update(Uint8List.fromList([version[0]]));
    dataMac.update(Uint8List.fromList([version[1]]));
  }
  
  dataMac.update(Uint8List.fromList([macStart >> 8]));
  dataMac.update(Uint8List.fromList([macStart & 0xff]));
  dataMac.update(data.sublist(0, startPos));

  final endPos = dataLen - digestSize;

  for (var i = startPos; i < endPos; i++) {
    final curMac = dataMac.copy();
    curMac.update(data.sublist(startPos, i));
    final macCompare = curMac.digest() as Uint8List;
    
    final mask = ctLsbPropU8(ctEqU32(i, macStart));
    for (var j = 0; j < digestSize; j++) {
      result |= (data[i + j] ^ macCompare[j]) & mask;
    }
  }

  return result == 0;
}
