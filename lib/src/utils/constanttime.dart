import 'dart:typed_data';

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

/// Placeholder for ct_check_cbc_mac_and_pad until the record layer is ported.
Never ctCheckCbcMacAndPad(
  Uint8List data,
  dynamic mac,
  Uint8List seqnumBytes,
  int contentType,
  List<int> version,
  {int blockSize = 16}
) {
  throw UnimplementedError('ct_check_cbc_mac_and_pad not yet ported');
}
