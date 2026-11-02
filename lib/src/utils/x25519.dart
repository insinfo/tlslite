// Ported to Dart from tlslite-ng tlslite/utils/x25519.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:typed_data';

import 'cryptomath.dart';

const int _x25519Bits = 255;
const int _x448Bits = 448;

final Uint8List x25519G = numberToByteArray(
  BigInt.from(9),
  howManyBytes: 32,
  endian: 'little',
);

const int x25519OrderSize = 32;

final Uint8List x448G = numberToByteArray(
  BigInt.from(5),
  howManyBytes: 56,
  endian: 'little',
);

const int x448OrderSize = 56;

BigInt decodeUCoordinate(List<int> u, int bits) {
  if (bits != _x25519Bits && bits != _x448Bits) {
    throw ArgumentError('Invalid number of expected bits');
  }
  final data = Uint8List.fromList(u);
  if (bits % 8 != 0 && data.isNotEmpty) {
    final mask = (1 << (bits % 8)) - 1;
    data[data.length - 1] &= mask;
  }
  return bytesToNumber(data, endian: 'little');
}

BigInt decodeScalar22519(List<int> k) {
  final data = Uint8List.fromList(k);
  data[0] &= 248;
  data[31] &= 127;
  data[31] |= 64;
  return bytesToNumber(data, endian: 'little');
}

BigInt decodeScalar448(List<int> k) {
  final data = Uint8List.fromList(k);
  data[0] &= 252;
  data[55] |= 128;
  return bytesToNumber(data, endian: 'little');
}

Uint8List x25519(List<int> k, List<int> u) {
  final scalar = decodeScalar22519(k);
  final coord = decodeUCoordinate(u, _x25519Bits);
  final a24 = BigInt.from(121665);
  final p = (BigInt.one << 255) - BigInt.from(19);
  return _x25519Generic(scalar, coord, _x25519Bits, a24, p);
}

Uint8List x448(List<int> k, List<int> u) {
  final scalar = decodeScalar448(k);
  final coord = decodeUCoordinate(u, _x448Bits);
  final a24 = BigInt.from(39081);
  final p = (BigInt.one << 448) - (BigInt.one << 224) - BigInt.one;
  return _x25519Generic(scalar, coord, _x448Bits, a24, p);
}

Uint8List _x25519Generic(
  BigInt k,
  BigInt u,
  int bits,
  BigInt a24,
  BigInt p,
) {
  BigInt x1 = u;
  BigInt x2 = BigInt.one;
  BigInt z2 = BigInt.zero;
  BigInt x3 = u;
  BigInt z3 = BigInt.one;
  int swap = 0;

  for (int t = bits - 1; t >= 0; t--) {
    final kt = ((k >> t) & BigInt.one) == BigInt.one ? 1 : 0;
    swap ^= kt;
    if (swap != 0) {
      final tmpX = x2;
      x2 = x3;
      x3 = tmpX;
      final tmpZ = z2;
      z2 = z3;
      z3 = tmpZ;
    }
    swap = kt;

    final A = (x2 + z2) % p;
    final aa = (A * A) % p;
    final B = (x2 - z2) % p;
    final bb = (B * B) % p;
    final E = (aa - bb) % p;
    final C = (x3 + z3) % p;
    final D = (x3 - z3) % p;
    final da = (D * A) % p;
    final cb = (C * B) % p;
    final tmp = (da + cb) % p;
    x3 = (tmp * tmp) % p;
    final tmp2 = (da - cb) % p;
    z3 = (x1 * ((tmp2 * tmp2) % p)) % p;
    x2 = (aa * bb) % p;
    final inner = (aa + (a24 * E) % p) % p;
    z2 = (E * inner) % p;
  }

  if (swap != 0) {
    final tmpX = x2;
    x2 = x3;
    x3 = tmpX;
    final tmpZ = z2;
    z2 = z3;
    z3 = tmpZ;
  }

  final zInv = z2.modPow(p - BigInt.from(2), p);
  final ret = (x2 * zInv) % p;
  final outLen = divceil(BigInt.from(bits), BigInt.from(8)).toInt();
  return numberToByteArray(ret, howManyBytes: outLen, endian: 'little');
}
