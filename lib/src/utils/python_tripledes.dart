import 'dart:typed_data';

import 'tripledes.dart';

TripleDES newTripleDES(List<int> key, List<int> iv) {
  return PythonTripleDES(Uint8List.fromList(key), Uint8List.fromList(iv));
}

abstract class _BaseDes {
  _BaseDes(Uint8List iv) : iv = Uint8List.fromList(iv);

  Uint8List iv;

  Uint8List _ensureBytes(List<int> data) {
    if (data is Uint8List) {
      return Uint8List.fromList(data);
    }
    return Uint8List.fromList(List<int>.from(data));
  }
}

class Des extends _BaseDes {
  Des(Uint8List key, Uint8List iv)
      : key = Uint8List.fromList(key),
        super(iv) {
    if (key.length != 8) {
      throw ArgumentError('DES key must be exactly 8 bytes.');
    }
    _setKey(key);
  }

  static const int blockSize = 8;
  static const int encrypt = 0x00;
  static const int decrypt = 0x01;

  final Uint8List key;

  late List<int> _l;
  late List<int> _r;
  late List<List<int>> _kn;
  late List<int> _finalBlock;

  static const List<int> _pc1 = [
    56,
    48,
    40,
    32,
    24,
    16,
    8,
    0,
    57,
    49,
    41,
    33,
    25,
    17,
    9,
    1,
    58,
    50,
    42,
    34,
    26,
    18,
    10,
    2,
    59,
    51,
    43,
    35,
    62,
    54,
    46,
    38,
    30,
    22,
    14,
    6,
    61,
    53,
    45,
    37,
    29,
    21,
    13,
    5,
    60,
    52,
    44,
    36,
    28,
    20,
    12,
    4,
    27,
    19,
    11,
    3
  ];

  static const List<int> _leftRotations = [
    1,
    1,
    2,
    2,
    2,
    2,
    2,
    2,
    1,
    2,
    2,
    2,
    2,
    2,
    2,
    1
  ];

  static const List<int> _pc2 = [
    13,
    16,
    10,
    23,
    0,
    4,
    2,
    27,
    14,
    5,
    20,
    9,
    22,
    18,
    11,
    3,
    25,
    7,
    15,
    6,
    26,
    19,
    12,
    1,
    40,
    51,
    30,
    36,
    46,
    54,
    29,
    39,
    50,
    44,
    32,
    47,
    43,
    48,
    38,
    55,
    33,
    52,
    45,
    41,
    49,
    35,
    28,
    31
  ];

  static const List<int> _ip = [
    57,
    49,
    41,
    33,
    25,
    17,
    9,
    1,
    59,
    51,
    43,
    35,
    27,
    19,
    11,
    3,
    61,
    53,
    45,
    37,
    29,
    21,
    13,
    5,
    63,
    55,
    47,
    39,
    31,
    23,
    15,
    7,
    56,
    48,
    40,
    32,
    24,
    16,
    8,
    0,
    58,
    50,
    42,
    34,
    26,
    18,
    10,
    2,
    60,
    52,
    44,
    36,
    28,
    20,
    12,
    4,
    62,
    54,
    46,
    38,
    30,
    22,
    14,
    6
  ];

  static const List<int> _expansionTable = [
    31,
    0,
    1,
    2,
    3,
    4,
    3,
    4,
    5,
    6,
    7,
    8,
    7,
    8,
    9,
    10,
    11,
    12,
    11,
    12,
    13,
    14,
    15,
    16,
    15,
    16,
    17,
    18,
    19,
    20,
    19,
    20,
    21,
    22,
    23,
    24,
    23,
    24,
    25,
    26,
    27,
    28,
    27,
    28,
    29,
    30,
    31,
    0
  ];

  static const List<List<int>> _sbox = [
    [
      14,
      4,
      13,
      1,
      2,
      15,
      11,
      8,
      3,
      10,
      6,
      12,
      5,
      9,
      0,
      7,
      0,
      15,
      7,
      4,
      14,
      2,
      13,
      1,
      10,
      6,
      12,
      11,
      9,
      5,
      3,
      8,
      4,
      1,
      14,
      8,
      13,
      6,
      2,
      11,
      15,
      12,
      9,
      7,
      3,
      10,
      5,
      0,
      15,
      12,
      8,
      2,
      4,
      9,
      1,
      7,
      5,
      11,
      3,
      14,
      10,
      0,
      6,
      13
    ],
    [
      15,
      1,
      8,
      14,
      6,
      11,
      3,
      4,
      9,
      7,
      2,
      13,
      12,
      0,
      5,
      10,
      3,
      13,
      4,
      7,
      15,
      2,
      8,
      14,
      12,
      0,
      1,
      10,
      6,
      9,
      11,
      5,
      0,
      14,
      7,
      11,
      10,
      4,
      13,
      1,
      5,
      8,
      12,
      6,
      9,
      3,
      2,
      15,
      13,
      8,
      10,
      1,
      3,
      15,
      4,
      2,
      11,
      6,
      7,
      12,
      0,
      5,
      14,
      9
    ],
    [
      10,
      0,
      9,
      14,
      6,
      3,
      15,
      5,
      1,
      13,
      12,
      7,
      11,
      4,
      2,
      8,
      13,
      7,
      0,
      9,
      3,
      4,
      6,
      10,
      2,
      8,
      5,
      14,
      12,
      11,
      15,
      1,
      13,
      6,
      4,
      9,
      8,
      15,
      3,
      0,
      11,
      1,
      2,
      12,
      5,
      10,
      14,
      7,
      1,
      10,
      13,
      0,
      6,
      9,
      8,
      7,
      4,
      15,
      14,
      3,
      11,
      5,
      2,
      12
    ],
    [
      7,
      13,
      14,
      3,
      0,
      6,
      9,
      10,
      1,
      2,
      8,
      5,
      11,
      12,
      4,
      15,
      13,
      8,
      11,
      5,
      6,
      15,
      0,
      3,
      4,
      7,
      2,
      12,
      1,
      10,
      14,
      9,
      10,
      6,
      9,
      0,
      12,
      11,
      7,
      13,
      15,
      1,
      3,
      14,
      5,
      2,
      8,
      4,
      3,
      15,
      0,
      6,
      10,
      1,
      13,
      8,
      9,
      4,
      5,
      11,
      12,
      7,
      2,
      14
    ],
    [
      2,
      12,
      4,
      1,
      7,
      10,
      11,
      6,
      8,
      5,
      3,
      15,
      13,
      0,
      14,
      9,
      14,
      11,
      2,
      12,
      4,
      7,
      13,
      1,
      5,
      0,
      15,
      10,
      3,
      9,
      8,
      6,
      4,
      2,
      1,
      11,
      10,
      13,
      7,
      8,
      15,
      9,
      12,
      5,
      6,
      3,
      0,
      14,
      11,
      8,
      12,
      7,
      1,
      14,
      2,
      13,
      6,
      15,
      0,
      9,
      10,
      4,
      5,
      3
    ],
    [
      12,
      1,
      10,
      15,
      9,
      2,
      6,
      8,
      0,
      13,
      3,
      4,
      14,
      7,
      5,
      11,
      10,
      15,
      4,
      2,
      7,
      12,
      9,
      5,
      6,
      1,
      13,
      14,
      0,
      11,
      3,
      8,
      9,
      14,
      15,
      5,
      2,
      8,
      12,
      3,
      7,
      0,
      4,
      10,
      1,
      13,
      11,
      6,
      4,
      3,
      2,
      12,
      9,
      5,
      15,
      10,
      11,
      14,
      1,
      7,
      6,
      0,
      8,
      13
    ],
    [
      4,
      11,
      2,
      14,
      15,
      0,
      8,
      13,
      3,
      12,
      9,
      7,
      5,
      10,
      6,
      1,
      13,
      0,
      11,
      7,
      4,
      9,
      1,
      10,
      14,
      3,
      5,
      12,
      2,
      15,
      8,
      6,
      1,
      4,
      11,
      13,
      12,
      3,
      7,
      14,
      10,
      15,
      6,
      8,
      0,
      5,
      9,
      2,
      6,
      11,
      13,
      8,
      1,
      4,
      10,
      7,
      9,
      5,
      0,
      15,
      14,
      2,
      3,
      12
    ],
    [
      13,
      2,
      8,
      4,
      6,
      15,
      11,
      1,
      10,
      9,
      3,
      14,
      5,
      0,
      12,
      7,
      1,
      15,
      13,
      8,
      10,
      3,
      7,
      4,
      12,
      5,
      6,
      11,
      0,
      14,
      9,
      2,
      7,
      11,
      4,
      1,
      9,
      12,
      14,
      2,
      0,
      6,
      10,
      13,
      15,
      3,
      5,
      8,
      2,
      1,
      14,
      7,
      4,
      10,
      8,
      13,
      15,
      12,
      9,
      0,
      3,
      5,
      6,
      11
    ],
  ];

  static const List<int> _p = [
    15,
    6,
    19,
    20,
    28,
    11,
    27,
    16,
    0,
    14,
    22,
    25,
    4,
    17,
    30,
    9,
    1,
    7,
    23,
    13,
    31,
    26,
    2,
    8,
    18,
    12,
    29,
    5,
    21,
    10,
    3,
    24
  ];

  static const List<int> _fp = [
    39,
    7,
    47,
    15,
    55,
    23,
    63,
    31,
    38,
    6,
    46,
    14,
    54,
    22,
    62,
    30,
    37,
    5,
    45,
    13,
    53,
    21,
    61,
    29,
    36,
    4,
    44,
    12,
    52,
    20,
    60,
    28,
    35,
    3,
    43,
    11,
    51,
    19,
    59,
    27,
    34,
    2,
    42,
    10,
    50,
    18,
    58,
    26,
    33,
    1,
    41,
    9,
    49,
    17,
    57,
    25,
    32,
    0,
    40,
    8,
    48,
    16,
    56,
    24
  ];

  void _setKey(Uint8List newKey) {
    final keyBits = _permutate(_pc1, _stringToBitList(newKey));
    _l = keyBits.sublist(0, 28);
    _r = keyBits.sublist(28);
    _kn = List<List<int>>.generate(16, (_) => List<int>.filled(48, 0));

    for (var i = 0; i < 16; i++) {
      for (var j = 0; j < _leftRotations[i]; j++) {
        _l..add(_l.removeAt(0));
        _r..add(_r.removeAt(0));
      }
      _kn[i] = _permutate(_pc2, [..._l, ..._r]);
    }
  }

  List<int> _stringToBitList(Uint8List data) {
    final len = data.length * 8;
    final result = List<int>.filled(len, 0);
    var pos = 0;
    for (final byte in data) {
      for (var i = 7; i >= 0; i--) {
        result[pos++] = (byte >> i) & 1;
      }
    }
    return result;
  }

  Uint8List _bitListToBytes(List<int> data) {
    final result = Uint8List(data.length ~/ 8);
    var bitIndex = 0;
    var value = 0;
    var byteIndex = 0;
    for (final bit in data) {
      value = (value << 1) | (bit & 1);
      bitIndex++;
      if (bitIndex == 8) {
        result[byteIndex++] = value;
        bitIndex = 0;
        value = 0;
      }
    }
    return result;
  }

  List<int> _permutate(List<int> table, List<int> block) {
    return List<int>.generate(table.length, (i) => block[table[i]]);
  }

  List<int> _xor(List<int> a, List<int> b) {
    return List<int>.generate(a.length, (i) => a[i] ^ b[i]);
  }

  List<int> _desCrypt(List<int> block, int cryptType) {
    block = _permutate(_ip, block);
    _l = block.sublist(0, 32);
    _r = block.sublist(32);

    var iteration = cryptType == encrypt ? 0 : 15;
    final iterationAdjustment = cryptType == encrypt ? 1 : -1;

    for (var i = 0; i < 16; i++) {
      final tempR = List<int>.from(_r);
      _r = _permutate(_expansionTable, _r);
      _r = _xor(_r, _kn[iteration]);

      final bn = List<int>.filled(32, 0);
      var pos = 0;
      for (var j = 0; j < 8; j++) {
        final start = j * 6;
        final b = _r.sublist(start, start + 6);
        final m = (b[0] << 1) + b[5];
        final n = (b[1] << 3) + (b[2] << 2) + (b[3] << 1) + b[4];
        final v = _sbox[j][(m << 4) + n];
        bn[pos] = (v & 8) >> 3;
        bn[pos + 1] = (v & 4) >> 2;
        bn[pos + 2] = (v & 2) >> 1;
        bn[pos + 3] = v & 1;
        pos += 4;
      }

      _r = _permutate(_p, bn);
      _r = _xor(_r, _l);
      _l = tempR;
      iteration += iterationAdjustment;
    }

    _finalBlock = _permutate(_fp, [..._r, ..._l]);
    return _finalBlock;
  }

  Uint8List crypt(List<int> data, int cryptType) {
    final input = _ensureBytes(data);
    if (input.isEmpty) {
      return Uint8List(0);
    }
    if (input.length % blockSize != 0) {
      throw ArgumentError('Data length must be multiple of $blockSize bytes.');
    }

    var ivBits = _stringToBitList(iv);
    final builder = BytesBuilder(copy: false);
    var offset = 0;
    while (offset < input.length) {
      final blockBytes = input.sublist(offset, offset + blockSize);
      var blockBits = _stringToBitList(Uint8List.fromList(blockBytes));
      if (cryptType == encrypt) {
        blockBits = _xor(blockBits, ivBits);
      }

      var processed = _desCrypt(blockBits, cryptType);
      if (cryptType == decrypt) {
        processed = _xor(processed, ivBits);
        ivBits = List<int>.from(blockBits);
      } else {
        ivBits = List<int>.from(processed);
      }
      builder.add(_bitListToBytes(processed));
      offset += blockSize;
    }
    return builder.takeBytes();
  }
}

class PythonTripleDES extends TripleDES {
  PythonTripleDES(Uint8List key, Uint8List iv)
      : _key1 = Des(key.sublist(0, 8), iv),
        _key2 = Des(key.sublist(8, 16), iv),
        _key3 = key.length == 16
            ? Des(key.sublist(0, 8), iv)
            : Des(key.sublist(16, 24), iv),
        super(key, tripleDesModeCBC, iv, 'python');

  final Des _key1;
  final Des _key2;
  final Des _key3;

  @override
  Uint8List encrypt(Uint8List plaintext) {
    if (plaintext.isEmpty) {
      return Uint8List(0);
    }
    ensureBlockMultiple(plaintext);

    final result = BytesBuilder(copy: false);
    var offset = 0;
    while (offset < plaintext.length) {
      final block = Uint8List.fromList(
          plaintext.sublist(offset, offset + TripleDES.blockSize));
      var processed = _key1.crypt(block, Des.encrypt);
      processed = _key2.crypt(processed, Des.decrypt);
      processed = _key3.crypt(processed, Des.encrypt);
      final cipherBlock = Uint8List.fromList(processed);
      _key1.iv = cipherBlock;
      _key2.iv = cipherBlock;
      _key3.iv = cipherBlock;
      iv = cipherBlock;
      result.add(cipherBlock);
      offset += TripleDES.blockSize;
    }
    return result.takeBytes();
  }

  @override
  Uint8List decrypt(Uint8List ciphertext) {
    if (ciphertext.isEmpty) {
      return Uint8List(0);
    }
    ensureBlockMultiple(ciphertext);

    final result = BytesBuilder(copy: false);
    var offset = 0;
    while (offset < ciphertext.length) {
      final block = Uint8List.fromList(
          ciphertext.sublist(offset, offset + TripleDES.blockSize));
      final nextIv = Uint8List.fromList(block);
      var processed = _key3.crypt(block, Des.decrypt);
      processed = _key2.crypt(processed, Des.encrypt);
      processed = _key1.crypt(processed, Des.decrypt);
      _key1.iv = nextIv;
      _key2.iv = nextIv;
      _key3.iv = nextIv;
      iv = nextIv;
      result.add(processed);
      offset += TripleDES.blockSize;
    }
    return result.takeBytes();
  }
}
