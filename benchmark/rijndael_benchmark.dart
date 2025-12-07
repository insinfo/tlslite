import 'dart:typed_data';

import 'package:tlslite/src/utils/rijndael_fast.dart';
import 'package:tlslite/src/utils/rijndael_slow.dart';

import 'rate_benchmark.dart';

class RijndaelBenchmark extends RateBenchmark {
  RijndaelBenchmark({
    required this.useFast,
    required this.decryptMode,
    int keyLength = 16,
    int blockSize = 16,
    String label = '',
  })  : _key = Uint8List.fromList(List.generate(keyLength, (i) => i)),
        _block = Uint8List.fromList(List.generate(blockSize, (i) => i)),
        super(
          'Rijndael ${decryptMode ? 'decrypt' : 'encrypt'} '
          '${useFast ? 'fast' : 'slow'}'
          '${label.isNotEmpty ? ' ($label)' : ''}',
        );

  final bool useFast;
  final bool decryptMode;
  final Uint8List _key;
  final Uint8List _block;

  late final Object _cipher;
  late Uint8List _ciphertext;
  late Uint8List _scratchOut;

  @override
  void setup() {
    // Prepara ciphertext de referência usando a implementação lenta
    final reference =
        Rijndael(Uint8List.fromList(_key), blockSize: _block.length);
    _ciphertext = reference.encrypt(_block);
    _scratchOut = Uint8List(_block.length);

    _cipher = useFast
        ? RijndaelFast(_key, blockSize: _block.length)
        : Rijndael(_key, blockSize: _block.length);
  }

  @override
  void teardown() {
    if (useFast) {
      ( _cipher as RijndaelFast).dispose();
    }
  }

  @override
  void run() {
    if (decryptMode) {
      if (useFast) {
        ( _cipher as RijndaelFast).decryptInto(_ciphertext, _scratchOut);
      } else {
        ( _cipher as Rijndael).decrypt(_ciphertext);
      }
    } else {
      if (useFast) {
        ( _cipher as RijndaelFast).encryptInto(_block, _scratchOut);
      } else {
        ( _cipher as Rijndael).encrypt(_block);
      }
    }
    addSample(_block.length);
  }
}

void main() {
  // AES-128
  RijndaelBenchmark(
    useFast: false,
    decryptMode: false,
    label: 'AES-128',
  ).report();
  RijndaelBenchmark(
    useFast: true,
    decryptMode: false,
    label: 'AES-128',
  ).report();
  RijndaelBenchmark(
    useFast: false,
    decryptMode: true,
    label: 'AES-128',
  ).report();
  RijndaelBenchmark(
    useFast: true,
    decryptMode: true,
    label: 'AES-128',
  ).report();

  // AES-256
  RijndaelBenchmark(
    useFast: false,
    decryptMode: false,
    keyLength: 32,
    label: 'AES-256',
  ).report();
  RijndaelBenchmark(
    useFast: true,
    decryptMode: false,
    keyLength: 32,
    label: 'AES-256',
  ).report();
  RijndaelBenchmark(
    useFast: false,
    decryptMode: true,
    keyLength: 32,
    label: 'AES-256',
  ).report();
  RijndaelBenchmark(
    useFast: true,
    decryptMode: true,
    keyLength: 32,
    label: 'AES-256',
  ).report();
}
