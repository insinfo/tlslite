// Comprehensive tests to compare TLS record layer operations between Dart and Python
// This is designed to find the bug causing bad_record_mac errors

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/mathtls.dart';
import 'package:tlslite/src/utils/tlshmac.dart';
import 'package:tlslite/src/utils/chacha20_poly1305.dart';
import 'package:tlslite/src/utils/python_aesgcm.dart' as python_aesgcm;

/// Helper to convert hex string to Uint8List
Uint8List hex(String hexStr) {
  final cleaned = hexStr.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
  if (cleaned.length.isOdd) {
    throw ArgumentError('Hex string must have even length');
  }
  final out = Uint8List(cleaned.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    final byte = cleaned.substring(i * 2, i * 2 + 2);
    out[i] = int.parse(byte, radix: 16);
  }
  return out;
}

/// Helper to convert Uint8List to hex string
String toHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

/// Run Python code and return output
Future<String> runPython(String code) async {
  final pythonPath = 'C:/MyDartProjects/tlslite/tlslite-ng';
  final result = await Process.run(
    'python',
    ['-c', code],
    environment: {'PYTHONPATH': pythonPath},
  );
  if (result.exitCode != 0) {
    throw Exception('Python execution failed: ${result.stderr}');
  }
  // Remove \r\n and trim for Windows compatibility
  return (result.stdout as String).trim().replaceAll('\r', '');
}

/// Run Python code and return hex result
Future<String> runPythonHex(String code) async {
  return await runPython(code);
}

bool pythonAvailable = false;

void main() {
  setUpAll(() async {
    try {
      final result = await runPython('print("ok")');
      if (result == 'ok') {
        pythonAvailable = true;
        print('Python is available');
        
        // Check if tlslite is importable
        try {
          await runPython('from tlslite import *; print("tlslite ok")');
          print('tlslite-ng is importable');
        } catch (e) {
          print('Warning: tlslite-ng import issue: $e');
        }
      }
    } catch (e) {
      print('Python not available: $e');
    }
  });

  group('Sequence Number Encoding', () {
    test('Sequence number bytes encoding matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      // Test various sequence numbers
      for (final seqnum in [0, 1, 255, 256, 65535, 65536, 0x7FFFFFFF, 0xFFFFFFFF]) {
        final pythonResult = await runPythonHex('''
from tlslite.utils.codec import Writer

writer = Writer()
writer.add($seqnum, 8)  # 8 bytes big-endian
print(writer.bytes.hex())
''');

        // Dart implementation
        final dartBytes = Uint8List(8);
        var value = seqnum;
        for (int i = 7; i >= 0; i--) {
          dartBytes[i] = value & 0xFF;
          value >>= 8;
        }

        expect(toHex(dartBytes), equals(pythonResult),
          reason: 'Seqnum $seqnum: Dart encoding should match Python\n'
                  'Dart:   ${toHex(dartBytes)}\n'
                  'Python: $pythonResult');
      }
    });
  });

  group('AAD (Additional Authenticated Data) Construction', () {
    test('TLS 1.2 AAD construction matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final seqnum = 0;
      final contentType = 0x17; // application_data
      final versionMajor = 3;
      final versionMinor = 3;
      final plaintextLength = 100;

      final pythonResult = await runPythonHex('''
from tlslite.utils.codec import Writer

seqnum = $seqnum
contentType = $contentType
versionMajor = $versionMajor
versionMinor = $versionMinor
plaintextLen = $plaintextLength

# Build sequence number bytes
writer = Writer()
writer.add(seqnum, 8)
seqNumBytes = writer.bytes

# Build AAD exactly as Python tlslite-ng does
authData = seqNumBytes + bytearray([contentType,
                                     versionMajor,
                                     versionMinor,
                                     plaintextLen//256,
                                     plaintextLen%256])
print(authData.hex())
''');

      // Dart implementation
      final seqNumBytes = Uint8List(8);
      var value = seqnum;
      for (int i = 7; i >= 0; i--) {
        seqNumBytes[i] = value & 0xFF;
        value >>= 8;
      }

      final authData = Uint8List.fromList([
        ...seqNumBytes,
        contentType,
        versionMajor,
        versionMinor,
        plaintextLength >> 8,
        plaintextLength & 0xff
      ]);

      expect(toHex(authData), equals(pythonResult),
        reason: 'TLS 1.2 AAD: Dart should match Python\n'
                'Dart:   ${toHex(authData)}\n'
                'Python: $pythonResult');
    });

    test('AAD with various sequence numbers', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      for (final seqnum in [0, 1, 100, 65535, 0xFFFFFF]) {
        final contentType = 0x17;
        final plaintextLength = 50;

        final pythonResult = await runPythonHex('''
from tlslite.utils.codec import Writer

seqnum = $seqnum
writer = Writer()
writer.add(seqnum, 8)
seqNumBytes = writer.bytes

authData = seqNumBytes + bytearray([0x17, 3, 3, ${plaintextLength >> 8}, ${plaintextLength & 0xff}])
print(authData.hex())
''');

        final seqNumBytes = Uint8List(8);
        var value = seqnum;
        for (int i = 7; i >= 0; i--) {
          seqNumBytes[i] = value & 0xFF;
          value >>= 8;
        }

        final authData = Uint8List.fromList([
          ...seqNumBytes,
          contentType,
          3, 3,
          plaintextLength >> 8,
          plaintextLength & 0xff
        ]);

        expect(toHex(authData), equals(pythonResult),
          reason: 'AAD with seqnum $seqnum: Dart should match Python');
      }
    });
  });

  group('Nonce Construction', () {
    test('ChaCha20-Poly1305 nonce (XOR method) matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final fixedNonce = hex('070000004041424344454647');
      final seqnum = 0;

      final pythonResult = await runPythonHex('''
from tlslite.utils.codec import Writer

fixedNonce = bytearray.fromhex('070000004041424344454647')
seqnum = $seqnum

# Get seqnum bytes
writer = Writer()
writer.add(seqnum, 8)
seqNumBytes = writer.bytes

# XOR method for ChaCha20-Poly1305 (like TLS 1.3)
pad = bytearray(len(fixedNonce) - len(seqNumBytes))
paddedSeq = pad + seqNumBytes
nonce = bytearray(i ^ j for i, j in zip(paddedSeq, fixedNonce))
print(nonce.hex())
''');

      // Dart implementation
      final seqNumBytes = Uint8List(8);
      var value = seqnum;
      for (int i = 7; i >= 0; i--) {
        seqNumBytes[i] = value & 0xFF;
        value >>= 8;
      }

      final pad = Uint8List(fixedNonce.length - seqNumBytes.length);
      final paddedSeq = Uint8List.fromList([...pad, ...seqNumBytes]);
      final nonce = Uint8List(fixedNonce.length);
      for (var i = 0; i < nonce.length; i++) {
        nonce[i] = paddedSeq[i] ^ fixedNonce[i];
      }

      expect(toHex(nonce), equals(pythonResult),
        reason: 'ChaCha20 nonce (XOR): Dart should match Python\n'
                'Dart:   ${toHex(nonce)}\n'
                'Python: $pythonResult');
    });

    test('ChaCha20-Poly1305 nonce with various sequence numbers', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final fixedNonce = hex('000102030405060708090a0b');

      for (final seqnum in [0, 1, 2, 100, 255, 256, 65535, 0xFFFFFFFF]) {
        final pythonResult = await runPythonHex('''
from tlslite.utils.codec import Writer

fixedNonce = bytearray.fromhex('000102030405060708090a0b')
seqnum = $seqnum

writer = Writer()
writer.add(seqnum, 8)
seqNumBytes = writer.bytes

pad = bytearray(len(fixedNonce) - len(seqNumBytes))
paddedSeq = pad + seqNumBytes
nonce = bytearray(i ^ j for i, j in zip(paddedSeq, fixedNonce))
print(nonce.hex())
''');

        final seqNumBytes = Uint8List(8);
        var value = seqnum;
        for (int i = 7; i >= 0; i--) {
          seqNumBytes[i] = value & 0xFF;
          value >>= 8;
        }

        final pad = Uint8List(fixedNonce.length - seqNumBytes.length);
        final paddedSeq = Uint8List.fromList([...pad, ...seqNumBytes]);
        final nonce = Uint8List(fixedNonce.length);
        for (var i = 0; i < nonce.length; i++) {
          nonce[i] = paddedSeq[i] ^ fixedNonce[i];
        }

        expect(toHex(nonce), equals(pythonResult),
          reason: 'ChaCha20 nonce with seqnum $seqnum: Dart should match Python');
      }
    });

    test('AES-GCM nonce (concatenation method) matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final fixedNonce = hex('01020304'); // 4 bytes for AES-GCM
      final seqnum = 0;

      final pythonResult = await runPythonHex('''
from tlslite.utils.codec import Writer

fixedNonce = bytearray.fromhex('01020304')
seqnum = $seqnum

writer = Writer()
writer.add(seqnum, 8)
seqNumBytes = writer.bytes

# Concatenation method for AES-GCM
nonce = fixedNonce + seqNumBytes
print(nonce.hex())
''');

      final seqNumBytes = Uint8List(8);
      var value = seqnum;
      for (int i = 7; i >= 0; i--) {
        seqNumBytes[i] = value & 0xFF;
        value >>= 8;
      }

      final nonce = Uint8List.fromList([...fixedNonce, ...seqNumBytes]);

      expect(toHex(nonce), equals(pythonResult),
        reason: 'AES-GCM nonce (concat): Dart should match Python\n'
                'Dart:   ${toHex(nonce)}\n'
                'Python: $pythonResult');
    });
  });

  group('Key Derivation (TLS 1.2)', () {
    test('Key block expansion matches Python exactly', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      // Use consistent test values
      final masterSecret = hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30');
      final serverRandom = hex('c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf');
      final clientRandom = hex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf');
      
      // ChaCha20-Poly1305 needs: 2*32 (keys) + 2*12 (IVs) = 88 bytes
      final keyBlockLength = 88;

      final pythonResult = await runPythonHex('''
from tlslite.mathtls import PRF_1_2

masterSecret = bytearray.fromhex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30')
serverRandom = bytearray.fromhex('c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf')
clientRandom = bytearray.fromhex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf')

# Key expansion: seed is server_random || client_random
seed = serverRandom + clientRandom
keyBlock = PRF_1_2(masterSecret, b"key expansion", seed, $keyBlockLength)
print(bytearray(keyBlock).hex())
''');

      // Dart implementation
      final seed = Uint8List.fromList([...serverRandom, ...clientRandom]);
      final dartKeyBlock = prf12(masterSecret, 'key expansion'.codeUnits, seed, keyBlockLength);

      expect(toHex(Uint8List.fromList(dartKeyBlock)), equals(pythonResult),
        reason: 'Key block: Dart should match Python\n'
                'Dart:   ${toHex(Uint8List.fromList(dartKeyBlock))}\n'
                'Python: $pythonResult');

      // Also print individual keys/IVs for debugging
      print('Key block (${dartKeyBlock.length} bytes): ${toHex(Uint8List.fromList(dartKeyBlock))}');
      print('Client write key (32 bytes): ${toHex(Uint8List.fromList(dartKeyBlock.sublist(0, 32)))}');
      print('Server write key (32 bytes): ${toHex(Uint8List.fromList(dartKeyBlock.sublist(32, 64)))}');
      print('Client write IV (12 bytes): ${toHex(Uint8List.fromList(dartKeyBlock.sublist(64, 76)))}');
      print('Server write IV (12 bytes): ${toHex(Uint8List.fromList(dartKeyBlock.sublist(76, 88)))}');
    });

    test('Key material partitioning for ChaCha20-Poly1305', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final masterSecret = hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30');
      final serverRandom = hex('c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf');
      final clientRandom = hex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf');

      final pythonResult = await runPython('''
from tlslite.mathtls import PRF_1_2

masterSecret = bytearray.fromhex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30')
serverRandom = bytearray.fromhex('c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf')
clientRandom = bytearray.fromhex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf')

# ChaCha20-Poly1305: key=32, IV=12, no MAC
keyLength = 32
ivLength = 12
keyBlockLen = 2*keyLength + 2*ivLength

seed = serverRandom + clientRandom
keyBlock = PRF_1_2(masterSecret, b"key expansion", seed, keyBlockLen)
keyBlock = bytearray(keyBlock)

clientWriteKey = keyBlock[0:32]
serverWriteKey = keyBlock[32:64]
clientWriteIV = keyBlock[64:76]
serverWriteIV = keyBlock[76:88]

print("CLIENT_WRITE_KEY:" + clientWriteKey.hex())
print("SERVER_WRITE_KEY:" + serverWriteKey.hex())
print("CLIENT_WRITE_IV:" + clientWriteIV.hex())
print("SERVER_WRITE_IV:" + serverWriteIV.hex())
''');

      // Parse Python output
      final lines = pythonResult.split('\n');
      final pythonClientWriteKey = lines.firstWhere((l) => l.startsWith('CLIENT_WRITE_KEY:')).split(':')[1];
      final pythonServerWriteKey = lines.firstWhere((l) => l.startsWith('SERVER_WRITE_KEY:')).split(':')[1];
      final pythonClientWriteIV = lines.firstWhere((l) => l.startsWith('CLIENT_WRITE_IV:')).split(':')[1];
      final pythonServerWriteIV = lines.firstWhere((l) => l.startsWith('SERVER_WRITE_IV:')).split(':')[1];

      // Dart implementation
      final seed = Uint8List.fromList([...serverRandom, ...clientRandom]);
      final keyBlock = prf12(masterSecret, 'key expansion'.codeUnits, seed, 88);

      final dartClientWriteKey = toHex(Uint8List.fromList(keyBlock.sublist(0, 32)));
      final dartServerWriteKey = toHex(Uint8List.fromList(keyBlock.sublist(32, 64)));
      final dartClientWriteIV = toHex(Uint8List.fromList(keyBlock.sublist(64, 76)));
      final dartServerWriteIV = toHex(Uint8List.fromList(keyBlock.sublist(76, 88)));

      expect(dartClientWriteKey, equals(pythonClientWriteKey),
        reason: 'Client write key should match Python');
      expect(dartServerWriteKey, equals(pythonServerWriteKey),
        reason: 'Server write key should match Python');
      expect(dartClientWriteIV, equals(pythonClientWriteIV),
        reason: 'Client write IV should match Python');
      expect(dartServerWriteIV, equals(pythonServerWriteIV),
        reason: 'Server write IV should match Python');
    });
  });

  group('Complete Record Encryption (TLS 1.2 ChaCha20-Poly1305)', () {
    test('Single record encryption matches Python exactly', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      // Fixed test values
      final key = hex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
      final fixedNonce = hex('070000004041424344454647');
      final plaintext = hex('48656c6c6f20576f726c6421'); // "Hello World!"
      final seqnum = 0;
      final contentType = 0x17; // application_data

      final pythonResult = await runPython('''
from tlslite.utils.chacha20_poly1305 import CHACHA20_POLY1305
from tlslite.utils.codec import Writer

key = bytearray.fromhex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
fixedNonce = bytearray.fromhex('070000004041424344454647')
plaintext = bytearray.fromhex('48656c6c6f20576f726c6421')
seqnum = $seqnum
contentType = $contentType

# Build seqnum bytes
writer = Writer()
writer.add(seqnum, 8)
seqNumBytes = writer.bytes

# Build nonce (XOR method)
pad = bytearray(len(fixedNonce) - len(seqNumBytes))
paddedSeq = pad + seqNumBytes
nonce = bytearray(i ^ j for i, j in zip(paddedSeq, fixedNonce))

# Build AAD
plaintextLen = len(plaintext)
authData = seqNumBytes + bytearray([contentType, 3, 3, plaintextLen//256, plaintextLen%256])

# Encrypt
cipher = CHACHA20_POLY1305(key, "python")
ciphertext = cipher.seal(nonce, plaintext, authData)

print("NONCE:" + nonce.hex())
print("AAD:" + authData.hex())
print("CIPHERTEXT:" + bytearray(ciphertext).hex())
''');

      // Parse Python output
      final lines = pythonResult.split('\n');
      final pythonNonce = lines.firstWhere((l) => l.startsWith('NONCE:')).split(':')[1];
      final pythonAAD = lines.firstWhere((l) => l.startsWith('AAD:')).split(':')[1];
      final pythonCiphertext = lines.firstWhere((l) => l.startsWith('CIPHERTEXT:')).split(':')[1];

      // Dart implementation
      final seqNumBytes = Uint8List(8);
      var value = seqnum;
      for (int i = 7; i >= 0; i--) {
        seqNumBytes[i] = value & 0xFF;
        value >>= 8;
      }

      // Nonce (XOR method)
      final pad = Uint8List(fixedNonce.length - seqNumBytes.length);
      final paddedSeq = Uint8List.fromList([...pad, ...seqNumBytes]);
      final nonce = Uint8List(fixedNonce.length);
      for (var i = 0; i < nonce.length; i++) {
        nonce[i] = paddedSeq[i] ^ fixedNonce[i];
      }

      // AAD
      final authData = Uint8List.fromList([
        ...seqNumBytes,
        contentType,
        3, 3,
        plaintext.length >> 8,
        plaintext.length & 0xff
      ]);

      // Encrypt
      final cipher = Chacha20Poly1305(key, 'python');
      final ciphertext = cipher.seal(nonce, plaintext, authData);

      expect(toHex(nonce), equals(pythonNonce),
        reason: 'Nonce should match Python');
      expect(toHex(authData), equals(pythonAAD),
        reason: 'AAD should match Python');
      expect(toHex(ciphertext), equals(pythonCiphertext),
        reason: 'Ciphertext+tag should match Python\n'
                'Dart:   ${toHex(ciphertext)}\n'
                'Python: $pythonCiphertext');
    });

    test('Multiple consecutive records match Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final key = hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
      final fixedNonce = hex('000000000000000000000000');

      for (int seqnum = 0; seqnum < 5; seqnum++) {
        final plaintext = Uint8List.fromList(List.generate(20, (i) => (seqnum * 20 + i) % 256));
        final contentType = 0x17;

        final pythonResult = await runPython('''
from tlslite.utils.chacha20_poly1305 import CHACHA20_POLY1305
from tlslite.utils.codec import Writer

key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
fixedNonce = bytearray.fromhex('000000000000000000000000')
plaintext = bytearray([${plaintext.join(', ')}])
seqnum = $seqnum
contentType = $contentType

writer = Writer()
writer.add(seqnum, 8)
seqNumBytes = writer.bytes

pad = bytearray(len(fixedNonce) - len(seqNumBytes))
paddedSeq = pad + seqNumBytes
nonce = bytearray(i ^ j for i, j in zip(paddedSeq, fixedNonce))

plaintextLen = len(plaintext)
authData = seqNumBytes + bytearray([contentType, 3, 3, plaintextLen//256, plaintextLen%256])

cipher = CHACHA20_POLY1305(key, "python")
ciphertext = cipher.seal(nonce, plaintext, authData)

print(bytearray(ciphertext).hex())
''');

        // Dart
        final seqNumBytes = Uint8List(8);
        var value = seqnum;
        for (int i = 7; i >= 0; i--) {
          seqNumBytes[i] = value & 0xFF;
          value >>= 8;
        }

        final pad = Uint8List(fixedNonce.length - seqNumBytes.length);
        final paddedSeq = Uint8List.fromList([...pad, ...seqNumBytes]);
        final nonce = Uint8List(fixedNonce.length);
        for (var i = 0; i < nonce.length; i++) {
          nonce[i] = paddedSeq[i] ^ fixedNonce[i];
        }

        final authData = Uint8List.fromList([
          ...seqNumBytes,
          contentType,
          3, 3,
          plaintext.length >> 8,
          plaintext.length & 0xff
        ]);

        final cipher = Chacha20Poly1305(key, 'python');
        final ciphertext = cipher.seal(nonce, plaintext, authData);

        expect(toHex(ciphertext), equals(pythonResult),
          reason: 'Record $seqnum: Dart ciphertext should match Python');
      }
    });
  });

  group('Complete Record Decryption (TLS 1.2 ChaCha20-Poly1305)', () {
    test('Decrypt Python-encrypted record', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final key = hex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
      final fixedNonce = hex('070000004041424344454647');
      final originalPlaintext = hex('48656c6c6f20576f726c6421');
      final seqnum = 0;
      final contentType = 0x17;

      // Get ciphertext from Python
      final pythonCiphertext = await runPythonHex('''
from tlslite.utils.chacha20_poly1305 import CHACHA20_POLY1305
from tlslite.utils.codec import Writer

key = bytearray.fromhex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
fixedNonce = bytearray.fromhex('070000004041424344454647')
plaintext = bytearray.fromhex('48656c6c6f20576f726c6421')
seqnum = $seqnum

writer = Writer()
writer.add(seqnum, 8)
seqNumBytes = writer.bytes

pad = bytearray(len(fixedNonce) - len(seqNumBytes))
paddedSeq = pad + seqNumBytes
nonce = bytearray(i ^ j for i, j in zip(paddedSeq, fixedNonce))

plaintextLen = len(plaintext)
authData = seqNumBytes + bytearray([0x17, 3, 3, plaintextLen//256, plaintextLen%256])

cipher = CHACHA20_POLY1305(key, "python")
ciphertext = cipher.seal(nonce, plaintext, authData)
print(bytearray(ciphertext).hex())
''');

      // Decrypt with Dart
      final ciphertext = hex(pythonCiphertext);

      final seqNumBytes = Uint8List(8);
      var value = seqnum;
      for (int i = 7; i >= 0; i--) {
        seqNumBytes[i] = value & 0xFF;
        value >>= 8;
      }

      final pad = Uint8List(fixedNonce.length - seqNumBytes.length);
      final paddedSeq = Uint8List.fromList([...pad, ...seqNumBytes]);
      final nonce = Uint8List(fixedNonce.length);
      for (var i = 0; i < nonce.length; i++) {
        nonce[i] = paddedSeq[i] ^ fixedNonce[i];
      }

      // AAD uses plaintext length (ciphertext - 16 byte tag)
      final plaintextLen = ciphertext.length - 16;
      final authData = Uint8List.fromList([
        ...seqNumBytes,
        contentType,
        3, 3,
        plaintextLen >> 8,
        plaintextLen & 0xff
      ]);

      final cipher = Chacha20Poly1305(key, 'python');
      final decrypted = cipher.open(nonce, ciphertext, authData);

      expect(decrypted, isNotNull, reason: 'Decryption should succeed');
      expect(decrypted, equals(originalPlaintext),
        reason: 'Decrypted plaintext should match original');
    });
  });

  group('Finished Message Verify Data', () {
    test('Client Finished verify_data matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final masterSecret = hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30');
      final handshakeHash = hex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

      final pythonResult = await runPythonHex('''
from tlslite.mathtls import PRF_1_2

masterSecret = bytearray.fromhex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30')
handshakeHash = bytearray.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

verifyData = PRF_1_2(masterSecret, b"client finished", handshakeHash, 12)
print(bytearray(verifyData).hex())
''');

      final dartVerifyData = prf12(masterSecret, 'client finished'.codeUnits, handshakeHash, 12);

      expect(toHex(Uint8List.fromList(dartVerifyData)), equals(pythonResult),
        reason: 'Client Finished verify_data should match Python');
    });

    test('Server Finished verify_data matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final masterSecret = hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30');
      final handshakeHash = hex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');

      final pythonResult = await runPythonHex('''
from tlslite.mathtls import PRF_1_2

masterSecret = bytearray.fromhex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30')
handshakeHash = bytearray.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

verifyData = PRF_1_2(masterSecret, b"server finished", handshakeHash, 12)
print(bytearray(verifyData).hex())
''');

      final dartVerifyData = prf12(masterSecret, 'server finished'.codeUnits, handshakeHash, 12);

      expect(toHex(Uint8List.fromList(dartVerifyData)), equals(pythonResult),
        reason: 'Server Finished verify_data should match Python');
    });
  });

  group('Complete TLS 1.2 Handshake Message Encryption', () {
    test('Encrypted Finished message matches Python format', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      // Simulate the Finished message structure
      final verifyData = hex('0102030405060708090a0b0c'); // 12 bytes
      final finishedMessage = Uint8List.fromList([
        0x14, // Finished type
        0x00, 0x00, 0x0c, // Length = 12
        ...verifyData
      ]);

      final key = hex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
      final fixedNonce = hex('000000000000000000000000');
      final seqnum = 0;
      final contentType = 0x16; // Handshake

      final pythonResult = await runPythonHex('''
from tlslite.utils.chacha20_poly1305 import CHACHA20_POLY1305
from tlslite.utils.codec import Writer

# Finished message
finishedMessage = bytearray([0x14, 0x00, 0x00, 0x0c] + [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c])

key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
fixedNonce = bytearray.fromhex('000000000000000000000000')
seqnum = $seqnum
contentType = 0x16  # Handshake

writer = Writer()
writer.add(seqnum, 8)
seqNumBytes = writer.bytes

pad = bytearray(len(fixedNonce) - len(seqNumBytes))
paddedSeq = pad + seqNumBytes
nonce = bytearray(i ^ j for i, j in zip(paddedSeq, fixedNonce))

plaintextLen = len(finishedMessage)
authData = seqNumBytes + bytearray([contentType, 3, 3, plaintextLen//256, plaintextLen%256])

cipher = CHACHA20_POLY1305(key, "python")
ciphertext = cipher.seal(nonce, finishedMessage, authData)
print(bytearray(ciphertext).hex())
''');

      // Dart
      final seqNumBytes = Uint8List(8);
      var value = seqnum;
      for (int i = 7; i >= 0; i--) {
        seqNumBytes[i] = value & 0xFF;
        value >>= 8;
      }

      final pad = Uint8List(fixedNonce.length - seqNumBytes.length);
      final paddedSeq = Uint8List.fromList([...pad, ...seqNumBytes]);
      final nonce = Uint8List(fixedNonce.length);
      for (var i = 0; i < nonce.length; i++) {
        nonce[i] = paddedSeq[i] ^ fixedNonce[i];
      }

      final authData = Uint8List.fromList([
        ...seqNumBytes,
        contentType,
        3, 3,
        finishedMessage.length >> 8,
        finishedMessage.length & 0xff
      ]);

      final cipher = Chacha20Poly1305(key, 'python');
      final ciphertext = cipher.seal(nonce, finishedMessage, authData);

      expect(toHex(ciphertext), equals(pythonResult),
        reason: 'Encrypted Finished should match Python');
    });
  });

  group('AES-GCM Record Layer', () {
    // NOTE: AES-GCM comparison with Python is already covered in crypto_python_comparison_test.dart
    // The Python API for raw AES in ECB mode is complex, so we skip this specific test
    // The important record layer logic (nonce, AAD) is tested above with ChaCha20-Poly1305
    test('AES-GCM nonce and AAD construction', () {
      // Just verify our Dart implementation matches expected format
      final fixedNonce = hex('00000000');
      final seqnum = 1;
      final plaintext = hex('48656c6c6f');
      final contentType = 0x17;

      final seqNumBytes = Uint8List(8);
      var value = seqnum;
      for (int i = 7; i >= 0; i--) {
        seqNumBytes[i] = value & 0xFF;
        value >>= 8;
      }

      // AES-GCM nonce = fixed || explicit
      final nonce = Uint8List.fromList([...fixedNonce, ...seqNumBytes]);
      expect(nonce.length, equals(12), reason: 'AES-GCM nonce should be 12 bytes');
      
      // First 4 bytes = fixed nonce
      expect(nonce.sublist(0, 4), equals(fixedNonce));
      // Last 8 bytes = sequence number
      expect(nonce.sublist(4, 12), equals(seqNumBytes));

      final authData = Uint8List.fromList([
        ...seqNumBytes,
        contentType,
        3, 3,
        plaintext.length >> 8,
        plaintext.length & 0xff
      ]);
      expect(authData.length, equals(13), reason: 'TLS 1.2 AAD should be 13 bytes');
    });
  });
}
