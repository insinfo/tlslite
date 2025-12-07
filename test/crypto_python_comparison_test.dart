// Test file to compare pure Dart crypto implementations with Python tlslite-ng
// This ensures our Dart port produces identical results to the original Python implementation


import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/chacha20_poly1305.dart';
import 'package:tlslite/src/utils/dart_aesgcm.dart' as dart_aesgcm;
import 'package:tlslite/src/utils/poly1305.dart';
import 'package:tlslite/src/utils/chacha.dart';
import 'package:tlslite/src/utils/tlshashlib.dart';
import 'package:tlslite/src/utils/tlshmac.dart';
import 'package:tlslite/src/mathtls.dart';

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

/// Path to executable
String get pythonPath => Platform.isWindows ? 'python' : 'python3';

/// Path to tlslite-ng directory
String get tlsliteNgPath => 'C:/MyDartProjects/tlslite/tlslite-ng';

/// Execute Python code and return the output
Future<String> runPython(String code) async {
  final fullCode = '''
import sys
sys.path.insert(0, '$tlsliteNgPath')
$code
''';

  final result = await Process.run(
    pythonPath,
    ['-c', fullCode],
    workingDirectory: tlsliteNgPath,
  );

  if (result.exitCode != 0) {
    throw Exception('Python execution failed: ${result.stderr}');
  }

  return result.stdout.toString().trim();
}

/// Run Python and get hex output
Future<String> runPythonHex(String code) async {
  return await runPython(code);
}

void main() {
  bool pythonAvailable = false;

  setUpAll(() async {
    // Check if Python is available
    try {
      final result = await Process.run(pythonPath, ['--version']);
      if (result.exitCode == 0) {
        pythonAvailable = true;
        print('Python available: ${result.stdout.toString().trim()}');
        
        // Check if tlslite-ng is importable
        final testImport = await Process.run(
          pythonPath,
          ['-c', 'import sys; sys.path.insert(0, "$tlsliteNgPath"); from tlslite.utils.chacha20_poly1305 import CHACHA20_POLY1305; print("OK")'],
        );
        if (testImport.exitCode != 0) {
          print('Warning: tlslite-ng import failed: ${testImport.stderr}');
          pythonAvailable = false;
        } else {
          print('tlslite-ng is importable');
        }
      }
    } catch (e) {
      print('Python not available: $e');
    }
  });

  group('ChaCha20 cipher comparison with Python', () {
    test('ChaCha20 encrypt matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final key = hex('0001020304050607 08090a0b0c0d0e0f 1011121314151617 18191a1b1c1d1e1f'.replaceAll(' ', ''));
      final nonce = hex('000000000000004a00000000');
      final plaintext = hex('4c6164696573');  // "Ladies"

      // Get Python result
      final pythonResult = await runPythonHex('''
from tlslite.utils.chacha import ChaCha

key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
nonce = bytearray.fromhex('000000000000004a00000000')
plaintext = bytearray.fromhex('4c6164696573')

cipher = ChaCha(key, nonce, counter=1)
ciphertext = cipher.encrypt(plaintext)
print(ciphertext.hex())
''');

      // Get Dart result
      final dartCipher = ChaCha(key, nonce, initialCounter: 1);
      final dartResult = dartCipher.encrypt(plaintext);

      expect(toHex(dartResult), equals(pythonResult),
        reason: 'ChaCha20 encrypt: Dart should match Python\n'
                'Dart:   ${toHex(dartResult)}\n'
                'Python: $pythonResult');
    });

    test('ChaCha20 decrypt matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final key = hex('0001020304050607 08090a0b0c0d0e0f 1011121314151617 18191a1b1c1d1e1f'.replaceAll(' ', ''));
      final nonce = hex('000000000000004a00000000');
      final ciphertext = hex('6e2e359a2568f980');

      // Get Python result
      final pythonResult = await runPythonHex('''
from tlslite.utils.chacha import ChaCha

key = bytearray.fromhex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
nonce = bytearray.fromhex('000000000000004a00000000')
ciphertext = bytearray.fromhex('6e2e359a2568f980')

cipher = ChaCha(key, nonce, counter=1)
plaintext = cipher.decrypt(ciphertext)
print(plaintext.hex())
''');

      // Get Dart result
      final dartCipher = ChaCha(key, nonce, initialCounter: 1);
      final dartResult = dartCipher.decrypt(ciphertext);

      expect(toHex(dartResult), equals(pythonResult),
        reason: 'ChaCha20 decrypt: Dart should match Python\n'
                'Dart:   ${toHex(dartResult)}\n'
                'Python: $pythonResult');
    });
  });

  group('Poly1305 comparison with Python', () {
    test('Poly1305 createTag matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final key = hex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b');
      final message = hex('43727970746f6772617068696320466f72756d2052657365617263682047726f7570');

      // Get Python result
      final pythonResult = await runPythonHex('''
from tlslite.utils.poly1305 import Poly1305

key = bytearray.fromhex('85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b')
message = bytearray.fromhex('43727970746f6772617068696320466f72756d2052657365617263682047726f7570')

poly = Poly1305(key)
tag = poly.create_tag(message)
print(tag.hex())
''');

      // Get Dart result
      final dartPoly = Poly1305(key);
      final dartResult = dartPoly.createTag(message);

      expect(toHex(dartResult), equals(pythonResult),
        reason: 'Poly1305 createTag: Dart should match Python\n'
                'Dart:   ${toHex(dartResult)}\n'
                'Python: $pythonResult');
    });
  });

  group('ChaCha20-Poly1305 AEAD comparison with Python', () {
    test('ChaCha20-Poly1305 seal matches Python (RFC 7539 vector)', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final key = hex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
      final nonce = hex('070000004041424344454647');
      final aad = hex('50515253c0c1c2c3c4c5c6c7');
      final plaintext = hex('4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e');

      // Get Python result
      final pythonResult = await runPythonHex('''
from tlslite.utils.chacha20_poly1305 import CHACHA20_POLY1305

key = bytearray.fromhex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
nonce = bytearray.fromhex('070000004041424344454647')
aad = bytearray.fromhex('50515253c0c1c2c3c4c5c6c7')
plaintext = bytearray.fromhex('4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e')

aead = CHACHA20_POLY1305(key, "python")
result = aead.seal(nonce, plaintext, aad)
print(result.hex())
''');

      // Get Dart result
      final dartAead = Chacha20Poly1305(key, 'dart');
      final dartResult = dartAead.seal(nonce, plaintext, aad);

      expect(toHex(dartResult), equals(pythonResult),
        reason: 'ChaCha20-Poly1305 seal: Dart should match Python\n'
                'Dart:   ${toHex(dartResult)}\n'
                'Python: $pythonResult');
    });

    test('ChaCha20-Poly1305 open matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final key = hex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');
      final nonce = hex('070000004041424344454647');
      final aad = hex('50515253c0c1c2c3c4c5c6c7');
      final ciphertextWithTag = hex('d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691');

      // Get Python result
      final pythonResult = await runPythonHex('''
from tlslite.utils.chacha20_poly1305 import CHACHA20_POLY1305

key = bytearray.fromhex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f')
nonce = bytearray.fromhex('070000004041424344454647')
aad = bytearray.fromhex('50515253c0c1c2c3c4c5c6c7')
ciphertext_with_tag = bytearray.fromhex('d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691')

aead = CHACHA20_POLY1305(key, "python")
result = aead.open(nonce, ciphertext_with_tag, aad)
print(result.hex() if result else "None")
''');

      // Get Dart result
      final dartAead = Chacha20Poly1305(key, 'dart');
      final dartResult = dartAead.open(nonce, ciphertextWithTag, aad);

      expect(dartResult, isNotNull);
      expect(toHex(dartResult!), equals(pythonResult),
        reason: 'ChaCha20-Poly1305 open: Dart should match Python\n'
                'Dart:   ${toHex(dartResult)}\n'
                'Python: $pythonResult');
    });

    test('ChaCha20-Poly1305 with empty plaintext matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final key = hex('0000000000000000000000000000000000000000000000000000000000000000');
      final nonce = hex('000000000000000000000000');
      final aad = Uint8List(0);
      final plaintext = Uint8List(0);

      // Get Python result
      final pythonResult = await runPythonHex('''
from tlslite.utils.chacha20_poly1305 import CHACHA20_POLY1305

key = bytearray(32)
nonce = bytearray(12)
aad = bytearray(0)
plaintext = bytearray(0)

aead = CHACHA20_POLY1305(key, "python")
result = aead.seal(nonce, plaintext, aad)
print(result.hex())
''');

      // Get Dart result
      final dartAead = Chacha20Poly1305(key, 'dart');
      final dartResult = dartAead.seal(nonce, plaintext, aad);

      expect(toHex(dartResult), equals(pythonResult),
        reason: 'ChaCha20-Poly1305 empty: Dart should match Python\n'
                'Dart:   ${toHex(dartResult)}\n'
                'Python: $pythonResult');
    });
  });

  group('AES-GCM comparison with Python', () {
    test('AES-GCM seal matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final key = hex('01010101010101010101010101010101');
      final nonce = hex('020202020202020202020202');
      final plaintext = hex('48656c6c6f20576f726c6421'); // "Hello World!"
      final aad = Uint8List(0);

      // Get Python result
      final pythonResult = await runPythonHex('''
from tlslite.utils.python_aesgcm import new

key = bytearray.fromhex('01010101010101010101010101010101')
nonce = bytearray.fromhex('020202020202020202020202')
plaintext = bytearray.fromhex('48656c6c6f20576f726c6421')
aad = bytearray(0)

aead = new(key)
result = aead.seal(nonce, plaintext, aad)
print(result.hex())
''');

      // Get Dart result
      final dartAead = dart_aesgcm.newAESGCM(key);
      final dartResult = dartAead.seal(nonce, plaintext, aad);

      expect(toHex(dartResult), equals(pythonResult),
        reason: 'AES-GCM seal: Dart should match Python\n'
                'Dart:   ${toHex(dartResult)}\n'
                'Python: $pythonResult');
    });

    test('AES-GCM open matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final key = hex('01010101010101010101010101010101');
      final nonce = hex('020202020202020202020202');
      final ciphertextWithTag = hex('27816817e65a295cf28e6d46cb910e757a313af67da75c40ba11d872df234bd4'); // from known test
      final aad = Uint8List(0);

      // Get Python result for plaintext "text to encrypt."
      final pythonResult = await runPythonHex('''
from tlslite.utils.python_aesgcm import new

key = bytearray.fromhex('01010101010101010101010101010101')
nonce = bytearray.fromhex('020202020202020202020202')
ciphertext_with_tag = bytearray.fromhex('27816817e65a295cf28e6d46cb910e757a313af67da75c40ba11d872df234bd4')
aad = bytearray(0)

aead = new(key)
result = aead.open(nonce, ciphertext_with_tag, aad)
print(result.hex() if result else "None")
''');

      // Get Dart result
      final dartAead = dart_aesgcm.newAESGCM(key);
      final dartResult = dartAead.open(nonce, ciphertextWithTag, aad);

      expect(dartResult, isNotNull);
      expect(toHex(dartResult!), equals(pythonResult),
        reason: 'AES-GCM open: Dart should match Python\n'
                'Dart:   ${toHex(dartResult)}\n'
                'Python: $pythonResult');
    });
  });

  group('TLS PRF comparison with Python', () {
    test('PRF (TLS 1.2) matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final secret = hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
      final label = 'test label';
      final seed = hex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf');
      final length = 48;

      // Get Python result
      final pythonResult = await runPythonHex('''
from tlslite.mathtls import PRF_1_2

secret = bytearray.fromhex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20')
label = b'test label'
seed = bytearray.fromhex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf')

result = PRF_1_2(secret, label, seed, $length)
print(bytearray(result).hex())
''');

      // Get Dart result
      final dartResult = prf12(secret, label.codeUnits, seed, length);

      expect(toHex(Uint8List.fromList(dartResult)), equals(pythonResult),
        reason: 'PRF_1_2: Dart should match Python\n'
                'Dart:   ${toHex(Uint8List.fromList(dartResult))}\n'
                'Python: $pythonResult');
    });

    test('Master secret derivation matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final preMasterSecret = hex('0303' + '00' * 46); // TLS 1.2 version + random
      final clientRandom = hex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf');
      final serverRandom = hex('c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf');

      // Get Python result
      final pythonResult = await runPythonHex('''
from tlslite.mathtls import calcMasterSecret

premasterSecret = bytearray.fromhex('0303' + '00' * 46)
clientRandom = bytearray.fromhex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf')
serverRandom = bytearray.fromhex('c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf')

# TLS 1.2 uses (3, 3)
result = calcMasterSecret((3, 3), 0, premasterSecret, clientRandom, serverRandom)
print(bytearray(result).hex())
''');

      // Get Dart result
      final dartResult = calcMasterSecret(
        [3, 3],
        0,
        preMasterSecret.toList(),
        clientRandom.toList(),
        serverRandom.toList(),
      );

      expect(toHex(Uint8List.fromList(dartResult)), equals(pythonResult),
        reason: 'calcMasterSecret: Dart should match Python\n'
                'Dart:   ${toHex(Uint8List.fromList(dartResult))}\n'
                'Python: $pythonResult');
    });

    test('Key expansion matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final masterSecret = hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30');
      final serverRandom = hex('c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf');
      final clientRandom = hex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf');
      final outputLength = 88; // For ChaCha20-Poly1305: 2*32 (keys) + 2*12 (IVs)

      // Get Python result
      final pythonResult = await runPythonHex('''
from tlslite.mathtls import PRF_1_2

masterSecret = bytearray.fromhex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30')
serverRandom = bytearray.fromhex('c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf')
clientRandom = bytearray.fromhex('a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf')

# Key expansion
keyBlock = PRF_1_2(masterSecret, b"key expansion", serverRandom + clientRandom, $outputLength)
print(bytearray(keyBlock).hex())
''');

      // Get Dart result
      final seed = Uint8List.fromList([...serverRandom, ...clientRandom]);
      final dartResult = prf12(masterSecret, 'key expansion'.codeUnits, seed, outputLength);

      expect(toHex(Uint8List.fromList(dartResult)), equals(pythonResult),
        reason: 'Key expansion: Dart should match Python\n'
                'Dart:   ${toHex(Uint8List.fromList(dartResult))}\n'
                'Python: $pythonResult');
    });

    test('Finished verify_data matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final masterSecret = hex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30');
      final handshakeHash = hex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'); // SHA-256 of empty

      // Get Python result for client finished
      final pythonResult = await runPythonHex('''
from tlslite.mathtls import PRF_1_2

masterSecret = bytearray.fromhex('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30')
handshakeHash = bytearray.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')

# Client Finished verify_data
verifyData = PRF_1_2(masterSecret, b"client finished", handshakeHash, 12)
print(bytearray(verifyData).hex())
''');

      // Get Dart result
      final dartResult = prf12(masterSecret, 'client finished'.codeUnits, handshakeHash, 12);

      expect(toHex(Uint8List.fromList(dartResult)), equals(pythonResult),
        reason: 'Finished verify_data: Dart should match Python\n'
                'Dart:   ${toHex(Uint8List.fromList(dartResult))}\n'
                'Python: $pythonResult');
    });
  });

  group('HMAC comparison with Python', () {
    test('HMAC-SHA256 matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final key = hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final data = hex('4869205468657265'); // "Hi There"

      // Get Python result
      final pythonResult = await runPythonHex('''
import hmac
import hashlib

key = bytes.fromhex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')
data = bytes.fromhex('4869205468657265')

result = hmac.new(key, data, hashlib.sha256).digest()
print(result.hex())
''');

      // Get Dart result
      final hmac = TlsHmac(key.toList(), digestmod: 'sha256');
      hmac.update(data.toList());
      final dartResult = hmac.digest();

      expect(toHex(dartResult), equals(pythonResult),
        reason: 'HMAC-SHA256: Dart should match Python\n'
                'Dart:   ${toHex(dartResult)}\n'
                'Python: $pythonResult');
    });

    test('HMAC-SHA384 matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final key = hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
      final data = hex('4869205468657265'); // "Hi There"

     
      final pythonResult = await runPythonHex('''
import hmac
import hashlib

key = bytes.fromhex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')
data = bytes.fromhex('4869205468657265')

result = hmac.new(key, data, hashlib.sha384).digest()
print(result.hex())
''');

      // Get Dart result
      final hmac = TlsHmac(key.toList(), digestmod: 'sha384');
      hmac.update(data.toList());
      final dartResult = hmac.digest();

      expect(toHex(dartResult), equals(pythonResult),
        reason: 'HMAC-SHA384: Dart should match Python\n'
                'Dart:   ${toHex(dartResult)}\n'
                'Python: $pythonResult');
    });
  });

  group('Hash comparison with Python', () {
    test('SHA-256 matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final data = hex('48656c6c6f20576f726c6421'); // "Hello World!"

      // Get Python result
      final pythonResult = await runPythonHex('''
import hashlib

data = bytes.fromhex('48656c6c6f20576f726c6421')
result = hashlib.sha256(data).digest()
print(result.hex())
''');

      // Get Dart result
      final hashObj = newHash('sha256', data.toList());
      final dartResult = hashObj.digest();

      expect(toHex(dartResult), equals(pythonResult),
        reason: 'SHA-256: Dart should match Python\n'
                'Dart:   ${toHex(dartResult)}\n'
                'Python: $pythonResult');
    });

    test('SHA-384 matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final data = hex('48656c6c6f20576f726c6421'); // "Hello World!"

      final pythonResult = await runPythonHex('''
import hashlib

data = bytes.fromhex('48656c6c6f20576f726c6421')
result = hashlib.sha384(data).digest()
print(result.hex())
''');

      // Get Dart result
      final hashObj = newHash('sha384', data.toList());
      final dartResult = hashObj.digest();

      expect(toHex(dartResult), equals(pythonResult),
        reason: 'SHA-384: Dart should match Python\n'
                'Dart:   ${toHex(dartResult)}\n'
                'Python: $pythonResult');
    });
  });

  group('Random data comparison with Python (stress test)', () {
    test('ChaCha20-Poly1305 with various sizes matches Python', () async {
      if (!pythonAvailable) {
        print('Skipping - Python not available');
        return;
      }

      final key = Uint8List.fromList(List.generate(32, (i) => i));
      final nonce = Uint8List.fromList(List.generate(12, (i) => i * 2));
      final aad = Uint8List.fromList(List.generate(13, (i) => i * 3));

      for (final size in [0, 1, 15, 16, 17, 63, 64, 65, 100]) {
        final plaintext = Uint8List.fromList(List.generate(size, (i) => i % 256));

        // Get Python result
        final pythonResult = await runPythonHex('''
from tlslite.utils.chacha20_poly1305 import CHACHA20_POLY1305

key = bytearray(range(32))
nonce = bytearray([i * 2 for i in range(12)])
aad = bytearray([i * 3 for i in range(13)])
plaintext = bytearray([i % 256 for i in range($size)])

aead = CHACHA20_POLY1305(key, "python")
result = aead.seal(nonce, plaintext, aad)
print(result.hex())
''');

        // Get Dart result
        final dartAead = Chacha20Poly1305(key, 'dart');
        final dartResult = dartAead.seal(nonce, plaintext, aad);

        expect(toHex(dartResult), equals(pythonResult),
          reason: 'ChaCha20-Poly1305 size $size: Dart should match Python\n'
                  'Dart:   ${toHex(dartResult)}\n'
                  'Python: $pythonResult');
      }
    });
  });
}
