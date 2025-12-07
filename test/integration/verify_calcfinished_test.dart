/// Test to verify calcFinished produces same output as Python
library;

import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/src/mathtls.dart';
import 'package:tlslite/src/handshake_hashes.dart';

Uint8List hexToBytes(String hex) {
  final result = <int>[];
  for (var i = 0; i < hex.length; i += 2) {
    result.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }
  return Uint8List.fromList(result);
}

String bytesToHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

void main() {
  test('calcFinished matches Python', () {
   
    final masterSecret = hexToBytes('0d36cc66603f174aa02ac40bc0b9409c' * 3);  // 48 bytes
    final handshakeHash = hexToBytes('c9aa1a577adc995f6ceac734fa496a69dcc3dc26840725071101a82705142421');  // 32 bytes
    
    const version = [3, 3];  // TLS 1.2
    const cipherSuite = 0xcca8;  // ECDHE_RSA_CHACHA20_POLY1305
    
    // Python result: 19c4bb77418c53a177b75046
    final expectedVerifyData = hexToBytes('19c4bb77418c53a177b75046');
    
    // Create a fake HandshakeHashes that returns our test hash
    final fakeHashes = _FakeHandshakeHashes(handshakeHash);
    
    // Calculate verify_data
    final verifyData = calcFinished(version, masterSecret, cipherSuite, fakeHashes, true);
    
    print('Master Secret: ${bytesToHex(masterSecret)}');
    print('Handshake Hash: ${bytesToHex(handshakeHash)}');
    print('Cipher Suite: 0x${cipherSuite.toRadixString(16).padLeft(4, '0')}');
    print('Expected Verify Data (Python): ${bytesToHex(expectedVerifyData)}');
    print('Actual Verify Data (Dart): ${bytesToHex(verifyData)}');
    print('Match: ${bytesToHex(verifyData) == bytesToHex(expectedVerifyData)}');
    
    expect(verifyData, equals(expectedVerifyData));
  });
}

/// Fake HandshakeHashes that returns a fixed hash
class _FakeHandshakeHashes implements HandshakeHashes {
  final Uint8List _hash;
  
  _FakeHandshakeHashes(this._hash);
  
  @override
  Uint8List digest([String? hashName]) => _hash;
  
  @override
  void update(Uint8List data) {}
  
  @override
  HandshakeHashes copy() => this;
  
  @override
  Uint8List digestSSL(Uint8List masterSecret, Uint8List senderStr) {
    throw UnimplementedError();
  }
  
  @override
  void replaceWith(HandshakeHashes other) {
    // No-op for fake implementation
  }
}
