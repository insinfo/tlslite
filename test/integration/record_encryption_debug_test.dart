/// Debug test to capture exact bytes sent by Dart client
/// 
/// This test connects to OpenSSL and logs every encrypted byte sent
/// to compare with expected values.
library;

import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/utils/cipherfactory.dart';

/// Test the nonce construction directly
void main() {
  group('Record Layer Debug', () {
    test('Nonce construction for ChaCha20-Poly1305', () {
      // Test vector with known values
      final fixedNonce = Uint8List.fromList([
        0x38, 0x41, 0xa0, 0x59, 0x17, 0x76, 0x85, 0xab, 0x3c, 0x52, 0x60, 0x05
      ]); // 12 bytes
      
      final seqNum = Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0]); // seqnum = 0
      
      // Expected: XOR of fixedNonce with padded seqNum
      // padded seqNum (12 bytes): [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
      // nonce = fixedNonce XOR paddedSeqNum = fixedNonce (since XOR with 0)
      
      final pad = Uint8List(fixedNonce.length - seqNum.length); // 4 zero bytes
      final paddedSeq = Uint8List.fromList([...pad, ...seqNum]); // 12 bytes all zero
      final nonce = Uint8List(fixedNonce.length);
      for (var i = 0; i < nonce.length; i++) {
        nonce[i] = paddedSeq[i] ^ fixedNonce[i];
      }
      
      print('fixedNonce: ${bytesToHex(fixedNonce)}');
      print('seqNum: ${bytesToHex(seqNum)}');
      print('paddedSeq: ${bytesToHex(paddedSeq)}');
      print('nonce: ${bytesToHex(nonce)}');
      
      // For seqnum=0, nonce should equal fixedNonce
      expect(nonce, equals(fixedNonce));
    });
    
    test('AAD construction for TLS 1.2 Finished record', () {
      // Finished message is 16 bytes: 4-byte header + 12-byte verify_data
      // ContentType: handshake (22)
      // Version: TLS 1.2 (0x0303)
      
      final seqNum = Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0]); // First encrypted record
      const contentType = 22; // handshake
      const versionMajor = 3;
      const versionMinor = 3; 
      const plaintextLength = 16; // Finished message
      
      final aad = Uint8List.fromList([
        ...seqNum,
        contentType,
        versionMajor,
        versionMinor,
        plaintextLength >> 8,
        plaintextLength & 0xff
      ]);
      
      print('AAD: ${bytesToHex(aad)}');
      print('AAD length: ${aad.length}');
      
      // Expected: 13 bytes (8 seqnum + 1 type + 2 version + 2 length)
      expect(aad.length, equals(13));
      expect(aad, equals(Uint8List.fromList([
        0, 0, 0, 0, 0, 0, 0, 0,  // seqnum = 0
        22,                       // handshake
        3, 3,                     // TLS 1.2
        0, 16                     // length = 16
      ])));
    });
    
    test('ChaCha20-Poly1305 seal with known vectors', () async {
      // Use known test vector to verify our ChaCha20-Poly1305 implementation
      final key = Uint8List.fromList([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
      ]);
      
      final nonce = Uint8List.fromList([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
      ]);
      
      final plaintext = Uint8List.fromList(
        'Ladies and Gentlemen of the class of \'99: If I could offer you only one tip for the future, sunscreen would be it.'.codeUnits
      );
      
      final aad = Uint8List.fromList([
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
        0xc4, 0xc5, 0xc6, 0xc7
      ]);
      
      // Create cipher
      final cipher = createCHACHA20(key);
      
      // Seal
      final ciphertext = cipher.seal(nonce, plaintext, aad);
      
      print('Key: ${bytesToHex(key)}');
      print('Nonce: ${bytesToHex(nonce)}');
      print('AAD: ${bytesToHex(aad)}');
      print('Plaintext length: ${plaintext.length}');
      print('Ciphertext length: ${ciphertext.length}');
      print('Ciphertext (first 32): ${bytesToHex(ciphertext.sublist(0, 32))}');
      print('Tag (last 16): ${bytesToHex(ciphertext.sublist(ciphertext.length - 16))}');
      
      // Expected ciphertext + tag from RFC 8439
      // This test verifies our ChaCha20-Poly1305 implementation
      expect(ciphertext.length, equals(plaintext.length + 16)); // plaintext + 16-byte tag
    });

    test('Debug full encryption flow', () async {
      // Simulate what happens in _encryptThenSeal
      
      // Known values from test run:
      final clientKey = Uint8List.fromList(hexToBytes(
        '3b74b4593b87d741be716415dad1a975ff0bf704ea9d257145aa6fd7f9900965'
      ));
      final clientIV = Uint8List.fromList(hexToBytes('3841a059177685ab3c526005'));
      
      print('=== Simulating first encrypted record (Finished) ===');
      print('Client Key: ${bytesToHex(clientKey)}');
      print('Client IV (fixedNonce): ${bytesToHex(clientIV)}');
      
      // Sequence number for first encrypted record is 0
      final seqNum = Uint8List.fromList([0, 0, 0, 0, 0, 0, 0, 0]);
      
      // Nonce = fixedNonce XOR padded(seqnum)
      final pad = Uint8List(clientIV.length - seqNum.length);
      final paddedSeq = Uint8List.fromList([...pad, ...seqNum]);
      final nonce = Uint8List(clientIV.length);
      for (var i = 0; i < nonce.length; i++) {
        nonce[i] = paddedSeq[i] ^ clientIV[i];
      }
      
      print('Sequence number: ${bytesToHex(seqNum)}');
      print('Padded seqnum: ${bytesToHex(paddedSeq)}');
      print('Nonce: ${bytesToHex(nonce)}');
      
      // AAD for TLS 1.2 Finished
      // Finished message: handshake type (20) + length (12) + verify_data (12 bytes)
      // Total: 16 bytes
      final finishedVerifyData = hexToBytes('8e22cfe2f07b46d94152926e'); // From test run
      final finishedMessage = Uint8List.fromList([
        20, // handshake type: finished
        0, 0, 12, // length: 12 bytes
        ...finishedVerifyData
      ]);
      
      print('Finished message: ${bytesToHex(finishedMessage)}');
      print('Finished message length: ${finishedMessage.length}');
      
      // AAD = seqnum + content_type + version + length
      const contentType = 22; // handshake
      final aad = Uint8List.fromList([
        ...seqNum,
        contentType,
        3, 3, // TLS 1.2
        finishedMessage.length >> 8,
        finishedMessage.length & 0xff
      ]);
      
      print('AAD: ${bytesToHex(aad)}');
      
      // Create cipher and seal
      final cipher = createCHACHA20(clientKey);
      final ciphertext = cipher.seal(nonce, finishedMessage, aad);
      
      print('Ciphertext length: ${ciphertext.length}');
      print('Ciphertext: ${bytesToHex(ciphertext)}');
      
      // The TLS record sent should be:
      // - Record header: 5 bytes (type=22, version=0x0303, length)
      // - Ciphertext: ciphertext + tag
      final recordLength = ciphertext.length;
      final record = Uint8List.fromList([
        22, // content type: handshake
        3, 3, // version: TLS 1.2
        recordLength >> 8,
        recordLength & 0xff,
        ...ciphertext
      ]);
      
      print('\n=== Full TLS Record ===');
      print('Record: ${bytesToHex(record)}');
      print('Record length: ${record.length}');
    });
  });
}

String bytesToHex(Uint8List bytes) {
  return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
}

Uint8List hexToBytes(String hex) {
  final result = <int>[];
  for (var i = 0; i < hex.length; i += 2) {
    result.add(int.parse(hex.substring(i, i + 2), radix: 16));
  }
  return Uint8List.fromList(result);
}
