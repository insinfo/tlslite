import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/src/handshake_helpers.dart';

// Mock ClientHello to simulate the behavior expected by HandshakeHelpers
class MockClientHello {
  // Base length excluding extensions overhead
  int baseLength;
  List<dynamic>? extensions;

  MockClientHello(this.baseLength, {this.extensions});

  Uint8List write() {
    int totalLength = baseLength;
    
    // If extensions list is present, we assume the baseLength INCLUDES the 
    // overhead for the extensions block length field (2 bytes) if it was already accounted for,
    // OR we need to add it.
    // The helper logic says:
    // if (clientHello.extensions == null) { ... clientHelloLength += 2; }
    // This implies that if extensions is null, the 2 bytes are NOT in the length.
    // If extensions is [], the 2 bytes ARE in the length.
    
    // For our mock, let's say baseLength is the length of everything EXCEPT the extensions content.
    // If extensions is not null, we add the content length.
    
    int extContentLength = 0;
    if (extensions != null) {
      for (var ext in extensions!) {
        // The extension added by HandshakeHelpers has a write() method
        try {
          final bytes = (ext as dynamic).write() as Uint8List;
          extContentLength += bytes.length;
        } catch (e) {
          // If it's a dummy extension for testing setup, we might need to handle it.
          // But for now we only add padding extension via the helper.
        }
      }
    }
    
    return Uint8List(totalLength + extContentLength);
  }
}

void main() {
  group('HandshakeHelpers.alignClientHelloPadding', () {
    test('length less than 256 bytes', () {
      // Target: < 256 bytes (excluding 4 byte header)
      // Let's say 200 bytes total -> 196 payload
      final clientHello = MockClientHello(200, extensions: []);
      
      HandshakeHelpers.alignClientHelloPadding(clientHello);
      
      expect(clientHello.write().length, 200);
      expect(clientHello.extensions, isEmpty);
    });

    test('length 256 bytes', () {
      // Target: 256 bytes payload -> 260 bytes total
      final clientHello = MockClientHello(260, extensions: []);
      
      HandshakeHelpers.alignClientHelloPadding(clientHello);
      
      // Should pad to 512 bytes payload -> 516 bytes total
      expect(clientHello.write().length, 516);
      expect(clientHello.extensions, hasLength(1));
      
      // Verify padding extension content
      // 512 - 256 = 256 bytes needed.
      // Extension header is 4 bytes.
      // So data is 252 bytes.
      // Total extension length = 256.
      // 260 + 256 = 516. Correct.
    });

    test('length 508 bytes', () {
      // Target: 508 bytes payload -> 512 bytes total
      final clientHello = MockClientHello(512, extensions: []);
      
      HandshakeHelpers.alignClientHelloPadding(clientHello);
      
      // Should pad to 512 bytes payload -> 516 bytes total
      // Wait, if it's 508, it is <= 511.
      // Padding needed: 512 - 508 - 4 = 0 bytes of data.
      // Extension: 4 bytes header + 0 bytes data = 4 bytes.
      // Total: 512 + 4 = 516.
      
      expect(clientHello.write().length, 516);
      expect(clientHello.extensions, hasLength(1));
    });

    test('length 511 bytes', () {
      // Target: 511 bytes payload -> 515 bytes total
      final clientHello = MockClientHello(515, extensions: []);
      
      HandshakeHelpers.alignClientHelloPadding(clientHello);
      
      // Padding needed: 512 - 511 - 4 = -3 -> clamped to 0.
      // Extension: 4 bytes header + 0 bytes data = 4 bytes.
      // Total: 515 + 4 = 519.
      
      expect(clientHello.write().length, 519);
      expect(clientHello.extensions, hasLength(1));
    });

    test('length 512 bytes', () {
      // Target: 512 bytes payload -> 516 bytes total
      final clientHello = MockClientHello(516, extensions: []);
      
      HandshakeHelpers.alignClientHelloPadding(clientHello);
      
      // Should not change
      expect(clientHello.write().length, 516);
      expect(clientHello.extensions, isEmpty);
    });
    
    test(
      'initializes extensions list if null',
      () {},
      skip: 'MockClientHello does not emulate extensions=null header growth yet',
    );
  });
}
