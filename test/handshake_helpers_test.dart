import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/src/handshake_helpers.dart';
import 'package:tlslite/src/tls_protocol.dart';

// Mock ClientHello to simulate the behavior expected by HandshakeHelpers
class MockClientHello {
  // Base length excluding extensions overhead
  int baseLength;
  List<dynamic>? _extensions;
  final bool _baseIncludesExtLen;

  List<dynamic>? get extensions => _extensions;
  set extensions(List<dynamic>? value) => _extensions = value;

  MockClientHello(this.baseLength, {List<dynamic>? extensions})
      : _extensions = extensions,
        _baseIncludesExtLen = extensions != null;

  Uint8List write() {
    int totalLength = baseLength;

    // When extensions are present (even empty), account for the 2-byte length
    // field plus the encoded extensions themselves.
    int extContentLength = 0;
    if (_extensions != null) {
      if (!_baseIncludesExtLen) {
        totalLength += 2; // extensions length field was not counted in baseLength
      }
      for (var ext in _extensions!) {
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
    
    test('initializes extensions list if null', () {
      // When extensions are null, alignClientHelloPadding should create the list
      // and account for the 2-byte extensions length field before padding.
      final clientHello = MockClientHello(260, extensions: null);

      HandshakeHelpers.alignClientHelloPadding(clientHello);

      // Padding target is 512 bytes payload (516 total with header).
      // Starting length: 260 -> length without header is 256.
      // Adding the implicit extensions length field (+2) and padding extension (4+252)
      // should bring the total to 516.
      expect(clientHello.write().length, 516);
      expect(clientHello.extensions, isNotNull);
      expect(clientHello.extensions, hasLength(1));
    });
  });

  group('HandshakeHelpers.resolveLegacyProtocolVersion', () {
    test('returns negotiated value within configured window', () {
      final negotiated = HandshakeHelpers.resolveLegacyProtocolVersion(
        clientVersion: TlsProtocolVersion.tls11,
        minVersion: const (3, 1),
        maxVersion: const (3, 3),
      );

      expect(negotiated, equals(TlsProtocolVersion.tls11));
    });

    test('clamps to server maximum when client advertises higher', () {
      final negotiated = HandshakeHelpers.resolveLegacyProtocolVersion(
        clientVersion: TlsProtocolVersion.tls12,
        minVersion: const (3, 1),
        maxVersion: const (3, 2),
      );

      expect(negotiated, equals(TlsProtocolVersion.tls11));
    });

    test('returns null when client version is below minimum', () {
      final negotiated = HandshakeHelpers.resolveLegacyProtocolVersion(
        clientVersion: TlsProtocolVersion.tls10,
        minVersion: const (3, 2),
        maxVersion: const (3, 3),
      );

      expect(negotiated, isNull);
    });
  });
}
