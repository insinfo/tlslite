import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/tlslite.dart';

void main() {
  group('TlsConnection Custom Transport', () {
    test('Can instantiate TlsConnection with MemoryBinaryInput/Output', () async {
      final input = MemoryBinaryInput(Uint8List(0));
      final output = MemoryBinaryOutput();
      
      final connection = TlsConnection.custom(input, output);
      
      expect(connection, isNotNull);
      expect(connection.session, isNotNull);
    });

    test('Can write application data to MemoryBinaryOutput', () async {
      final input = MemoryBinaryInput(Uint8List(0));
      final output = MemoryBinaryOutput();
      
      final connection = TlsConnection.custom(input, output);
      
      // Simulate handshake established to allow writing app data
      // In a real scenario, we would need to mock the handshake state or perform it.
      // For this test, we just check if write calls the output.
      // However, TlsConnection.write encrypts data. Without handshake, it might fail or write cleartext depending on state.
      // By default, state is cleartext (null cipher).
      
      final data = Uint8List.fromList([1, 2, 3, 4]);
      await connection.write(data);
      
      // Check output
      // TLS Record Header (5 bytes) + Data (4 bytes)
      // Version (2) + Type (1) + Length (2)
      // Default version is 0.0? No, RecordLayer initializes version to 0.0.
      // RecordHeader3: Type(1) + Version(2) + Length(2)
      
      final bytes = output.toUint8List();
      expect(bytes.length, greaterThan(5));
      expect(bytes[0], equals(ContentType.application_data)); // Type
    });
  });
}
