import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/tlslite.dart';
import 'package:tlslite/src/messages.dart';
import 'package:tlslite/src/recordlayer.dart';
import 'package:tlslite/src/tls_protocol.dart';

void main() {
  group('TlsConnection Negotiation', () {
    test('Client rejects SHA256 CipherSuite on TLS 1.1', () async {
      // 1. Prepare ServerHello with TLS 1.1 and SHA256 suite
      // TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C
      final serverHello = TlsServerHello(
        serverVersion: const TlsProtocolVersion(3, 2), // TLS 1.1
        random: Uint8List(32),
        sessionId: Uint8List(0),
        cipherSuite: 0x003C,
        compressionMethod: 0,
      );
      
      // Serialize ServerHello into a Record
      final messageData = serverHello.serialize();
      final recordHeader = RecordHeader3().create(
        const TlsProtocolVersion(3, 2), 
        ContentType.handshake, 
        messageData.length
      );
      final recordData = recordHeader.write();
      
      final inputData = Uint8List.fromList([...recordData, ...messageData]);
      
      final input = MemoryBinaryInput(inputData);
      final output = MemoryBinaryOutput();
      
      final connection = TlsConnection.custom(input, output);
      
      // We expect handshake to fail with illegal_parameter
      try {
        await connection.handshakeClient(anonParams: true);
        fail('Should have thrown TLSLocalAlert');
      } on TLSLocalAlert catch (e) {
        expect(e.description, equals(AlertDescription.illegal_parameter));
      } catch (e) {
        fail('Unexpected exception: ' + e.toString());
      }
    });

    test('Client rejects ServerHello with lower version than supported', () async {
      // Client supports TLS 1.2 by default.
      // If Server responds with TLS 1.0 (3, 1) but we didn't offer it?
      // Actually TlsConnection offers 1.2 and 1.3 by default.
      // Let's force client to only support 1.2 and server responds with 1.1.
      
      final settings = HandshakeSettings(
        minVersion: (3, 3),
        maxVersion: (3, 3),
      );

      final serverHello = TlsServerHello(
        serverVersion: const TlsProtocolVersion(3, 2), // TLS 1.1
        random: Uint8List(32),
        sessionId: Uint8List(0),
        cipherSuite: 0x002F, // TLS_RSA_WITH_AES_128_CBC_SHA
        compressionMethod: 0,
      );
      
      final messageData = serverHello.serialize();
      final recordHeader = RecordHeader3().create(
        const TlsProtocolVersion(3, 2), 
        ContentType.handshake, 
        messageData.length
      );
      final recordData = recordHeader.write();
      
      final inputData = Uint8List.fromList([...recordData, ...messageData]);
      
      final input = MemoryBinaryInput(inputData);
      final output = MemoryBinaryOutput();
      
      final connection = TlsConnection.custom(input, output);
      
      try {
        await connection.handshakeClient(settings: settings, anonParams: true);
        fail('Should have thrown TLSLocalAlert');
      } on TLSLocalAlert catch (e) {
        // protocol_version or illegal_parameter
        expect(e.description, equals(AlertDescription.protocol_version));
      } catch (e) {
        fail('Unexpected exception: ' + e.toString());
      }
    });
  });
}
