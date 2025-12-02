import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/session.dart';

void main() {
  group('Session', () {
    test('defaults are not resumable', () {
      final session = Session();
      expect(session.resumable, isFalse);
      expect(session.sessionID, isEmpty);
      expect(session.valid(), isFalse);
      expect(session.getCipherName(), isNull);
      expect(session.getMacName(), isNull);
    });

    test('create sets provided attributes', () {
      final session = Session();
      session.create(
        masterSecret: Uint8List.fromList([1, 2, 3]),
        sessionID: Uint8List.fromList([4, 5, 6]),
        cipherSuite: 0x002f,
        srpUsername: 'user',
        clientCertChain: null,
        serverCertChain: null,
        tackExt: null,
        tackInHelloExt: false,
        serverName: 'example.com',
        encryptThenMAC: true,
        extendedMasterSecret: true,
        appProto: Uint8List.fromList([7]),
        clAppSecret: Uint8List.fromList([8]),
        srAppSecret: Uint8List.fromList([9]),
      );

      expect(session.resumable, isTrue);
      expect(session.sessionID, hasLength(3));
      expect(session.encryptThenMAC, isTrue);
      expect(session.extendedMasterSecret, isTrue);
      expect(session.appProto, isNotEmpty);
      expect(session.valid(), isTrue);
    });

    test('setResumable enforces session id requirement', () {
      final session = Session();
      session.setResumable(true);
      expect(session.resumable, isFalse);

      session.sessionID = Uint8List.fromList([1]);
      session.setResumable(true);
      expect(session.resumable, isTrue);

      session.setResumable(false);
      expect(session.resumable, isFalse);
    });

    test('clone copies session fields', () {
      final session = Session();
      session.create(
        masterSecret: Uint8List.fromList([1]),
        sessionID: Uint8List.fromList([2]),
        cipherSuite: 0x002f,
        srpUsername: 'user',
        clientCertChain: null,
        serverCertChain: null,
        tackExt: null,
        tackInHelloExt: false,
        serverName: 'example.com',
      );

      final cloned = session.clone();
      expect(cloned.sessionID, equals(session.sessionID));
      expect(cloned.cipherSuite, equals(session.cipherSuite));
      expect(cloned.serverName, equals(session.serverName));
      expect(cloned.valid(), isTrue);
    });
  });

  group('Ticket', () {
    test('valid returns true while lifetime remains', () {
      final ticket = Ticket(
        ticket: Uint8List.fromList([1]),
        ticketLifetime: 10,
        masterSecret: Uint8List.fromList([2]),
        cipherSuite: 0x002f,
      );

      expect(ticket.valid(), isTrue);
    });
  });
}
