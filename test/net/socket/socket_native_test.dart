import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/net/socket/socket_native_ffi.dart';

void main() {
  group('SocketNative TCP', () {
    test('exchanges payload with Dart ServerSocket', () async {
      final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
      addTearDown(() async => await server.close());

      final serverHandled = Completer<void>();
      final subscription = server.listen((socket) async {
        final data = await socket.first;
        expect(utf8.decode(data), equals('ping'));
        socket.add(utf8.encode('pong'));
        await socket.flush();
        await socket.close();
        serverHandled.complete();
      });
      addTearDown(() async => await subscription.cancel());

      final client = SocketNative(AF_INET, SOCK_STREAM, IPPROTO_TCP);
      addTearDown(() => client.close());
      client.connect(InternetAddress.loopbackIPv4.address, server.port);

      client.sendall(Uint8List.fromList(utf8.encode('ping')));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      final response = await Future<Uint8List>(() => client.recv(4));

      expect(utf8.decode(response), equals('pong'));
      await serverHandled.future.timeout(const Duration(seconds: 5));
    });
  });

  group('SocketNative UDP', () {
    test('sendto/recvfrom communicates with RawDatagramSocket', () async {
      final server = await RawDatagramSocket.bind(
        InternetAddress.loopbackIPv4,
        0,
      );
      addTearDown(() => server.close());

      final packetEchoed = Completer<void>();
      final subscription = server.listen((event) {
        if (event != RawSocketEvent.read) {
          return;
        }
        final datagram = server.receive();
        if (datagram == null) {
          return;
        }
        expect(utf8.decode(datagram.data), equals('ping'));
        server.send(datagram.data, datagram.address, datagram.port);
        packetEchoed.complete();
      });
      addTearDown(() async => await subscription.cancel());

      final client = SocketNative(AF_INET, SOCK_DGRAM, 0);
      addTearDown(() => client.close());
      final payload = Uint8List.fromList(utf8.encode('ping'));
      client.sendto(payload, InternetAddress.loopbackIPv4.address, server.port);

      await packetEchoed.future.timeout(const Duration(seconds: 5));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      final (data, host, port) = await Future<(Uint8List, String, int)>(
        () => client.recvfrom(64),
      );
      expect(utf8.decode(data), equals('ping'));
      expect(host, equals(InternetAddress.loopbackIPv4.address));
      expect(port, equals(server.port));
    });
  });
}
