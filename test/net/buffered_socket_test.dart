import 'dart:collection';
import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/net/buffered_socket.dart';

class _FakeSocket {
  final List<List<int>> sentChunks = <List<int>>[];
  final Queue<Uint8List> _incoming = Queue<Uint8List>();
  int recvCalls = 0;
  bool shutdownCalled = false;
  bool closed = false;
  dynamic timeout;

  Future<int> send(Uint8List data) async {
    sentChunks.add(List<int>.from(data));
    return data.length;
  }

  Future<void> sendall(Uint8List data) async {
    sentChunks.add(List<int>.from(data));
  }

  Future<Uint8List> recv(int size) async {
    recvCalls++;
    if (_incoming.isEmpty) {
      return Uint8List(0);
    }
    return _incoming.removeFirst();
  }

  void queueIncoming(List<int> data) {
    _incoming.add(Uint8List.fromList(data));
  }

  String getsockname() => 'sock';

  String getpeername() => 'peer';

  Future<void> settimeout(dynamic value) async {
    timeout = value;
  }

  dynamic gettimeout() => timeout;

  Future<void> setsockopt(dynamic level, dynamic optname, dynamic value) async {}

  Future<void> shutdown(dynamic how) async {
    shutdownCalled = true;
  }

  Future<void> close() async {
    closed = true;
  }
}

void main() {
  group('BufferedSocket', () {
    test('send passes through when buffering disabled', () async {
      final fake = _FakeSocket();
      final socket = BufferedSocket(fake);

      final written = await socket.send([1, 2, 3]);

      expect(written, equals(3));
      expect(fake.sentChunks, hasLength(1));
      expect(fake.sentChunks.single, equals([1, 2, 3]));
    });

    test('send buffers when bufferWrites is enabled', () async {
      final fake = _FakeSocket();
      final socket = BufferedSocket(fake)..bufferWrites = true;

      await socket.send([1, 2]);
      await socket.sendall([3, 4, 5]);

      expect(fake.sentChunks, isEmpty, reason: 'data should remain buffered');

      await socket.flush();

      expect(fake.sentChunks, hasLength(1));
      expect(fake.sentChunks.single, equals([1, 2, 3, 4, 5]));
    });

    test('recv reuses buffered data before touching transport', () async {
      final fake = _FakeSocket();
      fake.queueIncoming(List<int>.generate(10, (i) => i));
      final socket = BufferedSocket(fake);

      final first = await socket.recv(4);
      expect(first, equals([0, 1, 2, 3]));
      expect(fake.recvCalls, equals(1));

      final second = await socket.recv(4);
      expect(second, equals([4, 5, 6, 7]));
      expect(fake.recvCalls, equals(1), reason: 'should reuse buffered bytes');
    });

    test('shutdown flushes buffered data', () async {
      final fake = _FakeSocket();
      final socket = BufferedSocket(fake)..bufferWrites = true;

      await socket.send([9, 9]);
      await socket.shutdown('both');

      expect(fake.sentChunks, hasLength(1));
      expect(fake.sentChunks.single, equals([9, 9]));
      expect(fake.shutdownCalled, isTrue);
    });
  });
}
