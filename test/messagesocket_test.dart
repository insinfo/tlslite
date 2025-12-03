import 'dart:collection';
import 'dart:io';
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:tlslite/src/constants.dart';
import 'package:tlslite/src/defragmenter.dart';
import 'package:tlslite/src/messagesocket.dart';
import 'package:tlslite/src/recordlayer.dart';
import 'package:tlslite/src/utils/codec.dart';

void main() {
  group('MessageSocket.recvMessage', () {
    test('bypasses defragmenter for SSLv2 records', () async {
      final harness = await _MessageSocketHarness.create();
      addTearDown(() async => harness.dispose());

      final header = RecordHeader2().create(3, 0)
        ..type = ContentType.handshake;
      final payload = Uint8List.fromList([0x01, 0x02, 0x03]);
      harness.socket.queueRecord(header, Parser(payload));

      final result = await harness.socket.recvMessage();

      expect(result.$1, same(header));
      expect(result.$2.getRemainingLength(), payload.length);
      expect(harness.defragmenter.addDataCalls, isZero);
    });

    test('recvMessageBlocking unwraps buffered fragments', () async {
      final harness = await _MessageSocketHarness.create();
      addTearDown(() async => harness.dispose());

      final payload = Uint8List.fromList([0x10, 0x20, 0x30]);
      harness.defragmenter.enqueueCompleteMessage(
        ContentType.handshake,
        payload,
      );

      final (header, parser) = await harness.socket.recvMessageBlocking();

      expect(header.type, equals(ContentType.handshake));
      expect(parser.getRemainingLength(), equals(payload.length));
      expect(parser.getFixBytes(payload.length), equals(payload));
    });
  });

  group('MessageSocket send helpers', () {
    test('sendMessageBlocking flushes buffered data', () async {
      final harness = await _MessageSocketHarness.create();
      addTearDown(() async => harness.dispose());

      final msg = Message(
        ContentType.handshake,
        Uint8List.fromList([0xAB, 0xCD]),
      );

      await harness.socket.sendMessageBlocking(msg);

      expect(harness.socket.sentRecords, hasLength(1));
      final sent = harness.socket.sentRecords.first;
      expect(sent.contentType, equals(ContentType.handshake));
      expect(sent.data, equals(msg.data));
    });
  });
}

class _StubDefragmenter extends Defragmenter {
  int addDataCalls = 0;
  final Queue<(int, Uint8List)> _queued = Queue();

  @override
  (int, Uint8List)? getMessage() {
    if (_queued.isEmpty) {
      return null;
    }
    return _queued.removeFirst();
  }

  @override
  void addData(int msgType, Uint8List data) {
    addDataCalls++;
    _queued.addLast((msgType, Uint8List.fromList(data)));
  }

  void enqueueCompleteMessage(int msgType, Uint8List data) {
    _queued.addLast((msgType, Uint8List.fromList(data)));
  }
}

class _TestMessageSocket extends MessageSocket {
  _TestMessageSocket(Socket socket, Defragmenter defragmenter)
      : super(socket, defragmenter);

  final Queue<(dynamic, Parser)> _records = Queue();
  final List<Message> sentRecords = [];

  void queueRecord(dynamic header, Parser parser) {
    _records.addLast((header, parser));
  }

  @override
  Future<(dynamic, Parser)> recvRecord() async {
    if (_records.isEmpty) {
      throw StateError('No queued records');
    }
    return _records.removeFirst();
  }

  @override
  Future<void> sendRecord(Message msg) async {
    sentRecords.add(
      Message(msg.contentType, Uint8List.fromList(msg.write())),
    );
    await super.sendRecord(msg);
  }
}

class _MessageSocketHarness {
  _MessageSocketHarness(this.socket, this.defragmenter, this._peerSocket);

  final _TestMessageSocket socket;
  final _StubDefragmenter defragmenter;
  final Socket _peerSocket;

  static Future<_MessageSocketHarness> create() async {
    final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    final client = await Socket.connect(server.address, server.port);
    final serverSide = await server.first;
    await server.close();

    final defragmenter = _StubDefragmenter();
    final socket = _TestMessageSocket(serverSide, defragmenter);
    return _MessageSocketHarness(socket, defragmenter, client);
  }

  Future<void> dispose() async {
    await socket.sock.close();
    await _peerSocket.close();
  }
}
