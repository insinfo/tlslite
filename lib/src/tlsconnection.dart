import 'dart:collection';
import 'dart:io';
import 'dart:typed_data';

import 'constants.dart';
import 'defragmenter.dart';
import 'errors.dart';
import 'messages.dart';
import 'messagesocket.dart';
import 'recordlayer.dart';
import 'session.dart';
import 'sessioncache.dart';
import 'tls_protocol.dart';
import 'utils/codec.dart';

/// TODO Partial port of tlslite-ng's TLSConnection focused on message handling,
/// session caching, and SSLv2/SSLv3 record interoperability.
class TlsConnection extends MessageSocket {
  TlsConnection(Socket socket, {SessionCache? sessionCache})
      : this._(socket,
            sessionCache: sessionCache,
            defragmenter: _createHandshakeDefragmenter());

  /// Visible for tests so we can inject custom defragmenters or stub sockets.
  TlsConnection.testing(Socket socket,
      {SessionCache? sessionCache, required Defragmenter defragmenter})
      : this._(socket, sessionCache: sessionCache, defragmenter: defragmenter);

  TlsConnection._(Socket socket,
      {SessionCache? sessionCache, required Defragmenter defragmenter})
      : _sessionCache = sessionCache,
        super(socket, defragmenter);

  Session session = Session();
  SessionCache? _sessionCache;
  final Queue<(dynamic, Parser)> _pendingMessages = Queue();
  final Queue<TlsHandshakeMessage> _handshakeQueue = Queue();

  SessionCache? get sessionCache => _sessionCache;
  set sessionCache(SessionCache? value) => _sessionCache = value;

  /// Attempt to reuse a cached TLS session. Returns `true` on success.
  bool tryResumeSession(List<int> sessionId) {
    final cache = _sessionCache;
    if (cache == null) {
      return false;
    }
    final cached = cache.getOrNull(sessionId);
    if (cached == null) {
      return false;
    }
    session = cached;
    return true;
  }

  /// Store the current session in the cache if it is resumable.
  void cacheCurrentSession() {
    final cache = _sessionCache;
    if (cache == null) {
      return;
    }
    final current = session;
    if (!current.valid()) {
      return;
    }
    cache[current.sessionID] = current;
  }

  /// Drain and return up to [maxMessages] handshake fragments, respecting the
  /// SSLv2 short-circuit path and re-queuing any non-handshake records.
  Future<List<Uint8List>> drainHandshakeMessages({int maxMessages = 8}) async {
    if (maxMessages <= 0) {
      return const <Uint8List>[];
    }
    final fragments = <Uint8List>[];
    while (fragments.length < maxMessages) {
      final (header, parser) = await recvMessageBlocking();
      if (header.type != ContentType.handshake) {
        _pendingMessages.addLast((header, parser));
        break;
      }
      fragments.add(_consumeParser(parser));
    }
    return fragments;
  }

  /// Read and parse the next handshake message from the wire.
  ///
  /// When [allowedTypes] is provided, a [TLSUnexpectedMessage] is thrown if the
  /// received handshake type is not part of the expected set.
  Future<TlsHandshakeMessage> recvHandshakeMessage(
      {Iterable<TlsHandshakeType>? allowedTypes}) async {
    await _bufferHandshakeMessages(minMessages: 1);
    if (_handshakeQueue.isEmpty) {
      throw TLSUnexpectedMessage('Handshake queue is empty');
    }
    final message = _handshakeQueue.removeFirst();
    _validateHandshakeType(message, allowedTypes);
    return message;
  }

  /// Return up to [maxMessages] buffered handshake messages, reading from the
  /// network as needed.
  Future<List<TlsHandshakeMessage>> recvHandshakeFlight(
      {int maxMessages = 4, Iterable<TlsHandshakeType>? allowedTypes}) async {
    if (maxMessages <= 0) {
      return const <TlsHandshakeMessage>[];
    }
    final flight = <TlsHandshakeMessage>[];
    while (flight.length < maxMessages) {
      if (_handshakeQueue.isEmpty) {
        await _bufferHandshakeMessages(minMessages: 1);
        if (_handshakeQueue.isEmpty) {
          break;
        }
      }
      final message = _handshakeQueue.removeFirst();
      _validateHandshakeType(message, allowedTypes);
      flight.add(message);
    }
    return flight;
  }

  /// Push a parsed handshake message back to the front of the buffer so the
  /// next call to [recvHandshakeMessage] will see it again.
  void unreadHandshakeMessage(TlsHandshakeMessage message) {
    _handshakeQueue.addFirst(message);
  }

  /// Discard any buffered handshake messages.
  void clearBufferedHandshakes() {
    _handshakeQueue.clear();
  }

  /// Queue a handshake message without flushing so multiple messages can share
  /// the same record.
  Future<void> queueHandshakeMessage(TlsHandshakeMessage message) {
    final wire = Message(ContentType.handshake, message.serialize());
    return queueMessageBlocking(wire);
  }

  /// Send a single handshake message immediately.
  Future<void> sendHandshakeMessage(TlsHandshakeMessage message) async {
    await queueHandshakeMessage(message);
    await flushBlocking();
  }

  /// Send an entire handshake flight, coalescing messages into as few records
  /// as possible.
  Future<void> sendHandshakeFlight(
      Iterable<TlsHandshakeMessage> messages) async {
    for (final message in messages) {
      await queueHandshakeMessage(message);
    }
    await flushBlocking();
  }

  Uint8List _consumeParser(Parser parser) {
    final remaining = parser.getRemainingLength();
    if (remaining == 0) {
      return Uint8List(0);
    }
    return parser.getFixBytes(remaining);
  }

  @override
  Future<(dynamic, Parser)> recvMessage() {
    if (_pendingMessages.isNotEmpty) {
      return Future<(dynamic, Parser)>.value(_pendingMessages.removeFirst());
    }
    return super.recvMessage();
  }

  static Defragmenter _createHandshakeDefragmenter() {
    final defragmenter = Defragmenter();
    defragmenter.addDynamicSize(ContentType.handshake, 1, 3);
    defragmenter.addStaticSize(ContentType.alert, 2);
    defragmenter.addStaticSize(ContentType.change_cipher_spec, 1);
    return defragmenter;
  }

  Future<void> _bufferHandshakeMessages({int minMessages = 1}) async {
    if (minMessages <= 0) {
      return;
    }
    while (_handshakeQueue.length < minMessages) {
      final (header, parser) = await recvMessageBlocking();
      if (header.type != ContentType.handshake) {
        _pendingMessages.addLast((header, parser));
        if (_handshakeQueue.isEmpty) {
          throw TLSUnexpectedMessage(
              'Expected handshake message, received ${ContentType.toStr(header.type)}');
        }
        break;
      }
      final recordVersion = _inferRecordVersion(header);
      final fragment = _consumeParser(parser);
      if (fragment.isEmpty) {
        continue;
      }
      final parsed = TlsHandshakeMessage.parseFragment(fragment,
          recordVersion: recordVersion);
      if (parsed.isEmpty) {
        continue;
      }
      _handshakeQueue.addAll(parsed);
    }
  }

  TlsProtocolVersion _inferRecordVersion(dynamic header) {
    if (header is RecordHeader3) {
      return header.version;
    }
    if (header is RecordHeader2) {
      throw TLSUnsupportedError('SSLv2 handshake parsing not implemented');
    }
    return version;
  }

  void _validateHandshakeType(
      TlsHandshakeMessage message, Iterable<TlsHandshakeType>? allowedTypes) {
    if (allowedTypes == null || allowedTypes.isEmpty) {
      return;
    }
    if (allowedTypes.contains(message.handshakeType)) {
      return;
    }
    final expected = allowedTypes.map((type) => type.name).join(', ');
    throw TLSUnexpectedMessage(
        'Expected handshake type in {$expected}, got ${message.handshakeType.name}');
  }
}
