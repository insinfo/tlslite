import 'dart:collection';
import 'dart:io';
import 'dart:typed_data';

import 'constants.dart';
import 'defragmenter.dart';
import 'errors.dart';
import 'handshake_hashes.dart';
import 'messages.dart';
import 'messagesocket.dart';
import 'net/security/pure_dart_with_ffi_socket/dart_tls_types.dart'
  show PureDartTlsMode;
import 'net/security/pure_dart_with_ffi_socket/tls_handshake_state.dart';
import 'recordlayer.dart';
import 'session.dart';
import 'sessioncache.dart';
import 'tls_protocol.dart';
import 'utils/codec.dart';
import 'utils/cryptomath.dart';

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
  final HandshakeHashes handshakeHashes = HandshakeHashes();
  final List<TlsNewSessionTicket> tls13Tickets = <TlsNewSessionTicket>[];
  PureDartTlsHandshakeStateMachine? _handshakeStateMachine;
  bool heartbeatSupported = false;
  bool heartbeatCanReceive = false;
  bool heartbeatCanSend = false;
  void Function(TlsHeartbeat message)? heartbeatResponseCallback;
  bool renegotiationAllowed = false;
  bool handshakeEstablished = false;

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
    current.tls13Tickets = List<TlsNewSessionTicket>.from(tls13Tickets);
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
        await _processNonHandshakeRecord(header, parser);
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

  Future<(dynamic, Parser)> _recvMessageInternal({bool bypassPending = false}) {
    if (!bypassPending && _pendingMessages.isNotEmpty) {
      return Future<(dynamic, Parser)>.value(_pendingMessages.removeFirst());
    }
    return super.recvMessage();
  }

  Future<(dynamic, Parser)> _recvMessageFromTransport() {
    return _recvMessageInternal(bypassPending: true);
  }

  @override
  Future<(dynamic, Parser)> recvMessage() {
    return _recvMessageInternal();
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
      final (header, parser) = await _recvMessageFromTransport();
      if (header.type != ContentType.handshake) {
        await _processNonHandshakeRecord(header, parser);
        continue;
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
      for (final message in parsed) {
        await _enforceTls13ExclusiveAlignment(message);
        if (await _rejectRenegotiationIfNeeded(message)) {
          continue;
        }
        await _advanceHandshakeState(message);
        if (await _handlePostHandshakeMessage(message)) {
          continue;
        }
        _updateHandshakeTranscript(message);
        _handshakeQueue.addLast(message);
      }
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

  Future<void> _processNonHandshakeRecord(dynamic header, Parser parser) async {
    await _ensureNoTls13Interleaving(header);
    final payload = _consumeParser(parser);
    if (header.type == ContentType.alert) {
      if (payload.isEmpty) {
        throw TLSDecodeError('Alert record truncated');
      }
      final alert = TlsAlert.parse(payload);
      throw TLSRemoteAlert(alert.description.code, alert.level.code);
    }
    if (header.type == ContentType.heartbeat) {
      await _handleHeartbeatRecord(payload);
      return;
    }
    _enqueuePendingRecord(header, payload);
  }

  void _enqueuePendingRecord(dynamic header, Uint8List payload) {
    _pendingMessages.addLast((header, Parser(Uint8List.fromList(payload))));
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

  bool _isRenegotiationAttempt(TlsHandshakeMessage message) {
    if (!handshakeEstablished) {
      return false;
    }
    final isHelloRequest =
        message.handshakeType == TlsHandshakeType.helloRequest && client;
    final isClientHello =
        message.handshakeType == TlsHandshakeType.clientHello && !client;
    return isHelloRequest || isClientHello;
  }

  Future<void> _handleHeartbeatRecord(Uint8List payload) async {
    final heartbeat = TlsHeartbeat.parse(payload);
    if (!heartbeatSupported) {
      await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
      throw TLSUnexpectedMessage(
          'Heartbeat message received without prior negotiation');
    }

    switch (heartbeat.messageType) {
      case HeartbeatMessageType.heartbeat_request:
        if (!heartbeatCanReceive) {
          await _sendAlert(
              AlertLevel.fatal, AlertDescription.unexpected_message);
          throw TLSUnexpectedMessage(
              'Heartbeat request received when peer_not_allowed_to_send');
        }
        if (heartbeat.padding.length < 16) {
          return;
        }
        final paddingLength = heartbeat.padding.length;
        final response = TlsHeartbeat(
          messageType: HeartbeatMessageType.heartbeat_response,
          payload: heartbeat.payload,
          padding: paddingLength == 0
              ? const <int>[]
              : getRandomBytes(paddingLength),
        );
        await queueMessageBlocking(
            Message(ContentType.heartbeat, response.serialize()));
        await flushBlocking();
        return;
      case HeartbeatMessageType.heartbeat_response:
        heartbeatResponseCallback?.call(heartbeat);
        return;
      default:
        await _sendAlert(AlertLevel.fatal, AlertDescription.illegal_parameter);
        throw TLSUnexpectedMessage(
            'Heartbeat message type ${heartbeat.messageType} unsupported');
    }
  }

  Future<void> _sendAlert(int level, int description) async {
    final writer = Writer();
    writer.add(level, 1);
    writer.add(description, 1);
    await sendMessageBlocking(
        Message(ContentType.alert, Uint8List.fromList(writer.bytes)));
  }

  Future<void> sendKeyUpdate({bool updateRequested = false}) async {
    if (!_isTls13Plus()) {
      throw TLSIllegalParameterException(
          'KeyUpdate is only defined for TLS 1.3 connections');
    }
    final activeSession = session;
    if (activeSession.clAppSecret.isEmpty ||
        activeSession.srAppSecret.isEmpty) {
      throw TLSInternalError(
          'Cannot send KeyUpdate before traffic secrets are available');
    }
    final update = TlsKeyUpdate(updateRequested: updateRequested);
    await sendHandshakeMessage(update);
    final (newClientSecret, newServerSecret) = calcTLS1_3KeyUpdateSender(
      activeSession.cipherSuite,
      activeSession.clAppSecret,
      activeSession.srAppSecret,
    );
    activeSession.clAppSecret = newClientSecret;
    activeSession.srAppSecret = newServerSecret;
  }

  Future<void> _ensureNoTls13Interleaving(dynamic header) async {
    if (!_isTls13Plus()) {
      return;
    }
    if (header.type == ContentType.handshake) {
      return;
    }
    if (!defragmenter.hasPending(ContentType.handshake)) {
      return;
    }
    await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
    throw TLSUnexpectedMessage(
        'Interleaved handshake and ${ContentType.toStr(header.type)} records during TLS 1.3 handshake');
  }

  Future<void> _enforceTls13ExclusiveAlignment(
      TlsHandshakeMessage message) async {
    if (!_isTls13Plus()) {
      return;
    }
    if (!_requiresExclusiveRecord(message.handshakeType)) {
      return;
    }
    if (!defragmenter.hasPending(ContentType.handshake)) {
      return;
    }
    await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
    throw TLSUnexpectedMessage(
        '${message.handshakeType.name} must be aligned to a single record in TLS 1.3');
  }

  bool _requiresExclusiveRecord(TlsHandshakeType type) {
    switch (type) {
      case TlsHandshakeType.clientHello:
      case TlsHandshakeType.serverHello:
      case TlsHandshakeType.helloRetryRequest:
      case TlsHandshakeType.finished:
      case TlsHandshakeType.keyUpdate:
        return true;
      default:
        return false;
    }
  }

  bool _isTls13Plus() => version > const TlsProtocolVersion(3, 3);

  Future<bool> _handlePostHandshakeMessage(
      TlsHandshakeMessage message) async {
    final isPostHandshake = message.handshakeType == TlsHandshakeType.keyUpdate ||
        message.handshakeType == TlsHandshakeType.newSessionTicket;
    if (!isPostHandshake) {
      return false;
    }
    if (!handshakeEstablished) {
      await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
      throw TLSUnexpectedMessage(
          '${message.handshakeType.name} received before handshake completion');
    }
    if (message is TlsKeyUpdate) {
      await _processKeyUpdate(message);
    } else if (message is TlsNewSessionTicket) {
      _storeNewSessionTicket(message);
    }
    return true;
  }

  Future<void> _processKeyUpdate(TlsKeyUpdate keyUpdate) async {
    if (!_isTls13Plus()) {
      await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
      throw TLSUnexpectedMessage('KeyUpdate requires TLS 1.3');
    }
    final activeSession = session;
    if (activeSession.cipherSuite == 0 ||
        activeSession.clAppSecret.isEmpty ||
        activeSession.srAppSecret.isEmpty) {
      await _sendAlert(AlertLevel.fatal, AlertDescription.internal_error);
      throw TLSUnexpectedMessage(
          'KeyUpdate received before traffic secrets were established');
    }
    final (newClientSecret, newServerSecret) = calcTLS1_3KeyUpdateReceiver(
      activeSession.cipherSuite,
      activeSession.clAppSecret,
      activeSession.srAppSecret,
    );
    activeSession.clAppSecret = newClientSecret;
    activeSession.srAppSecret = newServerSecret;
    if (keyUpdate.updateRequested) {
      await sendKeyUpdate(updateRequested: false);
    }
  }

  void _storeNewSessionTicket(TlsNewSessionTicket ticket) {
    tls13Tickets.add(ticket);
    session.tls13Tickets = List<TlsNewSessionTicket>.from(tls13Tickets);
  }

  void _updateHandshakeTranscript(TlsHandshakeMessage message) {
    if (_shouldSkipTranscript(message)) {
      return;
    }
    handshakeHashes.update(message.serialize());
  }

  bool _shouldSkipTranscript(TlsHandshakeMessage message) {
    if (!handshakeEstablished) {
      return false;
    }
    switch (message.handshakeType) {
      case TlsHandshakeType.keyUpdate:
      case TlsHandshakeType.newSessionTicket:
        return true;
      default:
        return false;
    }
  }

  Future<bool> _rejectRenegotiationIfNeeded(
      TlsHandshakeMessage message) async {
    if (!_isRenegotiationAttempt(message)) {
      return false;
    }
    if (renegotiationAllowed) {
      return false;
    }
    await _sendAlert(AlertLevel.warning, AlertDescription.no_renegotiation);
    return true;
  }

  Future<void> _advanceHandshakeState(TlsHandshakeMessage message) async {
    if (handshakeEstablished) {
      return;
    }
    if (_shouldBypassHandshakeState(message.handshakeType)) {
      return;
    }
    final machine = _handshakeStateMachine ??=
        PureDartTlsHandshakeStateMachine(mode: _handshakeMode);
    try {
      machine.processIncoming(<TlsHandshakeMessage>[message]);
    } on StateError catch (error) {
      await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
      throw TLSUnexpectedMessage(
          'Handshake sequencing error: ${error.message}');
    }
    if (!handshakeEstablished && machine.isHandshakeComplete) {
      handshakeEstablished = true;
    }
  }

  PureDartTlsMode get _handshakeMode =>
      client ? PureDartTlsMode.client : PureDartTlsMode.server;

  bool _shouldBypassHandshakeState(TlsHandshakeType type) {
    switch (type) {
      case TlsHandshakeType.clientHello:
      case TlsHandshakeType.serverHello:
      case TlsHandshakeType.finished:
        return false;
      default:
        return true;
    }
  }
}
