import 'dart:collection';
import 'dart:io';
import 'dart:typed_data';

import 'constants.dart';
import 'defragmenter.dart';
import 'errors.dart';
import 'handshake_hashes.dart';
import 'handshake_helpers.dart';
import 'handshake_settings.dart';
import 'keyexchange.dart';
import 'messages.dart';
import 'messagesocket.dart';
import 'net/security/pure_dart_with_ffi_socket/dart_tls_types.dart'
    show PureDartTlsMode;
import 'net/security/pure_dart_with_ffi_socket/tls_extensions.dart';
import 'net/security/pure_dart_with_ffi_socket/tls_handshake_state.dart';
import 'recordlayer.dart';
import 'session.dart';
import 'sessioncache.dart';
import 'tls_protocol.dart';
import 'utils/codec.dart';
import 'utils/cryptomath.dart';
import 'mathtls.dart';

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
  HandshakeSettings handshakeSettings = HandshakeSettings();
  bool heartbeatSupported = false;
  bool heartbeatCanReceive = false;
  bool heartbeatCanSend = false;
  void Function(TlsHeartbeat message)? heartbeatResponseCallback;
  bool renegotiationAllowed = false;
  bool handshakeEstablished = false;
  HandshakeHashes? _preClientHelloHandshakeHash;
  int? _negotiatedClientHelloPskIndex;
  PskConfig? _negotiatedExternalPsk;
  Uint8List? _negotiatedClientHelloPskIdentity;

  /// Replace the active handshake settings after validation.
  void configureHandshakeSettings(HandshakeSettings settings) {
    settings.validate();
    handshakeSettings = settings;
  }

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
    tls13Tickets
      ..clear()
      ..addAll(session.tls13Tickets);
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
    _prepareHandshakeForSend(message);
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
        if (message is TlsClientHello) {
          _preClientHelloHandshakeHash = handshakeHashes.copy();
          await _maybeHandleInboundClientHelloPsk(message);
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

  void _prepareHandshakeForSend(TlsHandshakeMessage message) {
    if (message is TlsClientHello) {
      _prepareClientHelloForSend(message);
    }
  }

  void _prepareClientHelloForSend(TlsClientHello clientHello) {
    if (!client) {
      return;
    }
    final extensions = clientHello.extensions;
    if (extensions == null) {
      return;
    }
    final preSharedKeyExt = extensions.last;
    if (preSharedKeyExt is! TlsPreSharedKeyExtension) {
      return;
    }

    final orderedConfigs = _orderedClientHelloPskConfigs(preSharedKeyExt);
    final hasExternalPsk = orderedConfigs.isNotEmpty;
    final tls13Tickets = session.tls13Tickets;
    final resSecret = session.resumptionMasterSecret;
    final hasResumptionPsk =
        tls13Tickets.isNotEmpty && resSecret.isNotEmpty;

    if (!hasExternalPsk && !hasResumptionPsk) {
      return;
    }

    updateClientHelloPskBinders(
      clientHello: clientHello,
      pskConfigs: orderedConfigs,
      tickets: hasResumptionPsk ? tls13Tickets : null,
      resumptionMasterSecret: hasResumptionPsk ? resSecret : null,
    );
  }

  List<PskConfig> _orderedClientHelloPskConfigs(
      TlsPreSharedKeyExtension extension) {
    final configs = handshakeSettings.pskConfigs;
    if (configs.isEmpty) {
      return const <PskConfig>[];
    }
    final tickets = session.tls13Tickets;
    final ordered = <PskConfig>[];
    for (final identity in extension.identities) {
      if (_isTicketIdentity(identity.identity, tickets)) {
        continue;
      }
      final match = _findPskConfig(identity.identity);
      if (match == null) {
        throw TLSInternalError(
          'Missing PSK secret for ClientHello identity',
        );
      }
      ordered.add(match);
    }
    return ordered;
  }

  PskConfig? _findPskConfig(Uint8List identity) {
    for (final config in handshakeSettings.pskConfigs) {
      if (_bytesEqual(config.identity, identity)) {
        return config;
      }
    }
    return null;
  }

  bool _isTicketIdentity(
      Uint8List identity, List<TlsNewSessionTicket> tickets) {
    for (final ticket in tickets) {
      if (_bytesEqual(identity, ticket.ticket)) {
        return true;
      }
    }
    return false;
  }

  bool _bytesEqual(Uint8List a, Uint8List b) {
    if (identical(a, b)) {
      return true;
    }
    if (a.lengthInBytes != b.lengthInBytes) {
      return false;
    }
    for (var i = 0; i < a.lengthInBytes; i++) {
      if (a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  /// Compute Finished.verify_data mirroring tlslite-ng for TLS 1.2 and 1.3.
  Uint8List buildFinishedVerifyData({required bool forClient}) {
    if (_isTls13Plus()) {
      return _buildTls13FinishedVerifyData(forClient: forClient);
    }
    final activeSession = session;
    if (activeSession.masterSecret.isEmpty) {
      throw TLSInternalError('Master secret unavailable for Finished');
    }
    if (activeSession.cipherSuite == 0) {
      throw TLSInternalError('Cipher suite undefined for Finished');
    }
    final versionTuple = [version.major, version.minor];
    return calcFinished(
      versionTuple,
      activeSession.masterSecret,
      activeSession.cipherSuite,
      handshakeHashes,
      forClient,
    );
  }

  Uint8List _buildTls13FinishedVerifyData({required bool forClient}) {
    final activeSession = session;
    final secret =
        forClient ? activeSession.clHandshakeSecret : activeSession.srHandshakeSecret;
    if (secret.isEmpty) {
      throw TLSInternalError('Handshake traffic secret missing for TLS 1.3');
    }
    final hashName = _prfHashName();
    final digestLength = hashName == 'sha384' ? 48 : 32;
    final finishedKey = HKDF_expand_label(
      secret,
      Uint8List.fromList('finished'.codeUnits),
      Uint8List(0),
      digestLength,
      hashName,
    );
    final transcript = handshakeHashes.digest(hashName);
    return secureHMAC(finishedKey, transcript, hashName);
  }

  String _prfHashName() {
    return CipherSuite.sha384PrfSuites.contains(session.cipherSuite)
        ? 'sha384'
        : 'sha256';
  }

  /// Build the byte sequence that must be signed inside CertificateVerify.
  Uint8List buildCertificateVerifyBytes({
    required int signatureScheme,
    String peerTag = 'client',
    String keyType = 'rsa',
    Uint8List? premasterSecret,
    Uint8List? clientRandom,
    Uint8List? serverRandom,
  }) {
    final prfName = _prfHashName();
    return KeyExchange.calcVerifyBytes(
      version,
      handshakeHashes,
      signatureScheme,
      premasterSecret: premasterSecret,
      clientRandom: clientRandom,
      serverRandom: serverRandom,
      prfName: prfName,
      peerTag: peerTag,
      keyType: keyType,
    );
  }

  /// Snapshot current transcript for upcoming ClientHello binder verification.
  void snapshotPreClientHelloHash() {
    _preClientHelloHandshakeHash = handshakeHashes.copy();
  }

  /// Update the binders inside the ClientHello's pre_shared_key extension.
  void updateClientHelloPskBinders({
    required TlsClientHello clientHello,
    required List<PskConfig> pskConfigs,
    List<TlsNewSessionTicket>? tickets,
    Uint8List? resumptionMasterSecret,
  }) {
    if (pskConfigs.isEmpty &&
        (tickets == null || tickets.isEmpty) &&
        (resumptionMasterSecret == null ||
            resumptionMasterSecret.isEmpty)) {
      return;
    }
    HandshakeHelpers.updateBinders(
      clientHello,
      handshakeHashes,
      pskConfigs,
      tickets: tickets ?? session.tls13Tickets,
      resMasterSecret:
          resumptionMasterSecret ?? session.resumptionMasterSecret,
    );
  }

  /// Validate a PSK binder emitted by the peer.
  void verifyClientHelloPskBinder({
    required TlsClientHello clientHello,
    required int binderIndex,
    required Uint8List secret,
    required String hashName,
    bool external = true,
  }) {
    final base = _preClientHelloHandshakeHash ?? handshakeHashes;
    HandshakeHelpers.verifyBinder(
      clientHello,
      base,
      binderIndex,
      secret,
      hashName,
      external: external,
    );
    _preClientHelloHandshakeHash = null;
  }

  int? get negotiatedClientHelloPskIndex => _negotiatedClientHelloPskIndex;

  PskConfig? get negotiatedExternalPsk => _negotiatedExternalPsk;

  Uint8List? get negotiatedClientHelloPskIdentity {
    final identity = _negotiatedClientHelloPskIdentity;
    if (identity == null) {
      return null;
    }
    return Uint8List.fromList(identity);
  }

  Future<void> _maybeHandleInboundClientHelloPsk(
      TlsClientHello clientHello) async {
    if (client) {
      return;
    }
    _negotiatedClientHelloPskIndex = null;
    _negotiatedExternalPsk = null;
    _negotiatedClientHelloPskIdentity = null;

    if (handshakeSettings.pskConfigs.isEmpty) {
      return;
    }
    final extensions = clientHello.extensions;
    final preSharedKeyExt = extensions?.last;
    if (preSharedKeyExt is! TlsPreSharedKeyExtension) {
      return;
    }

    for (var i = 0; i < preSharedKeyExt.identities.length; i++) {
      final identity = preSharedKeyExt.identities[i];
      final config = _findPskConfig(identity.identity);
      if (config == null) {
        continue;
      }
      try {
        verifyClientHelloPskBinder(
          clientHello: clientHello,
          binderIndex: i,
          secret: config.secret,
          hashName: config.hash,
        );
      } on TLSIllegalParameterException {
        await _sendAlert(AlertLevel.fatal, AlertDescription.illegal_parameter);
        rethrow;
      }
      _negotiatedClientHelloPskIndex = i;
      _negotiatedExternalPsk = config;
      _negotiatedClientHelloPskIdentity =
          Uint8List.fromList(identity.identity);
      return;
    }
  }

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
