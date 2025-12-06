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
import 'tls_types.dart'
    show PureDartTlsMode;
import 'tls_extensions.dart';
import 'tls_handshake_state.dart';
import 'recordlayer.dart';
import 'session.dart';
import 'sessioncache.dart';
import 'tls_protocol.dart';
import 'utils/codec.dart';
import 'utils/cryptomath.dart';
import 'utils/rsakey.dart';
import 'utils/ecdsakey.dart';
import 'utils/eddsakey.dart';
import 'utils/dsakey.dart';
import 'mathtls.dart';
import 'x509certchain.dart';
import 'x509.dart';

import 'utils/binary_io.dart';

/// Port of tlslite-ng's TLSConnection with full TLS 1.2/1.3 handshake support,
/// session caching, PSK resumption, and SSLv2/SSLv3 record interoperability.
class TlsConnection extends MessageSocket {
  TlsConnection(Socket socket, {SessionCache? sessionCache})
      : this._(socket,
            sessionCache: sessionCache,
            defragmenter: _createHandshakeDefragmenter());

  /// Visible for tests so we can inject custom defragmenters or stub sockets.
  TlsConnection.testing(Socket socket,
      {SessionCache? sessionCache, required Defragmenter defragmenter})
      : this._(socket, sessionCache: sessionCache, defragmenter: defragmenter);

  /// Creates a TlsConnection over a custom transport (BinaryInput/BinaryOutput).
  /// This allows running TLS over non-socket streams, such as encapsulated protocols.
  TlsConnection.custom(
    BinaryInput input,
    BinaryOutput output, {
    SessionCache? sessionCache,
  }) : this._custom(
          input,
          output,
          sessionCache: sessionCache,
          defragmenter: _createHandshakeDefragmenter(),
        );

  TlsConnection._(Socket socket,
      {SessionCache? sessionCache, required Defragmenter defragmenter})
      : _sessionCache = sessionCache,
        super(socket, defragmenter) {
    // Use 0x0303 as the legacy record version for initial ClientHello records.
    version = const TlsProtocolVersion(3, 3);
  }

  TlsConnection._custom(
    BinaryInput input,
    BinaryOutput output, {
    SessionCache? sessionCache,
    required Defragmenter defragmenter,
  })  : _sessionCache = sessionCache,
        super.custom(input, output, defragmenter) {
    version = const TlsProtocolVersion(3, 3);
  }

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
  final Map<int, dynamic> _clientKeyShares = {};
  Uint8List clientRandom = Uint8List(0);
  Uint8List serverRandom = Uint8List(0);
  Uint8List? _pendingSharedSecret;
  TlsClientHello? _clientHelloMsg;
  TlsServerHello? _serverHelloMsg;

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
    _updateHandshakeTranscript(message);
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

  final List<int> _appDataBuffer = [];

  /// Send application data.
  Future<void> write(Uint8List data) async {
    await sendMessage(Message(ContentType.application_data, data));
  }

  /// Read application data.
  Future<Uint8List> read({int? max}) async {
    while (_appDataBuffer.isEmpty) {
       // Check pending messages first
       if (_pendingMessages.isNotEmpty) {
          final (header, parser) = _pendingMessages.first;
          if (header.type == ContentType.application_data) {
             _pendingMessages.removeFirst();
             _appDataBuffer.addAll(parser.getFixBytes(parser.getRemainingLength()));
             continue;
          } else {
             _pendingMessages.removeFirst();
             continue;
          }
       }

       final (header, parser) = await _recvMessageInternal();
       if (header.type == ContentType.application_data) {
          _appDataBuffer.addAll(parser.getFixBytes(parser.getRemainingLength()));
       } else if (header.type == ContentType.handshake) {
          // Handle handshake
          throw UnimplementedError('Handshake during read not supported yet');
       } else {
          await _processNonHandshakeRecord(header, parser);
       }
    }

    final count = max ?? _appDataBuffer.length;
    final actualCount = count < _appDataBuffer.length ? count : _appDataBuffer.length;
    final result = Uint8List.fromList(_appDataBuffer.sublist(0, actualCount));
    _appDataBuffer.removeRange(0, actualCount);
    return result;
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
      final effectiveRecordVersion =
          _isTls13Plus() ? const TlsProtocolVersion(3, 4) : recordVersion;
      final fragment = _consumeParser(parser);
      if (fragment.isEmpty) {
        continue;
      }
      final parsed = header is RecordHeader2
          ? _wrapSsl2HandshakeMessages(
              _parseSsl2HandshakeFragment(fragment),
            )
          : TlsHandshakeMessage.parseFragmentWithBytes(
              fragment,
              recordVersion: effectiveRecordVersion,
            );
      if (parsed.isEmpty) {
        continue;
      }
      for (final parsedMessage in parsed) {
        final message = parsedMessage.message;
        final rawBytes = parsedMessage.rawBytes;
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
        _updateHandshakeTranscript(message, rawBytes: rawBytes);
        _handshakeQueue.addLast(message);
      }
    }
  }

  TlsProtocolVersion _inferRecordVersion(dynamic header) {
    if (header is RecordHeader3) {
      return header.version;
    }
    if (header is RecordHeader2) {
      return header.version;
    }
    return version;
  }

  List<TlsHandshakeMessage> _parseSsl2HandshakeFragment(Uint8List fragment) {
    if (fragment.isEmpty) {
      throw TLSDecodeError('SSLv2 handshake fragment truncated');
    }
    final parser = Parser(fragment);
    final typeByte = parser.get(1);
    final handshakeType = TlsHandshakeType.fromByte(typeByte);
    if (handshakeType != TlsHandshakeType.clientHello) {
      throw TLSUnexpectedMessage(
        'SSLv2 handshake ${handshakeType.name} is not supported',
      );
    }
    final body = parser.getFixBytes(parser.getRemainingLength());
    final clientHello = TlsClientHello.parseSsl2(body);
    return <TlsHandshakeMessage>[clientHello];
  }

  List<TlsParsedHandshakeMessage> _wrapSsl2HandshakeMessages(
    List<TlsHandshakeMessage> messages,
  ) {
    if (messages.isEmpty) {
      return const <TlsParsedHandshakeMessage>[];
    }
    return messages
        .map(
          (message) => TlsParsedHandshakeMessage(
            message: message,
            rawBytes: message.serialize(),
          ),
        )
        .toList(growable: false);
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

  Future<void> handshakeClient({
    HandshakeSettings? settings,
    Session? session,
    String srpUsername = '',
    dynamic srpParams,
    Keypair? certParams,
    dynamic anonParams,
    String serverName = '',
    List<String> nextProtos = const [],
    bool reqTack = false,
    List<String> alpn = const [],
  }) async {
    client = true;
    handshakeSettings = settings ?? HandshakeSettings();
    this.session = session ?? Session();

    await _clientSendClientHello(
      handshakeSettings,
      this.session,
      srpUsername,
      srpParams,
      certParams,
      anonParams,
      serverName,
      nextProtos,
      reqTack,
      alpn,
    );

    // Receive ServerHello
    var message = await recvHandshakeMessage(
        allowedTypes: [TlsHandshakeType.serverHello]);
    
    if (message is! TlsServerHello) {
        await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
        throw TLSUnexpectedMessage('Expected ServerHello, got ${message.handshakeType.name}');
    }

    // Check for HelloRetryRequest (TLS 1.3)
    if (_bytesEqual(message.random, TLS_1_3_HRR)) {
        // Handle HRR
        final cookieExt = message.extensions?.byType(ExtensionType.cookie);
        Uint8List? cookie;
        if (cookieExt is TlsCookieExtension) {
            cookie = cookieExt.cookie;
        }

        final keyShareExt = message.extensions?.byType(ExtensionType.key_share);
        int? retryGroup;
        if (keyShareExt is TlsKeyShareExtension) {
            retryGroup = keyShareExt.serverShare?.group;
        }

        // Send ClientHello2
        await _clientSendClientHello(
          handshakeSettings,
          this.session,
          srpUsername,
          srpParams,
          certParams,
          anonParams,
          serverName,
          nextProtos,
          reqTack,
          alpn,
          cookie: cookie,
          retryGroup: retryGroup,
        );

        // Receive ServerHello (again)
        message = await recvHandshakeMessage(
            allowedTypes: [TlsHandshakeType.serverHello]);
        
        if (message is! TlsServerHello) {
            await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
            throw TLSUnexpectedMessage('Expected ServerHello after HRR, got ${message.handshakeType.name}');
        }
        
        if (_bytesEqual(message.random, TLS_1_3_HRR)) {
             await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
             throw TLSUnexpectedMessage('Second HelloRetryRequest received');
        }
    }

    await _clientHandleServerHello(message);

    if (_isTls13Plus()) {
        await _clientHandshake13(certParams);
    } else {
        await _clientHandshake12(certParams);
    }
  }

  Future<void> _clientHandleServerHello(TlsServerHello serverHello) async {
    // Version Negotiation
    var negotiatedVersion = serverHello.serverVersion;
    
    // Check Supported Versions (TLS 1.3)
    final supportedVersions = serverHello.extensions?.byType(ExtensionType.supported_versions);
    if (supportedVersions is TlsSupportedVersionsExtension) {
       if (supportedVersions.selectedVersion != null) {
           negotiatedVersion = supportedVersions.selectedVersion!;
       }
    }
    
    version = negotiatedVersion;

    // Validate version against settings
    final minV = TlsProtocolVersion(handshakeSettings.minVersion.$1, handshakeSettings.minVersion.$2);
    final maxV = TlsProtocolVersion(handshakeSettings.maxVersion.$1, handshakeSettings.maxVersion.$2);
    if (version < minV || version > maxV) {
        await _sendAlert(AlertLevel.fatal, AlertDescription.protocol_version);
        throw TLSLocalAlert(
            AlertDescription.protocol_version, AlertLevel.fatal,
            detailedMessage: 'Server selected version $version which is not in range [$minV, $maxV]');
    }

    _serverHelloMsg = serverHello;
    
    // Update Session
    session.cipherSuite = serverHello.cipherSuite;

    // Check if the cipher suite is valid for this version
    if (version < const TlsProtocolVersion(3, 3) &&
        CipherSuite.sha256Suites.contains(session.cipherSuite)) {
      await _sendAlert(AlertLevel.fatal, AlertDescription.illegal_parameter);
      throw TLSLocalAlert(
          AlertDescription.illegal_parameter, AlertLevel.fatal,
          detailedMessage: 'SHA256 cipher suite with TLS < 1.2');
    }
    
    serverRandom = serverHello.random;
    session.sessionID = serverHello.sessionId;
    
    // Extensions
    final extensions = serverHello.extensions;
    if (extensions != null) {
        // EMS
        if (extensions.byType(ExtensionType.extended_master_secret) != null) {
            session.extendedMasterSecret = true;
        }
        
        // Encrypt-then-MAC
        if (extensions.byType(ExtensionType.encrypt_then_mac) != null) {
            session.encryptThenMAC = true;
        }

        // Pre-Shared Key (TLS 1.3)
        if (version >= const TlsProtocolVersion(3, 4)) {
            final pskExt = extensions.byType(ExtensionType.pre_shared_key);
            if (pskExt is TlsServerPreSharedKeyExtension) {
                 _negotiatedClientHelloPskIndex = pskExt.selectedIdentity;
            }
        }
    }

    // Key Share (TLS 1.3)
    if (version >= const TlsProtocolVersion(3, 4)) {
        final keyShareExt = serverHello.extensions?.byType(ExtensionType.key_share);
        if (keyShareExt is TlsKeyShareExtension) {
             final serverShare = keyShareExt.serverShare;
             if (serverShare != null) {
                 final group = serverShare.group;
                 final privateKey = _clientKeyShares[group];
                 if (privateKey == null) {
                     throw TLSHandshakeFailure('Server selected unsupported group');
                 }
                 
                 if (GroupName.allKEM.contains(group)) {
                     final kem = KEMKeyExchange(group);
                     _pendingSharedSecret = kem.calcSharedKey(privateKey, serverShare.keyExchange);
                 } else {
                     final kex = ECDHKeyExchange(group, (version.major, version.minor));
                     _pendingSharedSecret = kex.calcSharedKey(privateKey, serverShare.keyExchange);
                 }
             }
        }
    }
  }

  Future<void> _clientHandshake12(Keypair? certParams) async {
      // Determine Key Exchange Method
      final suiteName = CipherSuite.ietfNames[session.cipherSuite] ?? '';
      final isDHE = suiteName.contains('_DHE_');
      final isECDHE = suiteName.contains('_ECDHE_');
      final isRSA = suiteName.contains('_RSA_');
      
      // Get accepted curves/groups from settings
      final acceptedCurves = _curveNamesToList(handshakeSettings);
      
      KeyExchange? keyExchange;
      if (isECDHE) {
          keyExchange = ECDHE_RSAKeyExchange(
              session.cipherSuite, 
              _clientHelloMsg, 
              _serverHelloMsg, 
              null,
              acceptedCurves: acceptedCurves.isNotEmpty ? acceptedCurves : null,
          );
      } else if (isDHE) {
          keyExchange = DHE_RSAKeyExchange(session.cipherSuite, _clientHelloMsg, _serverHelloMsg, null);
      } else if (isRSA) {
          keyExchange = RSAKeyExchange(session.cipherSuite, _clientHelloMsg, _serverHelloMsg, null);
      } else {
          // Fallback to RSA if unknown (or handle error)
          keyExchange = RSAKeyExchange(session.cipherSuite, _clientHelloMsg, _serverHelloMsg, null);
      }

      Uint8List? premasterSecret;
      TlsCertificateRequest? certificateRequest;
      bool sentNonEmptyCertificate = false;

      // Receive ServerCertificate (Optional)
      // Receive ServerKeyExchange (Optional)
      // Receive CertificateRequest (Optional)
      // Receive ServerHelloDone
      
      while (true) {
          var message = await recvHandshakeMessage();
          print('[DART-DEBUG] Received message: ${message.runtimeType}, handshakeType: ${message.handshakeType.name}');
          
          // Handle RawTlsHandshakeMessage by parsing into specific types
          if (message is RawTlsHandshakeMessage) {
              print('[DART-DEBUG] Message is RawTlsHandshakeMessage, converting...');
              final rawBody = message.serializeBody();
              switch (message.handshakeType) {
                  case TlsHandshakeType.serverHelloDone:
                      message = TlsServerHelloDone();
                      print('[DART-DEBUG] Converted to TlsServerHelloDone');
                      break;
                  case TlsHandshakeType.serverKeyExchange:
                      message = TlsServerKeyExchange.parse(
                          rawBody,
                          session.cipherSuite,
                          [version.major, version.minor],
                      );
                      print('[DART-DEBUG] Converted to TlsServerKeyExchange');
                      break;
                  case TlsHandshakeType.certificateStatus:
                      message = TlsCertificateStatus.parse(rawBody);
                      print('[DART-DEBUG] Converted to TlsCertificateStatus');
                      break;
                  default:
                      print('[DART-DEBUG] Unknown type, keeping as RawTlsHandshakeMessage');
                      // Keep as RawTlsHandshakeMessage, will be caught below
                      break;
              }
          } else {
              print('[DART-DEBUG] Message is NOT RawTlsHandshakeMessage, type: ${message.runtimeType}');
          }
          
          if (message is TlsServerHelloDone) {
              break;
          } else if (message is TlsCertificate) {
              // Parse Certificate Chain
              final certs = <X509>[];
              for (final certBytes in message.certificateChain) {
                  final x509 = X509();
                  x509.parseBinary(certBytes);
                  certs.add(x509);
              }
              session.serverCertChain = X509CertChain(certs);
              _validateCertificateChain(session.serverCertChain!);
          } else if (message is TlsCertificateStatus) {
              if (message.statusType == 1) { // ocsp
                  session.ocspResponse = Uint8List.fromList(message.ocspResponse);
              }
          } else if (message is TlsServerKeyExchange) {
              final pubKey = session.serverCertChain?.getEndEntityPublicKey();
              premasterSecret = keyExchange.processServerKeyExchange(pubKey, message);
              
              if (message.signature.isNotEmpty) {
                  if (pubKey == null) {
                      throw TLSHandshakeFailure('ServerKeyExchange signature present but no server certificate');
                  }
                  
                  final params = message.encodeParameters();
                  final signedData = Uint8List.fromList([
                      ...clientRandom,
                      ...serverRandom,
                      ...params
                  ]);
                  
                  bool valid = false;
                  final hashAlg = message.hashAlg;
                  final hashName = HashAlgorithm.toRepr(hashAlg);
                  if (hashName == null) {
                       throw TLSHandshakeFailure('Unknown hash algorithm in ServerKeyExchange');
                  }
                  
                  final hash = secureHash(signedData, hashName);

                  if (pubKey is RSAKey) {
                      valid = pubKey.verify(
                          Uint8List.fromList(message.signature),
                          hash,
                          hashAlg: hashName
                      );
                  } else if (pubKey is ECDSAKey) {
                      valid = pubKey.verify(
                          Uint8List.fromList(message.signature),
                          hash,
                          hashAlg: hashName
                      );
                  } else if (pubKey is DSAKey) {
                      valid = pubKey.verify(
                          Uint8List.fromList(message.signature),
                          hash
                      );
                  } else {
                      throw UnimplementedError('Unsupported server key type: ${pubKey.runtimeType}');
                  }
                  
                  if (!valid) {
                      throw TLSHandshakeFailure('ServerKeyExchange signature invalid');
                  }
              }
          } else if (message is TlsCertificateRequest) {
              certificateRequest = message;
          } else {
              await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
              throw TLSUnexpectedMessage('Unexpected message in TLS 1.2 handshake: ${message.handshakeType.name}');
          }
      }
      
      // Send Certificate (if requested)
      if (certificateRequest != null) {
          bool shouldSendCert = false;
          if (certParams != null && certParams.certificates.isNotEmpty) {
              final pubKey = certParams.key;
              int? certType;
              if (pubKey is RSAKey) {
                  certType = ClientCertificateType.rsa_sign;
              } else if (pubKey is ECDSAKey) {
                  certType = ClientCertificateType.ecdsa_sign;
              } else if (pubKey is DSAKey) {
                  certType = ClientCertificateType.dss_sign;
              }
              
              if (certType != null && 
                  (certificateRequest.certificateTypes.isEmpty || 
                   certificateRequest.certificateTypes.contains(certType))) {
                  shouldSendCert = true;
              }
          }

          if (shouldSendCert) {
              final certList = certParams!.certificates.map((c) => c.bytes).toList();
              final certMsg = TlsCertificate.tls12(certificateChain: certList);
              await sendHandshakeMessage(certMsg);
              sentNonEmptyCertificate = true;
          } else {
              // Send empty certificate if no suitable certificate available
              final certMsg = TlsCertificate.tls12(certificateChain: []);
              await sendHandshakeMessage(certMsg);
          }
      }

      // Send ClientKeyExchange
      if (premasterSecret == null) {
          if (keyExchange is RSAKeyExchange) {
               final pubKey = session.serverCertChain!.getEndEntityPublicKey();
               premasterSecret = keyExchange.processServerKeyExchange(pubKey, null);
          } else {
               throw TLSHandshakeFailure('Missing ServerKeyExchange for DHE/ECDHE');
          }
      }
      
      final clientKeyExchange = keyExchange.makeClientKeyExchange();
      
      await sendHandshakeMessage(clientKeyExchange);
      
      // Send CertificateVerify (if certificate was sent)
      if (sentNonEmptyCertificate) {
        final isTls12 = version >= const TlsProtocolVersion(3, 3);
        int? signatureScheme;
        String keyType;
        String? padding;
        String? hashAlg;

        if (certParams!.key is RSAKey) {
          signatureScheme =
              isTls12 ? SignatureScheme.rsa_pkcs1_sha256.value : null;
          padding = 'pkcs1';
          hashAlg = null; // Implicit in verifyBytes for RSA
          keyType = 'rsa';
        } else if (certParams.key is ECDSAKey) {
          signatureScheme =
              isTls12 ? SignatureScheme.ecdsa_secp256r1_sha256.value : null;
          padding = null;
          hashAlg = isTls12 ? 'sha256' : 'sha1';
          keyType = 'ecdsa';
        } else if (certParams.key is DSAKey) {
          signatureScheme =
              isTls12 ? SignatureScheme.dsa_sha256.value : null;
          padding = null;
          hashAlg = isTls12 ? 'sha256' : 'sha1';
          keyType = 'dsa';
        } else {
          throw UnimplementedError(
            'Unsupported client key type: ${certParams.key.runtimeType}',
          );
        }

        final verifyBytes = KeyExchange.calcVerifyBytes(
          version,
          handshakeHashes,
          signatureScheme ?? 0,
          keyType: keyType,
        );

        final signature = (certParams.key as dynamic).sign(
          verifyBytes,
          padding: padding,
          hashAlg: hashAlg,
        );

        final certVerify = TlsCertificateVerify(
          version: version,
          signature: signature,
          signatureScheme: signatureScheme,
        );

        await sendHandshakeMessage(certVerify);
      }

      // Derive master secret now that all pre-CCS handshake messages are hashed
      print('[DEBUG] extendedMasterSecret: ${session.extendedMasterSecret}');
      if (session.extendedMasterSecret) {
          session.masterSecret = calcKey(
              [version.major, version.minor],
              premasterSecret,
              session.cipherSuite,
              Uint8List.fromList('extended master secret'.codeUnits),
              handshakeHashes: handshakeHashes,
          );
      } else {
          session.masterSecret = calcMasterSecret(
              [version.major, version.minor],
              session.cipherSuite,
              premasterSecret,
              clientRandom, 
              serverRandom
          );
      }
      print('[DEBUG] masterSecret=${session.masterSecret.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');

      // Send ChangeCipherSpec
      await queueMessageBlocking(Message(ContentType.change_cipher_spec, Uint8List.fromList([1])));
      await flushBlocking();
      
      print('[DEBUG] About to calcPendingStates');
      print('[DEBUG] cipherSuite: 0x${session.cipherSuite.toRadixString(16)}');
      print('[DEBUG] masterSecret length: ${session.masterSecret.length}');
      print('[DEBUG] clientRandom length: ${clientRandom.length}');
      print('[DEBUG] serverRandom length: ${serverRandom.length}');
      print('[DEBUG] version: ${version.major}.${version.minor}');
      
      // Calculate pending states for encryption (keys derived from master secret)
      calcPendingStates(
        session.cipherSuite,
        Uint8List.fromList(session.masterSecret),
        clientRandom,
        serverRandom,
        null, // implementations
      );
      
      print('[DEBUG] calcPendingStates done');
      print('[DEBUG] BEFORE changeWriteState - encContext: ${getCipherName()}');
      
      // Switch to Application Keys (Write) - MUST be done BEFORE sending Finished
      changeWriteState();
      
      print('[DEBUG] AFTER changeWriteState - encContext: ${getCipherName()}');
      
      print('[DEBUG] changeWriteState done, about to send Finished');
      
      // Debug: print handshake hash before building verifyData
      final hashForDebug = handshakeHashes.digest('sha256');
      print('[DEBUG] handshakeHash (sha256 before Finished): ${hashForDebug.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
      
      // Send Finished (now encrypted)
      final verifyData = buildFinishedVerifyData(forClient: true);
      print('[DEBUG] verifyData: ${verifyData.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
      print('[DEBUG] verifyData length: ${verifyData.length}');
      await sendHandshakeMessage(TlsFinished(verifyData: verifyData));
      
      print('[DEBUG] Finished sent');
      // Receive ChangeCipherSpec
      print('[DEBUG] About to receive CCS. _pendingMessages.length=${_pendingMessages.length}');
      if (_pendingMessages.isNotEmpty) {
        final firstPending = _pendingMessages.first;
        print('[DEBUG] First pending message type: ${firstPending.$1.type}');
      }
      final pendingEncryptedHandshakes = <(dynamic, Uint8List)>[];
      while (true) {
        final (header, parser) = await recvRecord();
        print('[DEBUG] Received message type: ${header.type}'
              '${header is RecordHeader3 ? ', length=${header.length}' : ''}');

        if (header.type == ContentType.alert) {
          final alertBytes = parser.getFixBytes(parser.getRemainingLength());
          print('[DEBUG] Alert received: level=${alertBytes.isNotEmpty ? alertBytes[0] : "?"} desc=${alertBytes.length > 1 ? alertBytes[1] : "?"}');
          final alert = TlsAlert.parse(alertBytes);
          throw TLSRemoteAlert(alert.description.code, alert.level.code);
        }

        if (header.type == ContentType.change_cipher_spec) {
          changeReadState();
          for (final pending in pendingEncryptedHandshakes) {
            final (_, plaintext) = decryptRecordPayload(pending.$1, pending.$2);
            defragmenter.addData(ContentType.handshake, plaintext);
          }
          break;
        }

        if (header.type == ContentType.handshake) {
          final fragment = parser.getFixBytes(parser.getRemainingLength());
          if (!hasReadCipher) {
            try {
              final recordVersion =
                  header is RecordHeader3 ? header.version : version;
              // If parsing succeeds, treat it as plaintext and let the
              // defragmenter/handshake queue process it normally.
              TlsHandshakeMessage.parseFragment(
                fragment,
                recordVersion: recordVersion,
              );
              defragmenter.addData(ContentType.handshake, fragment);
              print('[DEBUG] Queued plaintext handshake before CCS '
                  '(len=${fragment.length})');
            } catch (_) {
              print('[DEBUG] Stashed encrypted handshake fragment (hex): '
                  '${fragment.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
              pendingEncryptedHandshakes.add((header, fragment));
            }
            continue;
          }

          // Otherwise, decrypt the encrypted handshake using the pending keys.
          changeReadState();
          print('[DEBUG] Encrypted handshake record (hex): '
              '${fragment.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
          final (_, plaintext) = decryptRecordPayload(header, fragment);
          defragmenter.addData(ContentType.handshake, plaintext);
          break;
        }

        await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
        throw TLSUnexpectedMessage('Expected ChangeCipherSpec');
      }
      
      // Receive Finished (tickets may arrive before it when not encrypted)
      TlsFinished? finishedMsg;
      final initialFinishedSnapshot = handshakeHashes.copy();
      var finishedHandshakeSnapshot = initialFinishedSnapshot;
      while (finishedMsg == null) {
        final msg = await recvHandshakeMessage(
          allowedTypes: [TlsHandshakeType.finished, TlsHandshakeType.newSessionTicket],
        );
        if (msg is TlsFinished) {
          finishedMsg = msg;
        } else if (msg is TlsNewSessionTicket) {
          session.tickets ??= <Ticket>[];
          session.tickets!.add(Ticket(
            ticket: msg.ticket,
            ticketLifetime: msg.ticketLifetime,
            masterSecret: session.masterSecret,
            cipherSuite: session.cipherSuite,
          ));
          final hh = handshakeHashes.digest('sha256');
          print('[DEBUG] processed NST before Finished, handshakeHash='
              '${hh.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
          finishedHandshakeSnapshot = handshakeHashes.copy();
        } else {
          await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
          throw TLSUnexpectedMessage('Expected Finished');
        }
      }
      
      // Verify Finished
      print('[DEBUG] received server Finished verifyData: '
          '${finishedMsg.verifyData.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
      final expectedVerifyData = calcFinished(
        [version.major, version.minor],
        session.masterSecret,
        session.cipherSuite,
        finishedHandshakeSnapshot,
        false,
      );
      print('[DEBUG] expected server Finished verifyData: '
          '${expectedVerifyData.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
      final altVerifyData = calcFinished(
        [version.major, version.minor],
        session.masterSecret,
        session.cipherSuite,
        initialFinishedSnapshot,
        false,
      );
      print('[DEBUG] expected (without NST) verifyData: '
          '${altVerifyData.map((b) => b.toRadixString(16).padLeft(2, '0')).join()}');
      if (!_bytesEqual(finishedMsg.verifyData, expectedVerifyData)) {
          await _sendAlert(AlertLevel.fatal, AlertDescription.decrypt_error);
          throw TLSHandshakeFailure('Finished verification failed');
      }
      
      handshakeEstablished = true;
  }

  Future<void> _clientHandshake13(Keypair? certParams) async {
      if (_pendingSharedSecret == null) {
          throw TLSHandshakeFailure('Missing shared secret for TLS 1.3');
      }
      final sharedSecret = _pendingSharedSecret!;
      _pendingSharedSecret = null;

      // Determine Hash Algorithm
      final hashName = _prfHashName();
      final hashLen = hashName == 'sha384' ? 48 : 32;
      
      // Calculate Early Secret
      Uint8List psk = Uint8List(hashLen); // 0-filled
      if (_negotiatedClientHelloPskIndex != null) {
          if (session.resumptionMasterSecret.isNotEmpty) {
              psk = session.resumptionMasterSecret;
          }
      }
      final earlySecret = secureHMAC(psk, Uint8List(hashLen), hashName); 
      
      // Derive Handshake Secret
      final derivedSecret = derive_secret(
          earlySecret, 
          Uint8List.fromList('derived'.codeUnits), 
          null, 
          hashName
      );
      
      final handshakeSecret = secureHMAC(derivedSecret, sharedSecret, hashName);
      
      // Calculate Client/Server Handshake Traffic Secrets
      final helloHash = handshakeHashes.digest(hashName);
      
      final clientHandshakeTrafficSecret = HKDF_expand_label(
          handshakeSecret,
          Uint8List.fromList('c hs traffic'.codeUnits),
          helloHash,
          hashLen,
          hashName
      );
      
      final serverHandshakeTrafficSecret = HKDF_expand_label(
          handshakeSecret,
          Uint8List.fromList('s hs traffic'.codeUnits),
          helloHash,
          hashLen,
          hashName
      );
      
      // Store secrets in session
      session.clHandshakeSecret = clientHandshakeTrafficSecret;
      session.srHandshakeSecret = serverHandshakeTrafficSecret;
      
      // Switch to Handshake Keys
      calcTLS1_3PendingState(
          session.cipherSuite,
          clientHandshakeTrafficSecret,
          serverHandshakeTrafficSecret,
          null
      );
      changeReadState();
      changeWriteState();
      
      // Receive EncryptedExtensions
      final encExtMsg = await recvHandshakeMessage(allowedTypes: [TlsHandshakeType.encryptedExtensions]);
      if (encExtMsg is TlsEncryptedExtensions) {
          // Process ALPN
          final alpnExt = encExtMsg.extensions.byType(ExtensionType.alpn);
          if (alpnExt is TlsAlpnExtension) {
              if (alpnExt.protocols.isNotEmpty) {
                  session.appProto = Uint8List.fromList(alpnExt.protocols.first.codeUnits);
              }
          }
      } else {
          await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
          throw TLSUnexpectedMessage('Expected EncryptedExtensions, got ${encExtMsg.handshakeType.name}');
      }

      bool certRequested = false;
      TlsCertificateRequest? certRequestMsg;

      // Receive CertificateRequest (Optional) or Certificate
      var message = await recvHandshakeMessage(allowedTypes: [
          TlsHandshakeType.certificateRequest,
          TlsHandshakeType.certificate
      ]);

      if (message is TlsCertificateRequest) {
          certRequested = true;
          certRequestMsg = message;
          message = await recvHandshakeMessage(allowedTypes: [TlsHandshakeType.certificate]);
      }

      if (message is! TlsCertificate) {
          await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
          throw TLSUnexpectedMessage('Expected Certificate, got ${message.handshakeType.name}');
      }
      
      // Parse Certificate Chain
      final certs = <X509>[];
      for (final entry in message.certificateEntries) {
          final x509 = X509();
          x509.parseBinary(entry.certificate);
          certs.add(x509);

          if (certs.length == 1 && entry.extensions.isNotEmpty) {
              try {
                  final extBlock = TlsExtensionBlock.fromBytes(
                      entry.extensions, 
                      context: TlsExtensionContext.certificate
                  );
                  final statusExt = extBlock.byType(ExtensionType.status_request);
                  if (statusExt is TlsCertificateStatusExtension) {
                      if (statusExt.statusType == 1) { // ocsp
                          session.ocspResponse = statusExt.response;
                      }
                  }
              } catch (_) {
                  // Ignore extension parsing errors
              }
          }
      }
      session.serverCertChain = X509CertChain(certs);
      _validateCertificateChain(session.serverCertChain!);
      
      // Receive CertificateVerify
      final certVerifyTranscript = handshakeHashes.copy();
      final certVerifyMsg = await recvHandshakeMessage(allowedTypes: [TlsHandshakeType.certificateVerify]);
      if (certVerifyMsg is! TlsCertificateVerify) {
          await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
          throw TLSUnexpectedMessage('Expected CertificateVerify, got ${certVerifyMsg.handshakeType.name}');
      }
      
      final pubKey = session.serverCertChain!.getEndEntityPublicKey();
      String keyType;
      if (pubKey is RSAKey) {
          keyType = 'rsa';
      } else if (pubKey is ECDSAKey) {
          keyType = 'ecdsa';
      } else {
          throw UnimplementedError('Unsupported key type: ${pubKey.runtimeType}');
      }

      // Verify Signature
      final verifyBytes = buildCertificateVerifyBytes(
          signatureScheme: certVerifyMsg.signatureScheme!,
          peerTag: 'server',
          keyType: keyType,
          handshakeSnapshot: certVerifyTranscript,
      );
      
      final schemeName = SignatureScheme.toRepr(certVerifyMsg.signatureScheme!);
      if (schemeName == null) {
          throw TLSHandshakeFailure('Unknown signature scheme: ${certVerifyMsg.signatureScheme}');
      }

      String? padding;
      String hash;
      int? saltLen;

      if (schemeName.startsWith('rsa_pss')) {
          padding = 'pss';
          if (schemeName.endsWith('sha256')) {
              hash = 'sha256';
              saltLen = 32;
          } else if (schemeName.endsWith('sha384')) {
              hash = 'sha384';
              saltLen = 48;
          } else if (schemeName.endsWith('sha512')) {
              hash = 'sha512';
              saltLen = 64;
          } else {
              throw TLSHandshakeFailure('Unsupported hash for PSS: $schemeName');
          }
      } else if (schemeName.startsWith('rsa_pkcs1')) {
          padding = 'pkcs1';
          if (schemeName.endsWith('sha256')) hash = 'sha256';
          else if (schemeName.endsWith('sha384')) hash = 'sha384';
          else if (schemeName.endsWith('sha512')) hash = 'sha512';
          else if (schemeName.endsWith('sha1')) hash = 'sha1';
          else throw TLSHandshakeFailure('Unsupported hash for PKCS1: $schemeName');
      } else if (schemeName.startsWith('ecdsa')) {
          padding = null;
          if (schemeName.endsWith('sha256')) hash = 'sha256';
          else if (schemeName.endsWith('sha384')) hash = 'sha384';
          else if (schemeName.endsWith('sha512')) hash = 'sha512';
          else if (schemeName.endsWith('sha1')) hash = 'sha1';
          else throw TLSHandshakeFailure('Unsupported hash for ECDSA: $schemeName');
      } else {
           throw TLSHandshakeFailure('Mismatch between key type and signature scheme: $schemeName');
      }

      if (!(pubKey as dynamic).verify(certVerifyMsg.signature, verifyBytes, padding: padding, hashAlg: hash, saltLen: saltLen ?? 0)) {
           await _sendAlert(AlertLevel.fatal, AlertDescription.decrypt_error);
           throw TLSHandshakeFailure('Invalid signature');
      }
      
      // Receive Finished
      final finishedTranscript = handshakeHashes.copy();
      final finishedMsg = await recvHandshakeMessage(allowedTypes: [TlsHandshakeType.finished]);
      if (finishedMsg is! TlsFinished) {
          await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
          throw TLSUnexpectedMessage('Expected Finished, got ${finishedMsg.handshakeType.name}');
      }
      
      // Verify Finished
      final expectedVerifyData = buildFinishedVerifyData(
        forClient: false,
        handshakeSnapshot: finishedTranscript,
      );
      if (!_bytesEqual(finishedMsg.verifyData, expectedVerifyData)) {
          await _sendAlert(AlertLevel.fatal, AlertDescription.decrypt_error);
          throw TLSHandshakeFailure('Finished verification failed');
      }
      
      // Send Certificate and CertificateVerify if requested
      if (certRequested) {
          if (certParams != null) {
              final certEntries = certParams.certificates.map((c) => TlsCertificateEntry(certificate: c.bytes)).toList();
              
              await sendHandshakeMessage(TlsCertificate.tls13(
                  certificateRequestContext: certRequestMsg!.certificateRequestContext,
                  certificateEntries: certEntries
              ));
              
              // Signature Scheme Selection
              int? selectedScheme;
              final supportedSchemes = certRequestMsg.signatureAlgorithms;
              final pubKey = certParams.key;
              
              if (pubKey is RSAKey) {
                  if (supportedSchemes.contains(SignatureScheme.rsa_pss_rsae_sha256.value)) {
                      selectedScheme = SignatureScheme.rsa_pss_rsae_sha256.value;
                  } else if (supportedSchemes.contains(SignatureScheme.rsa_pss_rsae_sha384.value)) {
                      selectedScheme = SignatureScheme.rsa_pss_rsae_sha384.value;
                  } else if (supportedSchemes.contains(SignatureScheme.rsa_pkcs1_sha256.value)) {
                      selectedScheme = SignatureScheme.rsa_pkcs1_sha256.value;
                  }
              } else if (pubKey is ECDSAKey) {
                  if (supportedSchemes.contains(SignatureScheme.ecdsa_secp256r1_sha256.value)) {
                      selectedScheme = SignatureScheme.ecdsa_secp256r1_sha256.value;
                  } else if (supportedSchemes.contains(SignatureScheme.ecdsa_secp384r1_sha384.value)) {
                      selectedScheme = SignatureScheme.ecdsa_secp384r1_sha384.value;
                  }
              }
              
              if (selectedScheme == null) {
                   if (pubKey is RSAKey) selectedScheme = SignatureScheme.rsa_pss_rsae_sha256.value;
                   else if (pubKey is ECDSAKey) selectedScheme = SignatureScheme.ecdsa_secp256r1_sha256.value;
                   else throw UnimplementedError('Unsupported key type: ${pubKey.runtimeType}');
              }
              
              final verifyBytes = buildCertificateVerifyBytes(
                  signatureScheme: selectedScheme,
                  peerTag: 'client',
                  keyType: pubKey is RSAKey ? 'rsa' : 'ecdsa',
              );
              
              Uint8List signature;
              final schemeName = SignatureScheme.toRepr(selectedScheme);
              
              if (pubKey is RSAKey) {
                  String padding = 'pss';
                  String hash = 'sha256';
                  int saltLen = 32;
                  
                  if (schemeName!.startsWith('rsa_pkcs1')) {
                      padding = 'pkcs1';
                      if (schemeName.endsWith('sha256')) hash = 'sha256';
                      else if (schemeName.endsWith('sha384')) hash = 'sha384';
                      else if (schemeName.endsWith('sha512')) hash = 'sha512';
                  } else if (schemeName.startsWith('rsa_pss')) {
                      padding = 'pss';
                      if (schemeName.endsWith('sha256')) { hash = 'sha256'; saltLen = 32; }
                      else if (schemeName.endsWith('sha384')) { hash = 'sha384'; saltLen = 48; }
                      else if (schemeName.endsWith('sha512')) { hash = 'sha512'; saltLen = 64; }
                  }
                  
                  signature = pubKey.sign(verifyBytes, padding: padding, hashAlg: hash, saltLen: saltLen);
              } else if (pubKey is ECDSAKey) {
                  String hash = 'sha256';
                  if (schemeName!.endsWith('sha256')) hash = 'sha256';
                  else if (schemeName.endsWith('sha384')) hash = 'sha384';
                  else if (schemeName.endsWith('sha512')) hash = 'sha512';
                  
                  signature = pubKey.sign(verifyBytes, hashAlg: hash);
              } else {
                  throw UnimplementedError('Unsupported key type for signing');
              }
              
              await sendHandshakeMessage(TlsCertificateVerify(
                  version: const TlsProtocolVersion(3, 4),
                  signatureScheme: selectedScheme,
                  signature: signature
              ));
          } else {
              await sendHandshakeMessage(TlsCertificate.tls13(
                  certificateRequestContext: certRequestMsg!.certificateRequestContext,
                  certificateEntries: []
              ));
          }
      }

      // Send Finished
      final verifyData = buildFinishedVerifyData(forClient: true);
      await sendHandshakeMessage(TlsFinished(verifyData: verifyData));
      
      // Derive Application Traffic Secrets
      final derivedSecret2 = derive_secret(
          handshakeSecret, 
          Uint8List.fromList('derived'.codeUnits), 
          null, 
          hashName
      );
      
      final masterSecret = secureHMAC(derivedSecret2, Uint8List(hashLen), hashName); // 0-filled
      session.masterSecret = masterSecret;
      
      final handshakeHash = handshakeHashes.digest(hashName);
      
      final clientAppTrafficSecret = HKDF_expand_label(
          masterSecret,
          Uint8List.fromList('c ap traffic'.codeUnits),
          handshakeHash,
          hashLen,
          hashName
      );
      
      final serverAppTrafficSecret = HKDF_expand_label(
          masterSecret,
          Uint8List.fromList('s ap traffic'.codeUnits),
          handshakeHash,
          hashLen,
          hashName
      );
      
      session.clAppSecret = clientAppTrafficSecret;
      session.srAppSecret = serverAppTrafficSecret;
      
      // Calculate Resumption Master Secret
      final resumptionMasterSecret = derive_secret(
          masterSecret,
          Uint8List.fromList('res master'.codeUnits),
          handshakeHash,
          hashName
      );
      session.resumptionMasterSecret = resumptionMasterSecret;
      
      // Switch to Application Keys
      calcTLS1_3PendingState(
          session.cipherSuite,
          clientAppTrafficSecret,
          serverAppTrafficSecret,
          null
      );
      changeReadState();
      changeWriteState();
      
      handshakeEstablished = true;
  }

  Future<void> handshakeServer({
    HandshakeSettings? settings,
    Session? session,
    dynamic verifierDB,
    X509CertChain? certChain,
    dynamic privateKey,
    bool reqCert = false,
    List<String>? nextProtos,
    List<String>? alpn,
  }) async {
    client = false;
    handshakeSettings = settings ?? HandshakeSettings();
    this.session = session ?? Session();
    
    // Receive ClientHello
    final message = await recvHandshakeMessage(allowedTypes: [TlsHandshakeType.clientHello]);
    if (message is! TlsClientHello) {
        await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
        throw TLSUnexpectedMessage('Expected ClientHello, got ${message.handshakeType.name}');
    }
    
    // Process ClientHello by negotiating the highest mutually supported version
    final minSupported = TlsProtocolVersion(
      handshakeSettings.minVersion.$1,
      handshakeSettings.minVersion.$2,
    );
    final maxSupported = TlsProtocolVersion(
      handshakeSettings.maxVersion.$1,
      handshakeSettings.maxVersion.$2,
    );

    final supportedVersionsExt =
        message.extensions?.byType(ExtensionType.supported_versions);
    TlsProtocolVersion? negotiatedVersion;

    if (supportedVersionsExt is TlsSupportedVersionsExtension) {
      final offered = supportedVersionsExt.supportedVersions
          .where((v) => v >= minSupported && v <= maxSupported)
          .toList();
      offered.sort((a, b) => a == b ? 0 : (a > b ? -1 : 1));
      if (offered.isNotEmpty) {
        negotiatedVersion = offered.first;
      }
    }

    negotiatedVersion ??= HandshakeHelpers.resolveLegacyProtocolVersion(
      clientVersion: message.clientVersion,
      minVersion: handshakeSettings.minVersion,
      maxVersion: handshakeSettings.maxVersion,
    );

    if (negotiatedVersion == null) {
      await _sendAlert(AlertLevel.fatal, AlertDescription.protocol_version);
      throw TLSHandshakeFailure(
        'Client offered ${message.clientVersion} but server requires $minSupported–$maxSupported',
      );
    }

    version = negotiatedVersion;
    
    if (_isTls13Plus()) {
        await _serverHandshake13(message, certChain, privateKey, reqCert: reqCert, alpn: alpn);
    } else {
        await _serverHandshake12(message, certChain, privateKey, reqCert: reqCert, alpn: alpn);
    }
  }
  
  Future<void> _serverHandshake13(
    TlsClientHello clientHello,
    X509CertChain? certChain,
    dynamic privateKey, {
    bool reqCert = false,
    List<String>? alpn,
  }) async {
      if (certChain == null || privateKey == null) {
          await _sendAlert(AlertLevel.fatal, AlertDescription.internal_error);
          throw TLSHandshakeFailure('Server certificate and private key required');
      }
      session.serverCertChain = certChain;
      
      // 1. Select Cipher Suite
      final supportedSuites = CipherSuite.getTLS13Suites(handshakeSettings);
      int? selectedSuite;
      for (final suite in clientHello.cipherSuites) {
          if (supportedSuites.contains(suite)) {
              selectedSuite = suite;
              break;
          }
      }
      if (selectedSuite == null) {
          await _sendAlert(AlertLevel.fatal, AlertDescription.handshake_failure);
          throw TLSHandshakeFailure('No shared cipher suites');
      }
      session.cipherSuite = selectedSuite;
      
      // 2. Process Key Share
      final keyShareExt = clientHello.extensions?.byType(ExtensionType.key_share);
      if (keyShareExt is! TlsKeyShareExtension) {
           await _sendAlert(AlertLevel.fatal, AlertDescription.missing_extension);
           throw TLSHandshakeFailure('Missing KeyShare extension');
      }
      
      TlsKeyShareEntry? serverShare;
      Uint8List? sharedSecret;
      
      // Try to find a match in client's shares
      for (final share in keyShareExt.clientShares) {
          if (share.group == GroupName.x25519) {
               final kex = ECDHKeyExchange(GroupName.x25519, (3, 4));
               final serverPrivateKey = kex.getRandomPrivateKey();
               final pubKey = kex.calcPublicValue(serverPrivateKey);
               serverShare = TlsKeyShareEntry(group: GroupName.x25519, keyExchange: pubKey);
               sharedSecret = kex.calcSharedKey(serverPrivateKey, share.keyExchange);
               break;
          }
      }
      
      if (serverShare == null) {
           await _sendAlert(AlertLevel.fatal, AlertDescription.handshake_failure);
           throw TLSHandshakeFailure('No supported key share (only X25519 supported for now)');
      }
      
      serverRandom = getRandomBytes(32);
      
      // 3. Send ServerHello
      final extensions = <TlsExtension>[];
      extensions.add(TlsSupportedVersionsExtension.server(const TlsProtocolVersion(3, 4)));
      extensions.add(TlsKeyShareExtension.server(serverShare));
      
      final serverHello = TlsServerHello(
          serverVersion: const TlsProtocolVersion(3, 3),
          random: serverRandom,
          sessionId: clientHello.sessionId,
          cipherSuite: selectedSuite,
          compressionMethod: 0,
          extensions: TlsExtensionBlock(extensions: extensions),
      );
      
      await sendHandshakeMessage(serverHello);
      
      // 4. Key Derivation
      final hashName = _prfHashName();
      final hashLen = hashName == 'sha384' ? 48 : 32;
      
      final salt = Uint8List(hashLen); // 0-filled
      final earlySecret = secureHMAC(salt, Uint8List(hashLen), hashName); 
      
      final derivedSecret = derive_secret(
          earlySecret, 
          Uint8List.fromList('derived'.codeUnits), 
          null, 
          hashName
      );
      
      final handshakeSecret = secureHMAC(derivedSecret, sharedSecret!, hashName);
      
      final helloHash = handshakeHashes.digest(hashName);
      
      final clientHandshakeTrafficSecret = HKDF_expand_label(
          handshakeSecret,
          Uint8List.fromList('c hs traffic'.codeUnits),
          helloHash,
          hashLen,
          hashName
      );
      
      final serverHandshakeTrafficSecret = HKDF_expand_label(
          handshakeSecret,
          Uint8List.fromList('s hs traffic'.codeUnits),
          helloHash,
          hashLen,
          hashName
      );
      
      session.clHandshakeSecret = clientHandshakeTrafficSecret;
      session.srHandshakeSecret = serverHandshakeTrafficSecret;
      
      // Switch to Handshake Keys
      calcTLS1_3PendingState(
          session.cipherSuite,
          clientHandshakeTrafficSecret,
          serverHandshakeTrafficSecret,
          null
      );
      changeReadState();
      changeWriteState();
      
      // 5. Send EncryptedExtensions
      final encExtensions = <TlsExtension>[];
      
      // ALPN Negotiation
      if (alpn != null && alpn.isNotEmpty) {
          final clientAlpn = clientHello.extensions?.byType(ExtensionType.alpn);
          if (clientAlpn is TlsAlpnExtension) {
              for (final proto in alpn) {
                  if (clientAlpn.protocols.contains(proto)) {
                      encExtensions.add(TlsAlpnExtension(protocols: [proto]));
                      session.appProto = Uint8List.fromList(proto.codeUnits);
                      break;
                  }
              }
          }
      }
      
      await sendHandshakeMessage(TlsEncryptedExtensions(extensions: TlsExtensionBlock(extensions: encExtensions)));
      
      // 5.5 Send CertificateRequest (if requested)
      if (reqCert) {
          final certReqExtensions = <TlsExtension>[];
          certReqExtensions.add(TlsSignatureAlgorithmsExtension(signatureSchemes: [
              SignatureScheme.rsa_pss_rsae_sha256.value,
              SignatureScheme.rsa_pkcs1_sha256.value,
              SignatureScheme.ecdsa_secp256r1_sha256.value,
              SignatureScheme.ecdsa_secp384r1_sha384.value,
          ]));
          
          await sendHandshakeMessage(TlsCertificateRequest(
              version: const TlsProtocolVersion(3, 4),
              certificateRequestContext: Uint8List(0),
              extensions: TlsExtensionBlock(extensions: certReqExtensions)
          ));
      }

      // 6. Send Certificate
      final certEntries = <TlsCertificateEntry>[];
      for (final x509 in certChain.x509List) {
          certEntries.add(TlsCertificateEntry(certificate: x509.bytes, extensions: null));
      }
      await sendHandshakeMessage(TlsCertificate.tls13(certificateEntries: certEntries, certificateRequestContext: Uint8List(0)));
      
      // 7. Send CertificateVerify
      final sigAlgsExt = clientHello.extensions?.byType(ExtensionType.signature_algorithms);
      int? selectedScheme;
      String keyType = 'rsa';
      
      if (privateKey is ECDSAKey) {
          keyType = 'ecdsa';
      }

      if (sigAlgsExt is TlsSignatureAlgorithmsExtension) {
          if (privateKey is RSAKey) {
              if (sigAlgsExt.signatureSchemes.contains(SignatureScheme.rsa_pss_rsae_sha256.value)) {
                  selectedScheme = SignatureScheme.rsa_pss_rsae_sha256.value;
              } else if (sigAlgsExt.signatureSchemes.contains(SignatureScheme.rsa_pss_rsae_sha384.value)) {
                  selectedScheme = SignatureScheme.rsa_pss_rsae_sha384.value;
              } else if (sigAlgsExt.signatureSchemes.contains(SignatureScheme.rsa_pkcs1_sha256.value)) {
                  selectedScheme = SignatureScheme.rsa_pkcs1_sha256.value;
              }
          } else if (privateKey is ECDSAKey) {
              if (sigAlgsExt.signatureSchemes.contains(SignatureScheme.ecdsa_secp256r1_sha256.value)) {
                  selectedScheme = SignatureScheme.ecdsa_secp256r1_sha256.value;
              } else if (sigAlgsExt.signatureSchemes.contains(SignatureScheme.ecdsa_secp384r1_sha384.value)) {
                  selectedScheme = SignatureScheme.ecdsa_secp384r1_sha384.value;
              }
          }
      }
      
      if (selectedScheme == null) {
           if (privateKey is RSAKey) {
               selectedScheme = SignatureScheme.rsa_pss_rsae_sha256.value;
           } else if (privateKey is ECDSAKey) {
               selectedScheme = SignatureScheme.ecdsa_secp256r1_sha256.value;
           } else {
               throw UnimplementedError('Unsupported key type: ${privateKey.runtimeType}');
           }
      }
      
      final verifyBytes = buildCertificateVerifyBytes(
          signatureScheme: selectedScheme,
          peerTag: 'server',
          keyType: keyType,
      );
      
      Uint8List signature;
      if (privateKey is RSAKey) {
          final schemeName = SignatureScheme.toRepr(selectedScheme);
          String padding = 'pss';
          String hash = 'sha256';
          int saltLen = 32;
          
          if (schemeName!.startsWith('rsa_pkcs1')) {
              padding = 'pkcs1';
              if (schemeName.endsWith('sha256')) hash = 'sha256';
              else if (schemeName.endsWith('sha384')) hash = 'sha384';
              else if (schemeName.endsWith('sha512')) hash = 'sha512';
              else if (schemeName.endsWith('sha1')) hash = 'sha1';
          } else if (schemeName.startsWith('rsa_pss')) {
              padding = 'pss';
              if (schemeName.endsWith('sha256')) { hash = 'sha256'; saltLen = 32; }
              else if (schemeName.endsWith('sha384')) { hash = 'sha384'; saltLen = 48; }
              else if (schemeName.endsWith('sha512')) { hash = 'sha512'; saltLen = 64; }
          }
          
          signature = privateKey.sign(verifyBytes, padding: padding, hashAlg: hash, saltLen: saltLen);
      } else if (privateKey is ECDSAKey) {
          final schemeName = SignatureScheme.toRepr(selectedScheme);
          String hash = 'sha256';
          if (schemeName!.endsWith('sha256')) hash = 'sha256';
          else if (schemeName.endsWith('sha384')) hash = 'sha384';
          else if (schemeName.endsWith('sha512')) hash = 'sha512';
          
          signature = privateKey.sign(verifyBytes, hashAlg: hash);
      } else {
          throw UnimplementedError('Unsupported signing key');
      }
      
      await sendHandshakeMessage(TlsCertificateVerify(
          version: const TlsProtocolVersion(3, 4),
          signatureScheme: selectedScheme, 
          signature: signature
      ));
      
      // 8. Send Finished
      final verifyData = buildFinishedVerifyData(forClient: false);
      await sendHandshakeMessage(TlsFinished(verifyData: verifyData));
      
      // 9. Derive Application Keys
      // 10. Receive Client Messages (Certificate, CertificateVerify, Finished)
      if (reqCert) {
          final certMsg = await recvHandshakeMessage(allowedTypes: [TlsHandshakeType.certificate]);
          if (certMsg is! TlsCertificate) {
               await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
               throw TLSUnexpectedMessage('Expected Certificate');
          }
          
          X509CertChain? clientCertChain;
          if (certMsg.certificateEntries.isNotEmpty) {
               final certs = <X509>[];
               for (final entry in certMsg.certificateEntries) {
                   final x509 = X509();
                   x509.parseBinary(entry.certificate);
                   certs.add(x509);
               }
               clientCertChain = X509CertChain(certs);
               _validateCertificateChain(clientCertChain);
          }
          
          if (clientCertChain != null) {
               final cvTranscript = handshakeHashes.copy();
               final cvMsg = await recvHandshakeMessage(allowedTypes: [TlsHandshakeType.certificateVerify]);
               if (cvMsg is! TlsCertificateVerify) {
                    await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
                    throw TLSUnexpectedMessage('Expected CertificateVerify');
               }
               
               final pubKey = clientCertChain.x509List.first.publicKey!;
               final verifyBytes = buildCertificateVerifyBytes(
                   signatureScheme: cvMsg.signatureScheme!,
                   peerTag: 'client',
                   keyType: pubKey is RSAKey ? 'rsa' : 'ecdsa',
                   handshakeSnapshot: cvTranscript,
               );
               
               bool valid = false;
               if (pubKey is RSAKey) {
                   final schemeName = SignatureScheme.toRepr(cvMsg.signatureScheme!);
                   String padding = 'pss';
                   String hash = 'sha256';
                   int saltLen = 32;
                   
                   if (schemeName != null) {
                       if (schemeName.startsWith('rsa_pkcs1')) {
                           padding = 'pkcs1';
                           if (schemeName.endsWith('sha256')) hash = 'sha256';
                           else if (schemeName.endsWith('sha384')) hash = 'sha384';
                           else if (schemeName.endsWith('sha512')) hash = 'sha512';
                           else if (schemeName.endsWith('sha1')) hash = 'sha1';
                       } else if (schemeName.startsWith('rsa_pss')) {
                           padding = 'pss';
                           if (schemeName.endsWith('sha256')) { hash = 'sha256'; saltLen = 32; }
                           else if (schemeName.endsWith('sha384')) { hash = 'sha384'; saltLen = 48; }
                           else if (schemeName.endsWith('sha512')) { hash = 'sha512'; saltLen = 64; }
                       }
                   }
                   valid = pubKey.verify(cvMsg.signature, verifyBytes, padding: padding, hashAlg: hash, saltLen: saltLen);
               } else if (pubKey is ECDSAKey) {
                   final schemeName = SignatureScheme.toRepr(cvMsg.signatureScheme!);
                   String hash = 'sha256';
                   if (schemeName != null) {
                       if (schemeName.endsWith('sha256')) hash = 'sha256';
                       else if (schemeName.endsWith('sha384')) hash = 'sha384';
                       else if (schemeName.endsWith('sha512')) hash = 'sha512';
                   }
                   valid = pubKey.verify(cvMsg.signature, verifyBytes, hashAlg: hash);
               }
               
               if (!valid) {
                   await _sendAlert(AlertLevel.fatal, AlertDescription.decrypt_error);
                   throw TLSHandshakeFailure('CertificateVerify signature invalid');
               }
          }
      }

      final finishedTranscript = handshakeHashes.copy();
      final finishedMsg = await recvHandshakeMessage(allowedTypes: [TlsHandshakeType.finished]);
      if (finishedMsg is! TlsFinished) {
          await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
          throw TLSUnexpectedMessage('Expected Finished');
      }
      
      final expectedVerifyData = buildFinishedVerifyData(
        forClient: true,
        handshakeSnapshot: finishedTranscript,
      );
      if (!_bytesEqual(finishedMsg.verifyData, expectedVerifyData)) {
          await _sendAlert(AlertLevel.fatal, AlertDescription.decrypt_error);
          throw TLSHandshakeFailure('Finished verification failed');
      }

      // Derive application traffic secrets now that the full handshake transcript
      // (including the client's Finished) is known.
      final derivedSecret2 = derive_secret(
          handshakeSecret,
          Uint8List.fromList('derived'.codeUnits),
          null,
          hashName);

      final masterSecret =
          secureHMAC(derivedSecret2, Uint8List(hashLen), hashName);
      session.masterSecret = masterSecret;

      final handshakeHash = handshakeHashes.digest(hashName);

      final clientAppTrafficSecret = HKDF_expand_label(
          masterSecret,
          Uint8List.fromList('c ap traffic'.codeUnits),
          handshakeHash,
          hashLen,
          hashName);

      final serverAppTrafficSecret = HKDF_expand_label(
          masterSecret,
          Uint8List.fromList('s ap traffic'.codeUnits),
          handshakeHash,
          hashLen,
          hashName);

      session.clAppSecret = clientAppTrafficSecret;
      session.srAppSecret = serverAppTrafficSecret;

      // Calculate Resumption Master Secret
      final resumptionMasterSecret = derive_secret(
          masterSecret,
          Uint8List.fromList('res master'.codeUnits),
          handshakeHash,
          hashName);
      session.resumptionMasterSecret = resumptionMasterSecret;

      // Switch to Application Keys
      calcTLS1_3PendingState(
          session.cipherSuite,
          clientAppTrafficSecret,
          serverAppTrafficSecret,
          null);
      changeReadState();
      changeWriteState();

      handshakeEstablished = true;
  }
  
  Future<void> _serverHandshake12(TlsClientHello clientHello, X509CertChain? certChain, dynamic privateKey, {bool reqCert = false, List<String>? alpn}) async {
    // 1. Negotiate Cipher Suite
    final clientSuites = clientHello.cipherSuites;
    var serverSuites = <int>[];

    // Build server suites from settings (legacy/TLS 1.2 and below)
    serverSuites.addAll(CipherSuite.getEcdsaSuites(handshakeSettings));
    serverSuites.addAll(CipherSuite.getEcdheCertSuites(handshakeSettings));
    serverSuites.addAll(CipherSuite.getDheCertSuites(handshakeSettings));
    serverSuites.addAll(CipherSuite.getCertSuites(handshakeSettings));
    serverSuites.addAll(CipherSuite.getDheDsaSuites(handshakeSettings));

    // Filter suites to the negotiated legacy version window
    final negotiatedTuple = (version.major, version.minor);
    serverSuites = CipherSuite.filterForVersion(
      serverSuites,
      handshakeSettings.minVersion,
      negotiatedTuple,
    );
    
    // Filter by certificate
    if (certChain != null) {
        serverSuites = CipherSuite.filterForCertificate(serverSuites, certChain);
    }
    
    // Find intersection
    int? selectedSuite;
    for (final suite in serverSuites) {
        if (clientSuites.contains(suite)) {
            selectedSuite = suite;
            break;
        }
    }
    
    if (selectedSuite == null) {
        await _sendAlert(AlertLevel.fatal, AlertDescription.handshake_failure);
        throw TLSHandshakeFailure('No shared cipher suites');
    }
    
    session.cipherSuite = selectedSuite;
    
    // 2. Send ServerHello
    serverRandom = getRandomBytes(32);
    // Set last 8 bytes for downgrade protection if needed (not strictly required for basic 1.2)
    
    final extensions = <TlsExtension>[];
    if (clientHello.extensions?.byType(ExtensionType.renegotiation_info) != null) {
        extensions.add(TlsRawExtension(type: ExtensionType.renegotiation_info, body: Uint8List(1)..[0] = 0));
    }
    final clientOfferedEms =
        clientHello.extensions?.byType(ExtensionType.extended_master_secret) != null;
    if (handshakeSettings.useExtendedMasterSecret && clientOfferedEms) {
        extensions.add(const TlsExtendedMasterSecretExtension());
        session.extendedMasterSecret = true;
    } else if (handshakeSettings.requireExtendedMasterSecret && !clientOfferedEms) {
        await _sendAlert(AlertLevel.fatal, AlertDescription.handshake_failure);
        throw TLSHandshakeFailure('Client did not offer Extended Master Secret');
    }

    if (handshakeSettings.requireExtendedMasterSecret &&
        !session.extendedMasterSecret) {
      await _sendAlert(AlertLevel.fatal, AlertDescription.handshake_failure);
      throw TLSHandshakeFailure(
        'Server did not negotiate Extended Master Secret as required',
      );
    }

    // ALPN Negotiation
    if (alpn != null && alpn.isNotEmpty) {
        final alpnExt = clientHello.extensions?.byType(ExtensionType.alpn);
        if (alpnExt is TlsAlpnExtension) {
            String? selectedProto;
            for (final proto in alpnExt.protocols) {
                if (alpn.contains(proto)) {
                    selectedProto = proto;
                    break;
                }
            }
            if (selectedProto != null) {
                extensions.add(TlsAlpnExtension(protocols: [selectedProto]));
            }
        }
    }

    // Generate new Session ID for full handshake
    final sessionId = getRandomBytes(32);
    session.sessionID = sessionId;

    final serverHello = TlsServerHello(
      serverVersion: version,
        random: serverRandom,
        sessionId: sessionId,
        cipherSuite: selectedSuite,
        compressionMethod: 0, // Compression method null
        extensions: TlsExtensionBlock(extensions: extensions),
    );
    
    await sendHandshakeMessage(serverHello);
    _serverHelloMsg = serverHello;
    
    // 3. Send Certificate
    if (certChain != null) {
        // Convert X509CertChain to List<Uint8List>
        final certList = certChain.x509List.map((c) => c.bytes).toList();
        final certMsg = TlsCertificate.tls12(certificateChain: certList);
        await sendHandshakeMessage(certMsg);
    } else {
        // Handle anonymous or PSK if supported, else error if suite requires cert
        // For now assume cert is required for non-anon suites
    }
    
    // 4. Send ServerKeyExchange (if DHE/ECDHE)
    final suiteName = CipherSuite.ietfNames[selectedSuite] ?? '';
    final isDHE = suiteName.contains('_DHE_');
    final isECDHE = suiteName.contains('_ECDHE_');
    
    KeyExchange? keyExchange;
    
    if (isECDHE) {
        final acceptedCurves = _curveNamesToList(handshakeSettings);
        keyExchange = ECDHE_RSAKeyExchange(
          selectedSuite,
          clientHello,
          serverHello,
          privateKey,
          acceptedCurves: acceptedCurves.isNotEmpty ? acceptedCurves : null,
        );
    } else if (isDHE) {
        keyExchange = DHE_RSAKeyExchange(selectedSuite, clientHello, serverHello, privateKey);
    } else if (suiteName.contains('_RSA_')) {
        keyExchange = RSAKeyExchange(selectedSuite, clientHello, serverHello, privateKey);
    }
    
    if (keyExchange != null && (isDHE || isECDHE)) {
        String? sigHash;
        final sigAlgsExt = clientHello.extensions?.byType(ExtensionType.signature_algorithms);
        if (sigAlgsExt is TlsSignatureAlgorithmsExtension) {
             bool supportsSha256 = false;
             for (final scheme in sigAlgsExt.signatureSchemes) {
                 final name = SignatureScheme.toRepr(scheme);
                 if (name != null && name.endsWith('sha256')) {
                     supportsSha256 = true;
                     break;
                 }
             }
             
             if (supportsSha256) {
                 sigHash = 'sha256';
             } else {
                 for (final scheme in sigAlgsExt.signatureSchemes) {
                     final name = SignatureScheme.toRepr(scheme);
                     if (name != null) {
                         if (name.endsWith('sha384')) { sigHash = 'sha384'; break; }
                         if (name.endsWith('sha512')) { sigHash = 'sha512'; break; }
                         if (name.endsWith('sha1')) { sigHash = 'sha1'; break; }
                     }
                 }
             }
        }
        final ske = keyExchange.makeServerKeyExchange(sigHash: sigHash);
        await sendHandshakeMessage(ske);
    }

    // 5. Send CertificateRequest (if requested)
    if (reqCert) {
      final certTypes = [
        ClientCertificateType.rsa_sign,
        ClientCertificateType.dss_sign,
        ClientCertificateType.ecdsa_sign,
      ];
      final includeSigAlgs = version >= const TlsProtocolVersion(3, 3);
      final sigAlgs = includeSigAlgs
          ? <int>[
              0x0401, // rsa_pkcs1_sha256
              0x0403, // ecdsa_secp256r1_sha256
              0x0501, // rsa_pkcs1_sha384
              0x0503, // ecdsa_secp384r1_sha384
              0x0601, // rsa_pkcs1_sha512
              0x0603, // ecdsa_secp521r1_sha512
              0x0201, // rsa_pkcs1_sha1
              0x0203, // ecdsa_sha1
            ]
          : const <int>[];

      final certReq = TlsCertificateRequest(
        version: version,
        certificateTypes: certTypes,
        signatureAlgorithms: sigAlgs,
        certificateAuthorities: const [],
      );
      await sendHandshakeMessage(certReq);
    }
    
    // 6. Send ServerHelloDone
    await sendHandshakeMessage(TlsServerHelloDone());
    
    // 7. Receive Client Messages
    
    // If reqCert, expect Certificate
    bool gotClientCert = false;
    X509CertChain? clientCertChain;
    if (reqCert) {
        final certMsg = await recvHandshakeMessage(allowedTypes: [TlsHandshakeType.certificate]);
        if (certMsg is! TlsCertificate) {
             await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
             throw TLSUnexpectedMessage('Expected Certificate');
        }
        if (certMsg.certificateChain.isNotEmpty) {
             gotClientCert = true;
             final certs = <X509>[];
             for (final certBytes in certMsg.certificateChain) {
                 final x509 = X509();
                 x509.parseBinary(certBytes);
                 certs.add(x509);
             }
             clientCertChain = X509CertChain(certs);
             _validateCertificateChain(clientCertChain);
        }
    }
    
    // 8. Receive ClientKeyExchange
    var ckeMsg = await recvHandshakeMessage(allowedTypes: [TlsHandshakeType.clientKeyExchange]);
    if (ckeMsg is RawTlsHandshakeMessage) {
         ckeMsg = TlsClientKeyExchange.parse(
             ckeMsg.serializeBody(),
             session.cipherSuite,
             [version.major, version.minor],
         );
    }
    if (ckeMsg is! TlsClientKeyExchange) {
         await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
         throw TLSUnexpectedMessage('Expected ClientKeyExchange');
    }
    
    if (keyExchange == null) {
         throw TLSInternalError('KeyExchange not initialized');
    }

    final premasterSecret = await keyExchange.processClientKeyExchange(ckeMsg);
    
    // 9. Receive CertificateVerify (if client cert was sent)
    if (gotClientCert && clientCertChain != null) {
      final cvMsg = await recvHandshakeMessage(
        allowedTypes: [TlsHandshakeType.certificateVerify],
      );
      if (cvMsg is! TlsCertificateVerify) {
        await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
        throw TLSUnexpectedMessage('Expected CertificateVerify');
      }

      final pubKey = clientCertChain.getEndEntityPublicKey();
      final keyType = pubKey is ECDSAKey
          ? 'ecdsa'
          : pubKey is DSAKey
              ? 'dsa'
              : 'rsa';
      final isTls12 = version >= const TlsProtocolVersion(3, 3);
      final signatureScheme = cvMsg.signatureScheme;

      if (isTls12 && signatureScheme == null) {
        await _sendAlert(AlertLevel.fatal, AlertDescription.decode_error);
        throw TLSDecodeError('Missing signature scheme in CertificateVerify');
      }

      final verifyBytes = KeyExchange.calcVerifyBytes(
        version,
        handshakeHashes,
        (signatureScheme ?? 0),
        keyType: keyType,
      );

      bool valid;
      if (pubKey is RSAKey) {
        if (!isTls12) {
          valid = pubKey.verify(
            cvMsg.signature,
            verifyBytes,
            padding: 'pkcs1',
            hashAlg: null,
          );
        } else {
          final schemeName = SignatureScheme.toRepr(signatureScheme!);
          if (schemeName == null) {
            throw TLSIllegalParameterException('Unknown signature scheme');
          }
          final hashName = SignatureScheme.getHash(schemeName);
          final padding = SignatureScheme.getPadding(schemeName);

          if (padding == 'pkcs1') {
            valid = pubKey.verify(
              cvMsg.signature,
              verifyBytes,
              padding: 'pkcs1',
              hashAlg: null,
            );
          } else if (padding == 'pss') {
            valid = pubKey.verify(
              cvMsg.signature,
              verifyBytes,
              padding: 'pss',
              hashAlg: hashName,
            );
          } else {
            throw TLSIllegalParameterException('Unsupported padding: $padding');
          }
        }
      } else if (pubKey is ECDSAKey) {
        valid = pubKey.verify(cvMsg.signature, verifyBytes);
      } else if (pubKey is DSAKey) {
        valid = pubKey.verify(cvMsg.signature, verifyBytes);
      } else if (pubKey is EdDSAKey) {
        valid = pubKey.hashAndVerify(cvMsg.signature, verifyBytes);
      } else {
        throw UnimplementedError(
          'Unsupported client key type: ${pubKey.runtimeType}',
        );
      }

      if (!valid) {
        await _sendAlert(AlertLevel.fatal, AlertDescription.decrypt_error);
        throw TLSHandshakeFailure('CertificateVerify signature invalid');
      }
    }
    
    // Calculate Master Secret (respect Extended Master Secret if negotiated)
    if (session.extendedMasterSecret) {
      session.masterSecret = calcKey(
        [version.major, version.minor],
        premasterSecret,
        selectedSuite,
        Uint8List.fromList('extended master secret'.codeUnits),
        handshakeHashes: handshakeHashes,
      );
    } else {
      final masterSecret = calcMasterSecret(
        [version.major, version.minor],
        selectedSuite,
        premasterSecret,
        clientHello.random,
        serverHello.random,
      );
      session.masterSecret = masterSecret;
    }
    
    // Prepare pending read/write states derived from the negotiated master secret
    calcPendingStates(
      session.cipherSuite,
      Uint8List.fromList(session.masterSecret),
      clientHello.random,
      serverHello.random,
      null,
    );
    
    // 10. Receive ChangeCipherSpec
    final (header, _) = await recvMessage();
    if (header.type != ContentType.change_cipher_spec) {
        await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
        throw TLSUnexpectedMessage('Expected ChangeCipherSpec');
    }
    
    // 11. Receive Finished
    changeReadState(); // Switch to encrypted read
    final clientFinishedHandshakeHashes = handshakeHashes.copy();
    final finishedMsg = await recvHandshakeMessage(allowedTypes: [TlsHandshakeType.finished]);
    if (finishedMsg is! TlsFinished) {
         await _sendAlert(AlertLevel.fatal, AlertDescription.unexpected_message);
         throw TLSUnexpectedMessage('Expected Finished');
    }
    
    final expectedVerifyData = calcFinished(
      [version.major, version.minor],
      session.masterSecret,
      session.cipherSuite,
      clientFinishedHandshakeHashes,
      true,
    );
    if (!_bytesEqual(finishedMsg.verifyData, expectedVerifyData)) {
         await _sendAlert(AlertLevel.fatal, AlertDescription.decrypt_error);
         throw TLSHandshakeFailure('Finished verification failed');
    }
    
    // 12. Send ChangeCipherSpec
    await sendRecord(Message(ContentType.change_cipher_spec, Uint8List.fromList([1])));
    changeWriteState(); // Switch to encrypted write
    
    // 13. Send Finished
    final myVerifyData = buildFinishedVerifyData(forClient: false);
    final myFinished = TlsFinished(verifyData: myVerifyData);
    await sendHandshakeMessage(myFinished);
    
    handshakeEstablished = true;
  }

  Future<void> _clientSendClientHello(
    HandshakeSettings settings,
    Session session,
    String srpUsername,
    dynamic srpParams,
    Keypair? certParams,
    dynamic anonParams,
    String serverName,
    List<String> nextProtos,
    bool reqTack,
    List<String> alpn, {
    Uint8List? cookie,
    int? retryGroup,
  }) async {
    // Initialize acceptable cipher suites
    var cipherSuites = <int>[CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV];
    final wantsSrp = srpParams != null;
    final wantsAnon = anonParams != null;

    if (wantsSrp) {
      cipherSuites.addAll(CipherSuite.getSrpAllSuites(settings));
    }

    if (wantsAnon) {
      cipherSuites.addAll(CipherSuite.getEcdhAnonSuites(settings));
      cipherSuites.addAll(CipherSuite.getAnonSuites(settings));
    }

    // Default TLS client behaviour: authenticate server via its certificate
    // but do not present a client certificate unless requested.
    if (!wantsSrp && !wantsAnon) {
      cipherSuites.addAll(CipherSuite.getTLS13Suites(settings));
      cipherSuites.addAll(CipherSuite.getEcdsaSuites(settings));
      cipherSuites.addAll(CipherSuite.getEcdheCertSuites(settings));
      cipherSuites.addAll(CipherSuite.getDheCertSuites(settings));
      cipherSuites.addAll(CipherSuite.getCertSuites(settings));
      cipherSuites.addAll(CipherSuite.getDheDsaSuites(settings));
    }

    // If client-auth material is configured explicitly, reuse same cipher list
    // (these suites already added above). Keep behaviour identical for legacy
    // callers that previously passed certParams just to get the cipher list.

    if (cipherSuites.length == 1) {
      // Only TLS_EMPTY_RENEGOTIATION_INFO_SCSV present → unsupported config.
      throw ArgumentError('No compatible cipher suites available for client');
    }

    if (settings.sendFallbackSCSV) {
      cipherSuites.add(CipherSuite.TLS_FALLBACK_SCSV);
    }

    final extensions = <TlsExtension>[];

    if (settings.useEncryptThenMAC) {
      extensions.add(const TlsEncryptThenMacExtension());
    }
    if (settings.useExtendedMasterSecret) {
      extensions.add(const TlsExtendedMasterSecretExtension());
    }

    bool isGreaterOrEqual((int, int) v1, (int, int) v2) =>
        v1.$1 > v2.$1 || (v1.$1 == v2.$1 && v1.$2 >= v2.$2);
    bool isLessOrEqual((int, int) v1, (int, int) v2) =>
        v1.$1 < v2.$1 || (v1.$1 == v2.$1 && v1.$2 <= v2.$2);

    // Signature Algorithms
    if (isGreaterOrEqual(settings.maxVersion, (3, 3))) {
      final sigList = <int>[];
      if (isGreaterOrEqual(settings.maxVersion, (3, 4)) &&
          isLessOrEqual(settings.minVersion, (3, 4))) {
        sigList.addAll(_sigHashesToList(settings,
            version: const TlsProtocolVersion(3, 4)));
      }
      if (isGreaterOrEqual(settings.maxVersion, (3, 3)) &&
          isLessOrEqual(settings.minVersion, (3, 3))) {
        final tls12List = _sigHashesToList(settings,
            version: const TlsProtocolVersion(3, 3));
        for (final sig in tls12List) {
          if (!sigList.contains(sig)) {
            sigList.add(sig);
          }
        }
      }
      if (sigList.isNotEmpty) {
        extensions
            .add(TlsSignatureAlgorithmsExtension(signatureSchemes: sigList));
      }
    }

    if (serverName.isNotEmpty) {
      extensions.add(TlsServerNameExtension(hostNames: [serverName]));
    }

    if (alpn.isNotEmpty) {
      extensions.add(TlsAlpnExtension(protocols: alpn));
    }

    var sessionId = Uint8List(0);
    List<TlsKeyShareEntry>? shares;

    // TLS 1.3 logic
    if (settings.versions.any((v) => v.$1 == 3 && v.$2 == 4)) {
      if (certParams != null) {
        extensions.add(const TlsPostHandshakeAuthExtension());
      }
      if (cookie != null) {
        extensions.add(TlsCookieExtension(cookie: cookie));
      }

      sessionId = getRandomBytes(32); // Middlebox compat

      final supportedVersions = settings.versions
          .map((v) => TlsProtocolVersion(v.$1, v.$2))
          .toList();
      extensions.add(
          TlsSupportedVersionsExtension.client(supportedVersions));

      shares = <TlsKeyShareEntry>[];
      if (retryGroup != null) {
        final share = _genKeyShareEntry(retryGroup);
        shares.add(share);
      } else {
        for (final groupName in settings.keyShares) {
          final groupId = GroupName.valueOf(groupName);
          if (groupId != null) {
            final share = _genKeyShareEntry(groupId);
            shares.add(share);
          }
        }
      }
      extensions.add(TlsKeyShareExtension.client(shares));

      final pskModes = <int>[];
      for (final mode in settings.pskModes) {
        if (mode == 'psk_ke') {
          pskModes.add(PskKeyExchangeMode.psk_ke);
        } else if (mode == 'psk_dhe_ke') {
          pskModes.add(PskKeyExchangeMode.psk_dhe_ke);
        }
      }
      extensions.add(TlsPskKeyExchangeModesExtension(modes: pskModes));
    }

    // Supported Groups
    final groups = <int>[];
    if (cipherSuites.any((c) =>
        CipherSuite.ecdhAllSuites.contains(c) ||
        CipherSuite.tls13Suites.contains(c))) {
      groups.addAll(_curveNamesToList(settings));
      if (settings.ecPointFormats.isNotEmpty) {
        extensions.add(
            TlsEcPointFormatsExtension(formats: settings.ecPointFormats));
      }
    }
    if (cipherSuites.any((c) => CipherSuite.dhAllSuites.contains(c))) {
      groups.addAll(_groupNamesToList(settings));
    }
    if (groups.isNotEmpty) {
      if (shares != null) {
        final shareIds = shares.map((s) => s.group).toSet();
        final newGroups = shares.map((s) => s.group).toList();
        for (final g in groups) {
          if (!shareIds.contains(g)) {
            newGroups.add(g);
          }
        }
        extensions.add(TlsSupportedGroupsExtension(groups: newGroups));
      } else {
        extensions.add(TlsSupportedGroupsExtension(groups: groups));
      }
    }

    if (settings.use_heartbeat_extension) {
      extensions.add(
          TlsHeartbeatExtension(mode: HeartbeatMode.PEER_ALLOWED_TO_SEND));
      heartbeatCanReceive = true;
    }

    if (settings.record_size_limit > 0) {
      extensions.add(TlsRecordSizeLimitExtension(
          recordSizeLimit: settings.record_size_limit));
    }

    // Session Ticket (TLS 1.2)
    if (session.tls10Tickets != null && session.tls10Tickets!.isNotEmpty) {
      session.tls10Tickets =
          session.tls10Tickets!.where((t) => t.valid()).toList();
      for (final ticket in session.tls10Tickets!) {
        extensions.add(TlsSessionTicketExtension(ticket: ticket.ticket));
      }
    } else {
      extensions.add(TlsSessionTicketExtension(ticket: Uint8List(0)));
    }

    // PSK (TLS 1.3)
    if (settings.pskConfigs.isNotEmpty || session.tls13Tickets.isNotEmpty) {
      // Remove expired tickets
      session.tls13Tickets.removeWhere((t) {
          final ageSeconds = DateTime.now().difference(t.receivedAt).inSeconds;
          return ageSeconds > t.ticketLifetime;
      });

      final identities = <TlsPskIdentity>[];
      for (final config in settings.pskConfigs) {
        identities.add(TlsPskIdentity(
            identity: config.identity, obfuscatedTicketAge: 0));
      }
      for (final ticket in session.tls13Tickets) {
        final age = DateTime.now().difference(ticket.receivedAt).inMilliseconds;
        final obfuscatedAge = (age + ticket.ticketAgeAdd) % 4294967296;
        identities.add(
            TlsPskIdentity(identity: ticket.ticket, obfuscatedTicketAge: obfuscatedAge));
      }

      if (identities.isNotEmpty) {
        final binders =
            List<Uint8List>.filled(identities.length, Uint8List(32));
        extensions.add(
            TlsPreSharedKeyExtension(identities: identities, binders: binders));
      }
    }

    final clientHello = TlsClientHello(
      clientVersion: const TlsProtocolVersion(3, 3),
      random: getRandomBytes(32),
      sessionId: sessionId,
      cipherSuites: cipherSuites,
      compressionMethods: [0],
      extensions: TlsExtensionBlock(extensions: extensions),
    );

    if (settings.pskConfigs.isNotEmpty || session.tls13Tickets.isNotEmpty) {
      HandshakeHelpers.updateBinders(
        clientHello,
        handshakeHashes,
        settings.pskConfigs,
        tickets: session.tls13Tickets,
        resMasterSecret: session.resumptionMasterSecret.isNotEmpty 
            ? session.resumptionMasterSecret 
            : null,
      );
    }

    clientRandom = clientHello.random;
    _clientHelloMsg = clientHello;

    await sendHandshakeMessage(clientHello);
  }

  List<int> _sigHashesToList(HandshakeSettings settings,
      {required TlsProtocolVersion version}) {
    final schemes = <int>[];
    if (version >= const TlsProtocolVersion(3, 4)) {
      for (final schemeName in settings.moreSigSchemes) {
        final val = SignatureScheme.valueOf(schemeName);
        if (val != null) schemes.add(val);
      }
      for (final hashName in settings.ecdsaSigHashes) {
        if (hashName == 'sha1' || hashName == 'sha224') continue;
        if (hashName == 'sha256') {
          schemes.add(SignatureScheme.ecdsa_secp256r1_sha256.value);
        } else if (hashName == 'sha384') {
          schemes.add(SignatureScheme.ecdsa_secp384r1_sha384.value);
        } else if (hashName == 'sha512') {
          schemes.add(SignatureScheme.ecdsa_secp521r1_sha512.value);
        }
      }
      for (final hashName in settings.rsaSigHashes) {
        if (hashName == 'sha1' || hashName == 'sha224') continue;
        final schemeName = 'rsa_pss_rsae_$hashName';
        final val = SignatureScheme.valueOf(schemeName);
        if (val != null) schemes.add(val);
      }
    } else {
      // TLS 1.2 signature_algorithms
      for (final hashName in settings.rsaSigHashes) {
        final schemeName = 'rsa_pkcs1_$hashName';
        final val = SignatureScheme.valueOf(schemeName);
        if (val != null && !schemes.contains(val)) {
          schemes.add(val);
        }
      }
      for (final hashName in settings.ecdsaSigHashes) {
        String? schemeName;
        switch (hashName) {
          case 'sha1':
            schemeName = 'ecdsa_sha1';
            break;
          case 'sha224':
            schemeName = 'ecdsa_sha224';
            break;
          case 'sha256':
            schemeName = 'ecdsa_secp256r1_sha256';
            break;
          case 'sha384':
            schemeName = 'ecdsa_secp384r1_sha384';
            break;
          case 'sha512':
            schemeName = 'ecdsa_secp521r1_sha512';
            break;
        }
        if (schemeName != null) {
          final val = SignatureScheme.valueOf(schemeName);
          if (val != null && !schemes.contains(val)) {
            schemes.add(val);
          }
        }
      }
      for (final hashName in settings.dsaSigHashes) {
        final schemeName = 'dsa_$hashName';
        final val = SignatureScheme.valueOf(schemeName);
        if (val != null && !schemes.contains(val)) {
          schemes.add(val);
        }
      }

      // As a safety net, include SHA256-based RSA/ECDSA if the lists end up empty.
      if (schemes.isEmpty) {
        const fallbacks = ['rsa_pkcs1_sha256', 'ecdsa_secp256r1_sha256'];
        for (final name in fallbacks) {
          final val = SignatureScheme.valueOf(name);
          if (val != null && !schemes.contains(val)) {
            schemes.add(val);
          }
        }
      }
    }
    return schemes;
  }

  List<int> _curveNamesToList(HandshakeSettings settings) {
    final curves = <int>[];
    for (final name in settings.eccCurves) {
      final val = GroupName.valueOf(name);
      if (val != null) curves.add(val);
    }
    return curves;
  }

  List<int> _groupNamesToList(HandshakeSettings settings) {
    final groups = <int>[];
    for (final name in settings.dhGroups) {
      final val = GroupName.valueOf(name);
      if (val != null) groups.add(val);
    }
    return groups;
  }

  TlsKeyShareEntry _genKeyShareEntry(int groupId) {
    if (GroupName.allKEM.contains(groupId)) {
      final kem = KEMKeyExchange(groupId);
      final privateKey = kem.getRandomPrivateKey();
      final publicKey = kem.calcPublicValue(privateKey);
      _clientKeyShares[groupId] = privateKey;
      return TlsKeyShareEntry(group: groupId, keyExchange: publicKey);
    } else {
      // ECDH
      final kex = ECDHKeyExchange(groupId, (3, 4)); // Version 3.4 for TLS 1.3
      final privateKey = kex.getRandomPrivateKey();
      final publicKey = kex.calcPublicValue(privateKey);
      _clientKeyShares[groupId] = privateKey;
      return TlsKeyShareEntry(group: groupId, keyExchange: publicKey);
    }
  }

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
  Uint8List buildFinishedVerifyData(
      {required bool forClient, HandshakeHashes? handshakeSnapshot}) {
    if (_isTls13Plus()) {
      return _buildTls13FinishedVerifyData(
        forClient: forClient,
        handshakeSnapshot: handshakeSnapshot,
      );
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

  Uint8List _buildTls13FinishedVerifyData(
      {required bool forClient, HandshakeHashes? handshakeSnapshot}) {
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
    final transcript = (handshakeSnapshot ?? handshakeHashes).digest(hashName);
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
    HandshakeHashes? handshakeSnapshot,
  }) {
    final prfName = _prfHashName();
    return KeyExchange.calcVerifyBytes(
      version,
      handshakeSnapshot ?? handshakeHashes,
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
    final isTls13Ticket =
        _isTls13Plus() && message.handshakeType == TlsHandshakeType.newSessionTicket;
    final isPostHandshake = message.handshakeType == TlsHandshakeType.keyUpdate ||
        isTls13Ticket;
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

  void _updateHandshakeTranscript(
    TlsHandshakeMessage message, {
    Uint8List? rawBytes,
  }) {
    if (_shouldSkipTranscript(message)) {
      return;
    }
    // Use raw on-the-wire bytes when available to avoid re-serializing and
    // potentially changing the transcript (e.g., dropping unknown extensions).
    final bytes = rawBytes ?? message.serialize();
    handshakeHashes.update(bytes);
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

  // ---------------------------------------------------------------------------
  // PSK Selection for TLS 1.3 (server-side)
  // ---------------------------------------------------------------------------

  /// Result of PSK selection from ClientHello.
  PskSelectionResult? _selectedPsk;

  /// Get the result of PSK selection after processing ClientHello.
  PskSelectionResult? get selectedPsk => _selectedPsk;

  /// Select a PSK from the ClientHello for TLS 1.3 handshake.
  ///
  /// This method should be called by the server after receiving ClientHello.
  /// It validates binders and returns selection result that can be used to
  /// build the ServerHello pre_shared_key extension.
  ///
  /// Returns null if no acceptable PSK is found.
  Future<PskSelectionResult?> selectPskFromClientHello(
    TlsClientHello clientHello, {
    required String prfName,
  }) async {
    _selectedPsk = null;

    // Check if client advertised PSK extension
    final extensions = clientHello.extensions;
    if (extensions == null) {
      return null;
    }

    final pskExt = extensions.last;
    if (pskExt is! TlsPreSharedKeyExtension) {
      return null;
    }

    // Check PSK key exchange modes
    final pskModesExt = extensions.byType(ExtensionType.psk_key_exchange_modes);
    if (pskModesExt == null) {
      return null;
    }

    final supportedModes = _extractPskModes(pskModesExt);
    final serverModes = handshakeSettings.pskModes;
    final hasDheKe = supportedModes.contains(PskKeyExchangeMode.psk_dhe_ke) &&
        serverModes.contains('psk_dhe_ke');
    final hasKe = supportedModes.contains(PskKeyExchangeMode.psk_ke) &&
        serverModes.contains('psk_ke');

    if (!hasDheKe && !hasKe) {
      return null;
    }

    // No server-side PSK configs and no ticket keys
    if (handshakeSettings.pskConfigs.isEmpty &&
        handshakeSettings.ticketKeys.isEmpty) {
      return null;
    }

    // Iterate over client identities to find a match
    for (var i = 0; i < pskExt.identities.length; i++) {
      final identity = pskExt.identities[i];

      // Try external PSK first
      final externalConfig = _findPskConfig(identity.identity);
      if (externalConfig != null) {
        // Check if PSK hash matches the selected PRF
        if (externalConfig.hash != prfName) {
          continue;
        }

        // Verify binder
        try {
          verifyClientHelloPskBinder(
            clientHello: clientHello,
            binderIndex: i,
            secret: externalConfig.secret,
            hashName: externalConfig.hash,
            external: true,
          );
        } on TLSIllegalParameterException {
          await _sendAlert(AlertLevel.fatal, AlertDescription.illegal_parameter);
          rethrow;
        }

        _selectedPsk = PskSelectionResult(
          selectedIndex: i,
          psk: externalConfig.secret,
          pskHash: externalConfig.hash,
          isExternal: true,
          identity: identity.identity,
          useDheKe: hasDheKe,
        );
        return _selectedPsk;
      }

      // Try to decrypt session ticket
      final ticketResult = _tryDecryptTicket(identity);
      if (ticketResult != null) {
        final (psk, ticket) = ticketResult;
        final ticketHash = psk.length == 32 ? 'sha256' : 'sha384';

        // Check if ticket hash matches selected PRF
        if (ticketHash != prfName) {
          continue;
        }

        // Verify binder
        try {
          verifyClientHelloPskBinder(
            clientHello: clientHello,
            binderIndex: i,
            secret: psk,
            hashName: ticketHash,
            external: false,
          );
        } on TLSIllegalParameterException {
          await _sendAlert(AlertLevel.fatal, AlertDescription.illegal_parameter);
          rethrow;
        }

        _selectedPsk = PskSelectionResult(
          selectedIndex: i,
          psk: psk,
          pskHash: ticketHash,
          isExternal: false,
          identity: identity.identity,
          useDheKe: hasDheKe,
          ticket: ticket,
        );
        return _selectedPsk;
      }
    }

    return null;
  }

  /// Build the pre_shared_key extension for ServerHello.
  ///
  /// Returns null if no PSK was selected.
  TlsServerPreSharedKeyExtension? buildServerPreSharedKeyExtension() {
    final selection = _selectedPsk;
    if (selection == null) {
      return null;
    }
    return TlsServerPreSharedKeyExtension(
      selectedIdentity: selection.selectedIndex,
    );
  }

  /// Extract PSK modes from the extension.
  List<int> _extractPskModes(TlsExtension ext) {
    if (ext is TlsRawExtension) {
      final body = ext.body;
      if (body.isEmpty) {
        return const <int>[];
      }
      final parser = Parser(body);
      final length = parser.get(1);
      if (length > parser.getRemainingLength()) {
        return const <int>[];
      }
      final modes = <int>[];
      for (var i = 0; i < length; i++) {
        modes.add(parser.get(1));
      }
      return modes;
    }
    // Try dynamic access for typed extension
    try {
      final dynamic typedExt = ext;
      final modes = typedExt.modes;
      if (modes is List<int>) {
        return modes;
      }
      if (modes is List) {
        return modes.cast<int>();
      }
    } catch (_) {}
    return const <int>[];
  }

  /// Try to decrypt a session ticket identity.
  ///
  /// Returns (psk, ticket) if successful, null otherwise.
  (Uint8List, TlsNewSessionTicket)? _tryDecryptTicket(TlsPskIdentity identity) {
    final ticketKeys = handshakeSettings.ticketKeys;
    if (ticketKeys.isEmpty) {
      return null;
    }

    // For now, we check if the identity matches any stored ticket
    // Full ticket decryption requires the ticket encryption key infrastructure
    for (final ticket in tls13Tickets) {
      if (_bytesEqual(identity.identity, ticket.ticket)) {
        // Derive PSK from resumption master secret
        final resSecret = session.resumptionMasterSecret;
        if (resSecret.isEmpty) {
          continue;
        }

        final ticketHash = resSecret.length == 32 ? 'sha256' : 'sha384';
        final psk = HKDF_expand_label(
          resSecret,
          Uint8List.fromList('resumption'.codeUnits),
          ticket.ticketNonce,
          resSecret.length,
          ticketHash,
        );

        return (psk, ticket);
      }
    }

    return null;
  }

  void _validateCertificateChain(X509CertChain chain) {
    final now = DateTime.now().toUtc();
    for (final cert in chain.x509List) {
      if (cert.notBefore != null && now.isBefore(cert.notBefore!)) {
        throw TLSHandshakeFailure('Certificate not yet valid');
      }
      if (cert.notAfter != null && now.isAfter(cert.notAfter!)) {
        throw TLSHandshakeFailure('Certificate expired');
      }
    }
    // FUTURE: Full certificate path validation (signature verification up to trust anchor)
    // Currently validates expiration dates; full chain verification requires trust store integration
  }
}

/// Result of PSK selection from ClientHello.
class PskSelectionResult {
  PskSelectionResult({
    required this.selectedIndex,
    required Uint8List psk,
    required this.pskHash,
    required this.isExternal,
    required Uint8List identity,
    required this.useDheKe,
    this.ticket,
  })  : psk = Uint8List.fromList(psk),
        identity = Uint8List.fromList(identity);

  /// Index of the selected PSK identity in the ClientHello extension.
  final int selectedIndex;

  /// The PSK secret.
  final Uint8List psk;

  /// Hash algorithm for the PSK ('sha256' or 'sha384').
  final String pskHash;

  /// Whether this is an external PSK (vs resumption).
  final bool isExternal;

  /// The identity that was selected.
  final Uint8List identity;

  /// Whether to use PSK with DHE key exchange.
  final bool useDheKe;

  /// The ticket if this is a resumption PSK.
  final TlsNewSessionTicket? ticket;
}
