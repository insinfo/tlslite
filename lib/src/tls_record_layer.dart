import 'dart:async';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'constants.dart';
import 'defragmenter.dart';
import 'errors.dart';
import 'handshake_hashes.dart';
import 'messages.dart' as tlsmsg;
import 'recordlayer.dart';
import 'session.dart';
import 'tls_protocol.dart';
import 'utils/codec.dart';

/// Dart translation of tlslite-ng's ``tlsrecordlayer.py``.
///
/// The Python implementation exposes a large surface area that spans buffered
/// socket semantics, record-layer framing, handshake digest tracking, and a
/// variety of TLS 1.2/1.3 protocol quirks. Porting everything verbatim would be
/// unwieldy, so the approach here is incremental: first capture the shared
/// state and the small helper routines that other modules need right away, then
/// iteratively fill in the handshake/message plumbing.
class TLSRecordLayer {
  TLSRecordLayer(Socket socket)
      : sock = socket,
        _recordLayer = RecordLayer(socket),
        _defragmenter = Defragmenter(),
        _handshakeHash = HandshakeHashes() {
    // Match the static sizing hints from tlslite-ng so that once the
    // handshake/message code lands the buffering behaviour stays consistent.
    _defragmenter.addStaticSize(ContentType.change_cipher_spec, 1);
    _defragmenter.addStaticSize(ContentType.alert, 2);
    _defragmenter.addDynamicSize(ContentType.handshake, 1, 3);
    clearReadBuffer();
    clearWriteBuffer();
  }

  /// Underlying TCP socket.
  final Socket sock;

  /// Low-level encoder/decoder for TLS records.
  final RecordLayer _recordLayer;

  /// Buffers fragmented records until complete handshake messages are ready.
  final Defragmenter _defragmenter;

  /// Running transcript hashes for CertificateVerify/Finished validation.
  HandshakeHashes _handshakeHash;

  /// Expose the transcript state for future handshake helpers.
  HandshakeHashes get handshakeHashes => _handshakeHash;

  /// Session associated with this connection (if any).
  Session? session;

  /// Whether the logical TLS connection is currently closed.
  bool closed = true;

  /// Tracks if this connection was resumed from a cached session.
  bool resumed = false;

  /// Whether the transport socket should be closed during shutdown.
  bool closeSocket = true;

  /// If true, abrupt closes are tolerated without surfacing TLS errors.
  bool ignoreAbruptClose = false;

  /// Upper bound for plaintext bytes placed inside a single TLS record.
  int _userRecordLimit = 1 << 14;

  /// Buffered application data awaiting consumption by callers.
  Uint8List _readBuffer = Uint8List(0);

  /// Peek at the currently queued plaintext (primarily for debugging/tests).
  Uint8List get bufferedPlaintext => _readBuffer;

  /// Session tickets received from the peer.
  final List<tlsmsg.TlsNewSessionTicket> tickets =
      <tlsmsg.TlsNewSessionTicket>[];

  /// Callback to notify when a heartbeat response is processed.
  void Function(tlsmsg.TlsHeartbeat)? heartbeatResponseCallback;

  /// Heartbeat negotiation flags.
  bool heartbeatCanReceive = false;
  bool heartbeatCanSend = false;
  bool heartbeatSupported = false;

  /// Whether post-handshake auth must fail when the peer omits a certificate.
  bool clientCertRequired = false;

  /// Human-readable compression algorithms chosen for certificate chains.
  String? serverCertCompressionAlgo;
  String? clientCertCompressionAlgo;

  /// Tickets advertised after the handshake (TLS 1.3 specific state).
  final List<tlsmsg.TlsNewSessionTicket> tls13Tickets =
      <tlsmsg.TlsNewSessionTicket>[];

  /// Latest early-data limit negotiated via NewSessionTicket (TLS 1.3).
  int maxEarlyData = 0;

  /// -----------------------------------------------------------------------
  /// Public helpers and state accessors

  /// Reset buffered plaintext waiting for consumers.
  void clearReadBuffer() {
    _readBuffer = Uint8List(0);
  }

  /// Reset any queued plaintext waiting to be encrypted.
  void clearWriteBuffer() {
    // Record coalescing is not implemented yet.
  }

  /// Maximum plaintext payload per record.
  int get recordSize =>
      _userRecordLimit < _recordLayer.sendRecordLimit
          ? _userRecordLimit
          : _recordLayer.sendRecordLimit;

  set recordSize(int value) {
    if (value <= 0) {
      throw ArgumentError.value(value, 'value', 'record size must be positive');
    }
    _userRecordLimit = value;
  }

  /// Whether the record layer currently treats this endpoint as a client.
  bool get isClient => _recordLayer.client;

  set isClient(bool value) {
    _recordLayer.client = value;
  }

  /// Active protocol version.
  TlsProtocolVersion get version => _recordLayer.version;

  set version(TlsProtocolVersion value) {
    _recordLayer.version = value;
    if (value > const TlsProtocolVersion(3, 3)) {
      _recordLayer.tls13record = true;
    }
  }

  /// Whether encrypt-then-MAC is enabled for CBC cipher suites.
  bool get encryptThenMAC => _recordLayer.encryptThenMAC;

  set encryptThenMAC(bool value) {
    _recordLayer.encryptThenMAC = value;
  }

  /// Human readable protocol name (e.g. ``TLS 1.2``).
  String? getVersionName() {
    const names = {
      (3, 0): 'SSL 3.0',
      (3, 1): 'TLS 1.0',
      (3, 2): 'TLS 1.1',
      (3, 3): 'TLS 1.2',
      (3, 4): 'TLS 1.3',
    };
    final key = (version.major, version.minor);
    return names[key];
  }

  /// Name of the negotiated symmetric cipher (if any).
  String? getCipherName() => _recordLayer.getCipherName();

  /// Backend selected for the symmetric cipher (python/openssl/etc.).
  String? getCipherImplementation() => _recordLayer.getCipherImplementation();

  /// ``send`` compatibility wrapper.
  Future<int> send(Uint8List data) async {
    await write(data);
    return data.length;
  }

  /// ``sendall`` compatibility wrapper.
  Future<void> sendall(Uint8List data) => write(data);

  /// ``recv`` compatibility wrapper.
  Future<Uint8List> recv(int bufsize) => read(max: bufsize);

  /// Equivalent of Python's ``recv_into`` helper.
  Future<int?> recvInto(Uint8List buffer) async {
    final chunk = await read(max: buffer.length, min: 0);
    if (chunk.isEmpty) {
      return null;
    }
    buffer.setRange(0, chunk.length, chunk);
    return chunk.length;
  }

  /// Gracefully shut down the TLS connection.
  Future<void> close() async {
    await _shutdown(resumable: true);
  }

  /// -----------------------------------------------------------------------
  /// Internal primitives ported from tlslite-ng

  /// Prepare for a new handshake (initial or renegotiation).
  void handshakeStart({required bool client}) {
    if (!closed) {
      throw StateError('Renegotiation disallowed for security reasons');
    }
    isClient = client;
    _handshakeHash = HandshakeHashes();
    _defragmenter.clearBuffers();
    resumed = false;
    closed = true;
  }

  /// Mark handshake completion.
  void handshakeDone(bool resumedSession) {
    resumed = resumedSession;
    closed = false;
  }

  /// Mirror ``TLSRecordLayer.calcPendingStates`` from Python.
  void calcPendingStates(
    int cipherSuite,
    Uint8List masterSecret,
    Uint8List clientRandom,
    Uint8List serverRandom, {
    List<String>? implementations,
  }) {
    _recordLayer.calcPendingStates(
      cipherSuite,
      masterSecret,
      clientRandom,
      serverRandom,
      implementations,
    );
  }

  /// Activate the write state prepared via [calcPendingStates].
  void changeWriteState() => _recordLayer.changeWriteState();

  /// Activate the read state prepared via [calcPendingStates].
  void changeReadState() => _recordLayer.changeReadState();

  /// Core shutdown logic shared by ``close`` and alert-induced teardown.
  Future<void> _shutdown({required bool resumable}) async {
    _recordLayer.shutdown();
    closed = true;
    if (closeSocket) {
      await sock.close();
    }
    if (!resumable && session != null) {
      session!.resumable = false;
    }
  }

  /// -----------------------------------------------------------------------
  /// Placeholders for the remaining porting work

  Future<Uint8List> read({int? max, int min = 1}) async {
    if (min < 0) {
      throw ArgumentError.value(min, 'min', 'must be >= 0');
    }
    if (max != null && max < 0) {
      throw ArgumentError.value(max, 'max', 'must be >= 0');
    }
    if (max != null && max < min) {
      throw ArgumentError(
        'max ($max) must be greater than or equal to min ($min)',
      );
    }

    while (_readBuffer.length < min) {
      await _pumpApplicationData();
    }

    final takeLength = max == null
        ? _readBuffer.length
        : math.min(max, _readBuffer.length);
    final result = Uint8List.fromList(_readBuffer.sublist(0, takeLength));
    _readBuffer = Uint8List.fromList(_readBuffer.sublist(takeLength));
    return result;
  }

  Stream<Uint8List> readAsync({int? max, int min = 1}) async* {
    yield await read(max: max, min: min);
  }

  Future<void> write(Uint8List data) async {
    await for (final _ in writeAsync(data)) {
      // Drain the stream to ensure all fragments are flushed.
    }
  }

  Stream<void> writeAsync(Uint8List data) async* {
    if (data.isEmpty) {
      return;
    }

    await _sendMsg(tlsmsg.TlsApplicationData(data: data));
    yield null;
  }

  Future<void> sendHeartbeatRequest(Uint8List payload, int paddingLength) async {
    throw UnimplementedError('Heartbeat handling not ported yet');
  }

  Future<void> handleKeyUpdateRequest(tlsmsg.TlsKeyUpdate request) async {
    throw UnimplementedError('KeyUpdate handling not ported yet');
  }

  Future<void> _pumpApplicationData() async {
    while (true) {
      final (header, parser) = await _getNextRecord();
      final recordType = _resolveRecordType(header);

      if (recordType == ContentType.application_data) {
        final payload = parser.getFixBytes(parser.getRemainingLength());
        _appendPlaintext(payload);
        return;
      }

      if (recordType == ContentType.change_cipher_spec) {
        continue;
      }

      if (recordType == ContentType.alert) {
        await _handleIncomingAlert(parser);
        continue;
      }

      if (recordType == ContentType.handshake) {
        throw UnimplementedError('Handshake processing not ported yet');
      }

      if (recordType == ContentType.heartbeat) {
        throw UnimplementedError('Heartbeat handling not ported yet');
      }

      throw TLSLocalAlert(
        AlertDescription.unexpected_message,
        AlertLevel.fatal,
        detailedMessage: 'Received unsupported record type $recordType',
      );
    }
  }

  void _appendPlaintext(Uint8List chunk) {
    if (chunk.isEmpty) {
      return;
    }

    if (_readBuffer.isEmpty) {
      _readBuffer = Uint8List.fromList(chunk);
      return;
    }

    final combined = Uint8List(_readBuffer.length + chunk.length);
    combined.setRange(0, _readBuffer.length, _readBuffer);
    combined.setRange(_readBuffer.length, combined.length, chunk);
    _readBuffer = combined;
  }

  /// Serialize and send a TLS message, fragmenting as necessary.
  Future<void> _sendMsg(
    tlsmsg.TlsMessage message, {
    bool randomizeFirstBlock = true,
    bool updateHandshakeHash = true,
  }) async {
    final contentType = message.contentType.code;
    final payload = message.serialize();
    await _sendRawMessage(
      contentType,
      payload,
      randomizeFirstBlock: randomizeFirstBlock,
      updateHandshakeHash:
          updateHandshakeHash && contentType == ContentType.handshake,
    );
  }

  Future<void> _sendRawMessage(
    int contentType,
    Uint8List payload, {
    bool randomizeFirstBlock = true,
    bool updateHandshakeHash = false,
  }) async {
    if (payload.isEmpty) {
      return;
    }

    Uint8List remaining = payload;
    final needsFirstByteMasking =
        randomizeFirstBlock &&
            version <= const TlsProtocolVersion(3, 1) &&
            _recordLayer.isCBCMode() &&
            contentType == ContentType.application_data;

    if (needsFirstByteMasking) {
      final firstByte = Uint8List.fromList(<int>[remaining.first]);
      await _sendMsgThroughSocket(Message(contentType, firstByte));
      if (remaining.length == 1) {
        return;
      }
      remaining = Uint8List.fromList(remaining.sublist(1));
    }

    if (updateHandshakeHash) {
      _handshakeHash.update(remaining);
    }

    var offset = 0;
    while (offset < remaining.length) {
      final chunkLength = math.min(recordSize, remaining.length - offset);
      final chunk = Uint8List.fromList(
        remaining.sublist(offset, offset + chunkLength),
      );
      await _sendMsgThroughSocket(Message(contentType, chunk));
      offset += chunkLength;
    }
  }

  Future<void> _sendMsgThroughSocket(Message message) =>
      _recordLayer.sendRecord(message);

  Future<Never> _sendError(int alertDescription, [String? errorStr]) async {
    final payload = Uint8List.fromList(<int>[
      AlertLevel.fatal,
      alertDescription,
    ]);
    await _sendRawMessage(
      ContentType.alert,
      payload,
      randomizeFirstBlock: false,
      updateHandshakeHash: false,
    );
    await _shutdown(resumable: false);
    throw TLSLocalAlert(
      alertDescription,
      AlertLevel.fatal,
      detailedMessage: errorStr,
    );
  }

  Future<(dynamic, Parser)> _getNextRecord() async {
    while (true) {
      while (true) {
        final buffered = _defragmenter.getMessage();
        if (buffered == null) {
          break;
        }

        final msgType = buffered.$1;
        final payload = buffered.$2;
        final header = RecordHeader3().create(version, msgType, payload.length);
        return (header, Parser(payload));
      }

      final earlyDataOk = _recordLayer.earlyDataOk;
      final (header, parser) = await _getNextRecordFromSocket();

      final recordType = _resolveRecordType(header);

      final isTls13Ccs =
          version > const TlsProtocolVersion(3, 3) &&
              recordType == ContentType.change_cipher_spec;
      if (recordType == ContentType.application_data || isTls13Ccs) {
        if (isTls13Ccs) {
          _recordLayer.earlyDataOk = earlyDataOk;
        }
        return (header, parser);
      }

      if (recordType == ContentType.heartbeat || header is RecordHeader2) {
        return (header, parser);
      }

      final remaining = parser.getFixBytes(parser.getRemainingLength());
      _defragmenter.addData(recordType, remaining);
    }
  }

  Future<(dynamic, Parser)> _getNextRecordFromSocket() async {
    (dynamic, Parser) record;
    try {
      record = await _recordLayer.recvRecord();
    } on TLSUnexpectedMessage {
      await _sendError(AlertDescription.unexpected_message);
    } on TLSRecordOverflow {
      await _sendError(AlertDescription.record_overflow);
    } on TLSIllegalParameterException {
      await _sendError(AlertDescription.illegal_parameter);
    } on TLSDecryptionFailed {
      await _sendError(
        AlertDescription.decryption_failed,
        'Encrypted data not a multiple of blocksize',
      );
    } on TLSBadRecordMAC {
      await _sendError(
        AlertDescription.bad_record_mac,
        'MAC failure (or padding failure)',
      );
    }

    final (header, parser) = record;
    if (header is! RecordHeader2 &&
        parser.getRemainingLength() == 0 &&
        header.type != ContentType.application_data) {
      await _sendError(
        AlertDescription.unexpected_message,
        'Received empty non-application data record',
      );
    }

    if (header is! RecordHeader2 &&
        !ContentType.all.contains(header.type)) {
      await _sendError(
        AlertDescription.unexpected_message,
        'Received record with unknown ContentType',
      );
    }

    return (header, parser);
  }

  int _resolveRecordType(dynamic header) {
    if (header is RecordHeader2) {
      return ContentType.handshake;
    }
    return header.type;
  }

  Future<void> _handleIncomingAlert(Parser parser) async {
    if (parser.getRemainingLength() < 2) {
      await _sendError(
        AlertDescription.decode_error,
        'Alert message truncated',
      );
    }

    final level = parser.get(1);
    final description = parser.get(1);
    final isCloseNotify = description == AlertDescription.close_notify;
    final isWarning = level == AlertLevel.warning;

    if (isCloseNotify || isWarning) {
      if (isCloseNotify) {
        try {
          await _sendRawMessage(
            ContentType.alert,
            Uint8List.fromList(<int>[
              AlertLevel.warning,
              AlertDescription.close_notify,
            ]),
            randomizeFirstBlock: false,
            updateHandshakeHash: false,
          );
        } catch (_) {
          // Ignore transport errors while acknowledging alerts.
        }
        await _shutdown(resumable: true);
      } else {
        await _shutdown(resumable: false);
      }
    } else {
      await _shutdown(resumable: false);
    }

    throw TLSRemoteAlert(description, level);
  }
}
