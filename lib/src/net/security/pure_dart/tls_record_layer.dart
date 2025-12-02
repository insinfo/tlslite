import 'dart:math';
import 'dart:typed_data';

import '../../socket/socket_native_ffi.dart';
import '../../../utils/codec.dart' show DecodeError;
import 'pure_dart_tls_types.dart';
import 'tls_messages.dart';

/// Responsável por encapsular/decapsular registros TLS usando apenas Dart.
class PureDartRecordLayer {
  PureDartRecordLayer({required this.mode})
      : _protocolVersion = TlsProtocolVersion.tls12;

  static const int _maxPlaintextLength = 16 * 1024; // 2^14 bytes

  final PureDartTlsMode mode;
  final TlsProtocolVersion _protocolVersion;
  bool _handshakeComplete = false;
  bool _peerSentChangeCipherSpec = false;
  TlsProtocolVersion? _handshakeProtocolVersion;

  bool get isHandshakeComplete => _handshakeComplete;
  bool get peerSentChangeCipherSpec => _peerSentChangeCipherSpec;

  List<TlsHandshakeMessage> ensureHandshake(
    RawTransport transport,
    PureDartTlsConfig config,
  ) {
    if (_handshakeComplete) {
      return const <TlsHandshakeMessage>[];
    }
    if (mode == PureDartTlsMode.client) {
      throw StateError(
        'Modo cliente do TLS puro Dart ainda não foi portado de tlslite-ng.',
      );
    }
    config.ensureServerCredentials();

    while (true) {
      final record = _readRecord(transport);
      switch (record.header.contentType) {
        case TlsContentType.handshake:
          try {
            final messages = TlsHandshakeMessage.parseFragment(
              record.fragment,
              recordVersion:
                  _handshakeProtocolVersion ?? record.header.protocolVersion,
            );
            if (messages.isEmpty) {
              _sendAlert(transport, TlsAlertDescription.decodeError);
              throw StateError('Registro de handshake vazio recebido.');
            }
            return messages;
          } on DecodeError catch (error) {
            _sendAlert(transport, TlsAlertDescription.decodeError);
            throw StateError('Falha ao parsear handshake TLS: $error');
          }
        case TlsContentType.alert:
          final alert = TlsAlert.parse(record.fragment);
          throw StateError(
            'Handshake abortado pelo par com ${alert.description.name} '
            '(${alert.level.name}).',
          );
        case TlsContentType.changeCipherSpec:
          TlsChangeCipherSpec.parse(record.fragment);
          _peerSentChangeCipherSpec = true;
          continue;
        default:
          _sendAlert(transport, TlsAlertDescription.unexpectedMessage);
          throw StateError(
            'Esperado registro de handshake, mas recebeu '
            '${record.header.contentType.name}.',
          );
      }
    }
  }

  int sendApplicationData(RawTransport transport, Uint8List data) {
    if (!_handshakeComplete) {
      throw StateError('Handshake TLS puro Dart ainda não concluído');
    }
    var offset = 0;
    while (offset < data.length) {
      final chunkLength = min(_maxPlaintextLength, data.length - offset);
      final chunk = Uint8List.sublistView(data, offset, offset + chunkLength);
      final record = TlsPlaintext(
        header: TlsRecordHeader(
          contentType: TlsContentType.applicationData,
          protocolVersion: _protocolVersion,
          fragmentLength: chunk.length,
        ),
        fragment: chunk,
      );
      _writeRecord(transport, record);
      offset += chunkLength;
    }
    return data.length;
  }

  Uint8List receiveApplicationData(
    RawTransport transport,
    int bufferSize,
  ) {
    if (!_handshakeComplete) {
      throw StateError('Handshake TLS puro Dart ainda não concluído');
    }
    final record = _readRecord(transport);
    if (record.header.contentType == TlsContentType.alert) {
      final alert = TlsAlert.parse(record.fragment);
      throw SocketException(
        'Recebido alerta ${alert.description.name} '
        '(${alert.level.name}).',
      );
    }
    if (record.header.contentType != TlsContentType.applicationData) {
      throw StateError(
        'Registro inesperado durante recebimento de dados: '
        '${record.header.contentType.name}',
      );
    }
    if (bufferSize < record.fragment.length) {
      return Uint8List.fromList(record.fragment.sublist(0, bufferSize));
    }
    return record.fragment;
  }

  void dispose() {
    _handshakeComplete = false;
    _peerSentChangeCipherSpec = false;
    _handshakeProtocolVersion = null;
  }

  void markHandshakeComplete() {
    _handshakeComplete = true;
  }

  void setHandshakeProtocolVersion(TlsProtocolVersion version) {
    _handshakeProtocolVersion = version;
  }

  TlsPlaintext _readRecord(RawTransport transport) {
    final headerBytes =
        _readExact(transport, TlsRecordHeader.serializedLength);
    final header = TlsRecordHeader.fromBytes(headerBytes);
    final fragment = header.fragmentLength == 0
        ? Uint8List(0)
        : _readExact(transport, header.fragmentLength);
    return TlsPlaintext(header: header, fragment: fragment);
  }

  void _writeRecord(RawTransport transport, TlsPlaintext record) {
    transport.sendall(record.serialize());
  }

  Uint8List _readExact(RawTransport transport, int length) {
    if (length == 0) {
      return Uint8List(0);
    }
    final builder = BytesBuilder();
    var remaining = length;
    while (remaining > 0) {
      final chunk = transport.recv(remaining);
      if (chunk.isEmpty) {
        throw SocketException(
          'Conexão encerrada antes de receber $length bytes completos',
        );
      }
      builder.add(chunk);
      remaining -= chunk.length;
    }
    return builder.toBytes();
  }

  void _sendAlert(
    RawTransport transport,
    TlsAlertDescription description, {
    TlsAlertLevel level = TlsAlertLevel.fatal,
  }) {
    try {
      final alert = TlsAlert(level: level, description: description);
      final record = TlsPlaintext(
        header: TlsRecordHeader(
          contentType: TlsContentType.alert,
          protocolVersion: _protocolVersion,
          fragmentLength: TlsAlert.serializedLength,
        ),
        fragment: alert.serialize(),
      );
      _writeRecord(transport, record);
    } catch (_) {
      // Se não for possível enviar o alerta (socket fechado, etc.), ignoramos.
    }
  }
}
