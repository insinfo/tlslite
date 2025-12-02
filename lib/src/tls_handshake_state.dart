import 'tls_messages.dart';
import 'net/security/pure_dart/pure_dart_tls_types.dart';

enum _HandshakePhase {
  idle,
  waitingPeerFinished,
  complete,
}

/// Minimal state machine inspired by tlslite-ng's `tlsconnection.py`.
///
/// This focuses on the ordering of ClientHello/ServerHello and Finished
/// messages, allowing us to determine when the record layer can switch from
/// handshake mode to application-data mode. The actual cryptographic
/// operations are still TODO while the remaining tlslite-ng modules are ported.
class PureDartTlsHandshakeStateMachine {
  PureDartTlsHandshakeStateMachine({required this.mode});

  final PureDartTlsMode mode;
  _HandshakePhase _phase = _HandshakePhase.idle;
  TlsProtocolVersion? _negotiatedVersion;

  bool processIncoming(List<TlsHandshakeMessage> messages) {
    for (final message in messages) {
      _advance(message);
    }
    return isHandshakeComplete;
  }

  void _advance(TlsHandshakeMessage message) {
    switch (_phase) {
      case _HandshakePhase.idle:
        _handleInitial(message);
        break;
      case _HandshakePhase.waitingPeerFinished:
        if (message is TlsFinished) {
          _phase = _HandshakePhase.complete;
        }
        break;
      case _HandshakePhase.complete:
        _handlePostHandshake(message);
        break;
    }
  }

  void _handleInitial(TlsHandshakeMessage message) {
    switch (mode) {
      case PureDartTlsMode.server:
        if (message is! TlsClientHello) {
          throw StateError(
            'Servidor puro Dart esperava ClientHello inicial, recebeu '
            '${message.handshakeType.name}',
          );
        }
        _negotiatedVersion = _selectClientProtocolVersion(message);
        _phase = _HandshakePhase.waitingPeerFinished;
        break;
      case PureDartTlsMode.client:
        if (message is! TlsServerHello) {
          throw StateError(
            'Cliente puro Dart esperava ServerHello inicial, recebeu '
            '${message.handshakeType.name}',
          );
        }
        _negotiatedVersion =
            message.selectedSupportedVersion ?? message.serverVersion;
        _phase = _HandshakePhase.waitingPeerFinished;
        break;
    }
  }

  TlsProtocolVersion _selectClientProtocolVersion(TlsClientHello hello) {
    if (hello.supportedVersions.isEmpty) {
      return hello.clientVersion;
    }
    return hello.supportedVersions.reduce(_pickNewerVersion);
  }

  TlsProtocolVersion _pickNewerVersion(
    TlsProtocolVersion left,
    TlsProtocolVersion right,
  ) {
    if (right.major > left.major) {
      return right;
    }
    if (right.major == left.major && right.minor > left.minor) {
      return right;
    }
    return left;
  }

  void _handlePostHandshake(TlsHandshakeMessage message) {
    switch (mode) {
      case PureDartTlsMode.client:
        if (_isClientAllowedPostHandshake(message)) {
          return;
        }
        break;
      case PureDartTlsMode.server:
        if (_isServerAllowedPostHandshake(message)) {
          return;
        }
        break;
    }
    throw StateError(
      'Mensagem pós-handshake inesperada: ${message.handshakeType.name}',
    );
  }

  bool _isClientAllowedPostHandshake(TlsHandshakeMessage message) {
    switch (message.handshakeType) {
      case TlsHandshakeType.newSessionTicket:
      case TlsHandshakeType.keyUpdate:
      case TlsHandshakeType.certificateRequest:
        return true;
      default:
        return false;
    }
  }

  bool _isServerAllowedPostHandshake(TlsHandshakeMessage message) {
    switch (message.handshakeType) {
      case TlsHandshakeType.keyUpdate:
      case TlsHandshakeType.certificate:
      case TlsHandshakeType.certificateVerify:
      case TlsHandshakeType.finished:
        return true;
      default:
        return false;
    }
  }

  bool get isHandshakeComplete => _phase == _HandshakePhase.complete;

  bool get hasSeenHello => _phase != _HandshakePhase.idle;

  TlsProtocolVersion? get negotiatedVersion => _negotiatedVersion;
}
