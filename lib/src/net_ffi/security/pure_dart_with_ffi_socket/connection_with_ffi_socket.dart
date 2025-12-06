import 'dart:typed_data';
import 'package:tlslite/src/tls_extensions.dart';
import 'package:tlslite/src/tls_protocol.dart';
import '../../../constants.dart' as tls_constants;
import '../../socket/socket_native_ffi.dart';
import '../../../tls_types.dart';
import '../../../handshake_parameters.dart';
import '../../../tls_handshake_state.dart';
import '../../../messages.dart';
import 'tls_record_layer_with_ffi_socket.dart';

/// Controla o fluxo de handshake e registros para o engine puro Dart que usa o SocketNative com FFI
/// Implementação Experimental que usa FFI para a parte do Socket
/// // TODO(tlslite-ng): portar `tlsconnection.py` para preencher esta classe
/// com logica real de negociacao, cipher suites e controle de sessao.
class PureDartTlsConnectionFFI {
  PureDartTlsConnectionFFI({
    required this.mode,
    required PureDartTlsConfig config,
  })  : _config = config,
        _recordLayer = PureDartRecordLayerFFI(mode: mode),
        _handshakeState = PureDartTlsHandshakeStateMachine(mode: mode),
        _keyShareCoordinator = PureDartKeyShareCoordinator(mode: mode),
        _signatureNegotiator = const SignatureSchemeNegotiator();

  final PureDartTlsMode mode;
  final PureDartTlsConfig _config;
  final PureDartRecordLayerFFI _recordLayer;
  final PureDartTlsHandshakeStateMachine _handshakeState;
  final PureDartKeyShareCoordinator _keyShareCoordinator;
  final SignatureSchemeNegotiator _signatureNegotiator;
  final List<TlsHandshakeMessage> _handshakeTranscript =
      <TlsHandshakeMessage>[];
  List<TlsKeyShareEntry> _clientHelloKeyShares = const <TlsKeyShareEntry>[];
  TlsStatusRequestExtension? _clientHelloStatusRequest;
  List<int> _clientHelloSignatureAlgorithmsCert = const <int>[];
  TlsKeyShareEntry? _serverHelloKeyShare;
  TlsStatusRequestExtension? _certificateRequestStatus;
  List<int> _certificateRequestSignatureAlgorithmsCert = const <int>[];

  static final List<int> _defaultSignatureSchemes =
      List<int>.unmodifiable(<int>[
    tls_constants.SignatureScheme.ed25519.value,
    tls_constants.SignatureScheme.rsa_pss_rsae_sha256.value,
    tls_constants.SignatureScheme.ecdsa_secp256r1_sha256.value,
  ]);

  bool get isHandshakeComplete => _recordLayer.isHandshakeComplete;

  List<TlsHandshakeMessage> get handshakeTranscript =>
      List.unmodifiable(_handshakeTranscript);

  List<TlsKeyShareEntry> get clientHelloKeyShares => _clientHelloKeyShares;

  TlsStatusRequestExtension? get clientHelloStatusRequest =>
      _clientHelloStatusRequest;

  List<int> get clientHelloSignatureAlgorithmsCert =>
      _clientHelloSignatureAlgorithmsCert;

  TlsKeyShareEntry? get serverHelloKeyShare => _serverHelloKeyShare;

    PureDartKeyShareCoordinator get keyShareCoordinator =>
      _keyShareCoordinator;

  TlsStatusRequestExtension? get certificateRequestStatus =>
      _certificateRequestStatus;

  List<int> get certificateRequestSignatureAlgorithmsCert =>
      _certificateRequestSignatureAlgorithmsCert;

  int? get negotiatedKeyShareGroup => _keyShareCoordinator.negotiatedGroup;

  bool get clientRequestedOcspStapling =>
      _clientHelloStatusRequest?.isRequest ?? false;

  bool get serverRequestedClientCertificateStatus =>
      _certificateRequestStatus?.isRequest ?? false;

  List<int> get defaultSignatureSchemes => _defaultSignatureSchemes;

  int selectServerCertificateSignatureScheme([
    List<int>? supportedSchemes,
  ]) {
    return _signatureNegotiator.selectScheme(
      peerPreferred: _clientHelloSignatureAlgorithmsCert,
      localSupported: supportedSchemes ?? _defaultSignatureSchemes,
    );
  }

  int selectClientCertificateSignatureScheme([
    List<int>? supportedSchemes,
  ]) {
    return _signatureNegotiator.selectScheme(
      peerPreferred: _certificateRequestSignatureAlgorithmsCert,
      localSupported: supportedSchemes ?? _defaultSignatureSchemes,
    );
  }

  void ensureHandshake(RawTransport transport) {
    if (_recordLayer.isHandshakeComplete) {
      return;
    }
      while (true) {
        final messages = _recordLayer.ensureHandshake(transport, _config);
        if (messages.isEmpty) {
          return;
        }
      for (final message in messages) {
        _handshakeTranscript.add(message);
        _capturePeerMetadata(message);
      }
        final completed = _handshakeState.processIncoming(messages);
        final negotiated = _handshakeState.negotiatedVersion;
        if (negotiated != null) {
          _recordLayer.setHandshakeProtocolVersion(negotiated);
        }
        if (completed) {
          _recordLayer.markHandshakeComplete();
          return;
        }
        // Ainda aguardamos mais registros de handshake para avançar o estado.
      }
  }

  int sendApplicationData(RawTransport transport, Uint8List data) {
    return _recordLayer.sendApplicationData(transport, data);
  }

  Uint8List receiveApplicationData(
      RawTransport transport, int bufferSize) {
    return _recordLayer.receiveApplicationData(transport, bufferSize);
  }

  void dispose() => _recordLayer.dispose();

  void _capturePeerMetadata(TlsHandshakeMessage message) {
    switch (mode) {
      case PureDartTlsMode.server:
        if (message is TlsClientHello) {
          _clientHelloKeyShares = message.keyShares;
          _clientHelloStatusRequest = message.statusRequest;
          _clientHelloSignatureAlgorithmsCert =
              message.signatureAlgorithmsCert;
          _keyShareCoordinator.registerClientShares(message.keyShares);
          if (_keyShareCoordinator.needsHelloRetryRequest &&
              _clientTargetsTls13(message)) {
            // TODO(tlslite-ng): gerar HelloRetryRequest real.
            throw StateError(
              'ClientHello nao trouxe key_share para TLS 1.3',
            );
          }
        }
        break;
      case PureDartTlsMode.client:
        if (message is TlsServerHello) {
          _serverHelloKeyShare = message.keyShare;
          if (message.keyShare != null) {
            _keyShareCoordinator.registerServerHelloShare(message.keyShare!);
          }
        } else if (message is TlsCertificateRequest) {
          _certificateRequestStatus = message.statusRequest;
          _certificateRequestSignatureAlgorithmsCert =
              message.signatureAlgorithmsCert;
        }
        break;
    }
  }

  bool _clientTargetsTls13(TlsClientHello hello) {
    if (hello.supportedVersions
        .any((version) => version == TlsProtocolVersion.tls13)) {
      return true;
    }
    return hello.clientVersion == TlsProtocolVersion.tls13;
  }
}
