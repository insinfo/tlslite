import 'dart:typed_data';
import 'dart:io' as io;
import 'package:test/test.dart';
import 'package:tlslite/src/tls_types.dart';

import 'package:tlslite/src/net_ffi/security/pure_dart_with_ffi_socket/tls_record_layer_with_ffi_socket.dart';
import 'package:tlslite/src/net_ffi/socket/socket_native_ffi.dart';
import 'package:tlslite/src/messages.dart';

import 'package:tlslite/src/tls_protocol.dart';

void main() {
  test('uses negotiated TLS version hint for parsing', () {
    final certPem =
        io.File('tlslite-ng/tests/serverX509Cert.pem').readAsStringSync();
    final keyPem =
        io.File('tlslite-ng/tests/serverX509Key.pem').readAsStringSync();

    final config = PureDartTlsConfig(
      certificateChainPem: certPem,
      privateKeyPem: keyPem,
    );

    final certificateEntry = TlsCertificateEntry(
      certificate: config.certificateChainDer.first,
      extensions: Uint8List(0),
    );
    final certificate = TlsCertificate.tls13(
      certificateEntries: <TlsCertificateEntry>[certificateEntry],
    );

    final fragment = certificate.serialize();
    final record = TlsPlaintext(
      header: TlsRecordHeader(
        contentType: TlsContentType.handshake,
        protocolVersion: TlsProtocolVersion.tls12,
        fragmentLength: fragment.length,
      ),
      fragment: fragment,
    );

    final transport = _FakeTransport(record.serialize());
    final layer = PureDartRecordLayerFFI(mode: PureDartTlsMode.server)
      ..setHandshakeProtocolVersion(TlsProtocolVersion.tls13);

    final messages = layer.ensureHandshake(transport, config);
    expect(messages, hasLength(1));
    final parsed = messages.single as TlsCertificate;
    expect(parsed.isTls13, isTrue);
  });
}

class _FakeTransport implements RawTransport {
  _FakeTransport(Uint8List payload) : _payload = Uint8List.fromList(payload);

  final Uint8List _payload;
  int _offset = 0;

  @override
  SocketBlockingMode get blockingMode => SocketBlockingMode.blocking;

  @override
  bool get isClosed => false;

  @override
  (String, int) get address => ('0.0.0.0', 0);

  @override
  int get port => 0;

  @override
  Duration? get timeoutDuration => null;

  @override
  int? get nativeHandle => null;

  @override
  void setBlockingMode(SocketBlockingMode mode) {}

  @override
  void settimeout(double? timeout) {}

  @override
  void setTimeout(Duration? duration) {}

  @override
  void bind(String host, int port) =>
      throw UnimplementedError('bind not supported');

  @override
  void connect(String host, int port) =>
      throw UnimplementedError('connect not supported');

  @override
  void listen(int backlog) => throw UnimplementedError('listen not supported');

  @override
  RawTransport accept() => throw UnimplementedError('accept not supported');

  @override
  int send(Uint8List data) => data.length;

  @override
  void sendall(Uint8List data) {}

  @override
  Uint8List recv(int bufferSize) {
    if (_offset >= _payload.length) {
      return Uint8List(0);
    }
    final end = (_offset + bufferSize).clamp(0, _payload.length).toInt();
    final chunk = Uint8List.sublistView(_payload, _offset, end);
    _offset = end;
    return chunk;
  }

  @override
  (Uint8List, String, int) recvfrom(int bufferSize) =>
      (Uint8List(0), '0.0.0.0', 0);

  @override
  int sendto(Uint8List data, String host, int port) => data.length;

  @override
  bool waitForRead({Duration? timeout}) => true;

  @override
  bool waitForWrite({Duration? timeout}) => true;

  @override
  void setReuseAddress(bool enabled) {}

  @override
  void setReusePort(bool enabled) {}

  @override
  void setNoDelay(bool enabled) {}

  @override
  void shutdown([SocketShutdown how = SocketShutdown.both]) {}

  @override
  void close() {}
}
