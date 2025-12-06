// import 'dart:typed_data';

// import '../socket/socket_native_ffi.dart';
// import '../../tls_types.dart';
// import 'connection_with_ffi_socket.dart';

// /// Engine inicial responsável por concentrar o porte do TLS puro Dart que usa o SocketNative com FFI
// ///
// /// // TODO(tlslite-ng): portar `tlslite-ng/tlslite/tlsconnection.py`,
// /// `recordlayer.py`, `messages.py` e dependências para dar suporte real
// /// ao handshake, negociação de ciphersuites e fluxo de registros.
// class PureDartTlsEngineFFI {
//   PureDartTlsEngineFFI({
//     required this.mode,
//     PureDartTlsConfig? config,
//   }) : _config = config ?? PureDartTlsConfig() {
//     _connection = PureDartTlsConnectionFFI(mode: mode, config: _config);
//   }

//   final PureDartTlsMode mode;
//   final PureDartTlsConfig _config;
//   late final PureDartTlsConnectionFFI _connection;

//   bool get isHandshakeComplete => _connection.isHandshakeComplete;

//   void ensureHandshakeCompleted(RawTransport transport) {
//     _connection.ensureHandshake(transport);
//   }

//   int sendApplicationData(RawTransport transport, Uint8List data) {
//     ensureHandshakeCompleted(transport);
//     return _connection.sendApplicationData(transport, data);
//   }

//   Uint8List receiveApplicationData(
//     RawTransport transport,
//     int bufferSize,
//   ) {
//     ensureHandshakeCompleted(transport);
//     return _connection.receiveApplicationData(transport, bufferSize);
//   }

//   void dispose() => _connection.dispose();
// }
