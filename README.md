# tlslite

A pure Dart implementation of the TLS protocol (Transport Layer Security), supporting TLS 1.0 through TLS 1.3 with modern cryptographic algorithms.

## Features

- **TLS 1.3** with full handshake support, HelloRetryRequest (HRR), PSK resumption, and post-quantum ML-KEM
- **TLS 1.2** with RSA, DHE, ECDHE key exchanges and client authentication
- **TLS 1.0/1.1** legacy support for backward compatibility
- **Modern Cryptography**: AES-GCM, ChaCha20-Poly1305, Ed25519, Ed448, X25519, ECDSA, ML-KEM (post-quantum)
- **Compression**: Brotli and Zstandard (zstd) support
- **OpenSSL FFI Integration**: Opcional High-performance TLS via native OpenSSL bindings

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  tlslite:
    git:
      url: https://github.com/insinfo/tlslite.git
```

## Quick Start

### Client Connection (Pure Dart)

```dart
import 'dart:io';
import 'dart:typed_data';
import 'package:tlslite/tlslite.dart';

void main() async {
  final socket = await Socket.connect('example.com', 443);
  final tls = TlsConnection(socket);
  
  await tls.handshakeClient(
    serverName: 'example.com',
    alpn: ['http/1.1'],
  );
  
  await tls.write(Uint8List.fromList('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'.codeUnits));
  final response = await tls.read();
  print(String.fromCharCodes(response));
  
  await tls.close();
}
```

### Server Connection (Pure Dart)

```dart
import 'dart:io';
import 'dart:typed_data';
import 'package:tlslite/tlslite.dart';
import 'package:tlslite/src/utils/keyfactory.dart';

void main() async {
  final server = await ServerSocket.bind('0.0.0.0', 8443);
  
  await for (final socket in server) {
    final tls = TlsConnection(socket);
    
    // Load certificate chain from PEM file
    final certChain = X509CertChain();
    certChain.parsePemList(File('server.crt').readAsStringSync());
    
    // Load private key from PEM file
    final privateKey = parsePrivateKey(File('server.key').readAsStringSync());
    
    await tls.handshakeServer(
      certChain: certChain,
      privateKey: privateKey,
    );
    
    final data = await tls.read();
    await tls.write(Uint8List.fromList('HTTP/1.1 200 OK\r\n\r\nHello!'.codeUnits));
    await tls.close();
  }
}
```

---

## Core Components

### `lib/src/tls_connection.dart` - TlsConnection

The main TLS connection class that implements the complete TLS handshake protocol for both client and server modes.

#### Overview

`TlsConnection` extends `MessageSocket` and provides:

- Full TLS 1.0/1.1/1.2/1.3 handshake support
- Session caching and PSK resumption
- Client and server certificate authentication
- ALPN (Application-Layer Protocol Negotiation)
- HelloRetryRequest (HRR) handling for TLS 1.3
- Post-quantum ML-KEM key exchange support

#### Constructor

```dart
TlsConnection(Socket socket, {SessionCache? sessionCache, Logger? logger})
```

Creates a TLS connection over a standard Dart `Socket`.

```dart
TlsConnection.custom(BinaryInput input, BinaryOutput output, {SessionCache? sessionCache, Logger? logger})
```

Creates a TLS connection over custom transports (non-socket streams).

#### Key Methods

##### `handshakeClient()`

Initiates a TLS handshake as a client.

```dart
Future<void> handshakeClient({
  HandshakeSettings? settings,
  Session? session,
  String serverName = '',           // SNI hostname
  List<String> alpn = const [],     // ALPN protocols
  Keypair? certParams,              // Client certificate (optional)
})
```

**Parameters:**
- `settings`: Configure min/max TLS version, cipher suites, signature algorithms
- `session`: Existing session for resumption
- `serverName`: Server Name Indication (SNI) for virtual hosting
- `alpn`: Application-Layer Protocol Negotiation list (e.g., `['h2', 'http/1.1']`)
- `certParams`: Client certificate and private key for mutual TLS

##### `handshakeServer()`

Accepts a TLS handshake as a server.

```dart
Future<void> handshakeServer({
  HandshakeSettings? settings,
  X509CertChain? certChain,         // Server certificate chain
  dynamic privateKey,                // Server private key
  bool reqCert = false,              // Request client certificate
  List<String>? alpn,                // Supported ALPN protocols
})
```

**Parameters:**
- `certChain`: X.509 certificate chain (leaf + intermediates)
- `privateKey`: RSA, ECDSA, Ed25519, or Ed448 private key
- `reqCert`: Enable client certificate authentication
- `alpn`: List of supported application protocols

##### `read()` / `write()`

Send and receive application data after handshake completion.

```dart
Future<void> write(Uint8List data)
Future<Uint8List> read({int? max})
```

##### `close()`

Gracefully closes the TLS connection with a `close_notify` alert.

```dart
Future<void> close()
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `session` | `Session` | Current session state (cipher, keys, tickets) |
| `handshakeEstablished` | `bool` | `true` after successful handshake |
| `version` | `TlsProtocolVersion` | Negotiated TLS version |
| `handshakeSettings` | `HandshakeSettings` | Active handshake configuration |
| `tls13Tickets` | `List<TlsNewSessionTicket>` | TLS 1.3 session tickets for resumption |

#### Example: TLS 1.3 with ALPN

```dart
// HandshakeSettings uses final fields - configure via constructor
final settings = HandshakeSettings(
  minVersion: (3, 4),  // TLS 1.3 minimum
  maxVersion: (3, 4),  // TLS 1.3 maximum
  keyShares: ['x25519', 'secp256r1'],  // Key shares to send
);

final tls = TlsConnection(socket);
await tls.handshakeClient(
  settings: settings,
  serverName: 'api.example.com',
  alpn: ['h2', 'http/1.1'],
);

print('Negotiated: ${tls.session.alpnProtocol}'); // 'h2' or 'http/1.1'
```

#### HandshakeSettings Constructor Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `minVersion` | `(int, int)` | `(3, 1)` | Minimum TLS version (3,1)=TLS 1.0, (3,3)=TLS 1.2, (3,4)=TLS 1.3 |
| `maxVersion` | `(int, int)` | `(3, 3)` | Maximum TLS version |
| `cipherNames` | `List<String>?` | AES-GCM, ChaCha20 | Allowed cipher algorithms |
| `eccCurves` | `List<String>?` | x25519, secp256r1, etc. | Elliptic curves for ECDHE |
| `keyShares` | `List<String>` | `['secp256r1', 'x25519']` | Key shares for TLS 1.3 ClientHello |
| `alpnProtos` | `List<String>` | `[]` | ALPN protocols to advertise |
| `useExtendedMasterSecret` | `bool` | `true` | Enable Extended Master Secret (RFC 7627) |
| `useEncryptThenMAC` | `bool` | `true` | Enable Encrypt-then-MAC (RFC 7366) |
| `pskConfigs` | `List<PskConfig>?` | `[]` | Pre-shared keys for TLS 1.3 |
| `minKeySize` | `int` | `1023` | Minimum asymmetric key size in bits |
| `maxKeySize` | `int` | `8193` | Maximum asymmetric key size in bits |

---

### `lib/src/net/secure_socket_openssl_async.dart` - SecureSocketOpenSSLAsync

A high-performance TLS socket implementation using OpenSSL via FFI (Foreign Function Interface).

#### Overview

`SecureSocketOpenSSLAsync` provides:

- Native OpenSSL-backed TLS with automatic handshake
- Client and server mode support
- Memory BIO-based transport (no direct file descriptors)
- Callback-based ciphertext I/O for custom transports
- Full async/await API

#### Factory Methods

##### Client Mode

```dart
// Connect to a remote host
static Future<SecureSocketOpenSSLAsync> connect(
  String host,
  int port, {
  Duration? timeout,
  bool eagerHandshake = true,
  Logger? logger,
})

// Wrap an existing socket
factory SecureSocketOpenSSLAsync.clientFromSocket(
  Socket socket, {
  bool eagerHandshake = true,
  Logger? logger,
})

// Use custom ciphertext callbacks
factory SecureSocketOpenSSLAsync.clientWithCallbacks({
  required CiphertextWriterAsync writer,
  required CiphertextReaderAsync reader,
  bool eagerHandshake = true,
  Logger? logger,
})
```

##### Server Mode

```dart
factory SecureSocketOpenSSLAsync.serverFromSocket(
  Socket socket, {
  required String certFile,    // Path to PEM certificate
  required String keyFile,     // Path to PEM private key
  bool eagerHandshake = true,
  Logger? logger,
})
```

#### Key Methods

##### `ensureHandshakeCompleted()`

Waits for the TLS handshake to complete. Called automatically when `eagerHandshake = true`.

```dart
Future<void> ensureHandshakeCompleted()
```

##### `send()` / `recv()`

Send and receive plaintext data through the encrypted channel.

```dart
Future<int> send(Uint8List data)      // Returns bytes written
Future<Uint8List> recv(int bufferSize) // Returns decrypted data
```

##### `shutdown()` / `close()`

Gracefully terminate the TLS session and release resources.

```dart
Future<void> shutdown()  // Send SSL shutdown
Future<void> close()     // Shutdown + close socket + free OpenSSL objects
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `socket` | `Socket?` | Underlying Dart socket (if applicable) |
| `isHandshakeComplete` | `bool` | `true` after successful TLS handshake |

#### Example: Client Connection

```dart
import 'dart:typed_data';
import 'package:tlslite/tlslite.dart';

void main() async {
  final secure = await SecureSocketOpenSSLAsync.connect('example.com', 443);
  
  await secure.send(Uint8List.fromList('GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'.codeUnits));
  
  final response = await secure.recv(4096);
  print(String.fromCharCodes(response));
  
  await secure.close();
}
```

#### Example: Server with Certificates

```dart
import 'dart:io';
import 'dart:typed_data';
import 'package:tlslite/tlslite.dart';

void main() async {
  final server = await ServerSocket.bind('0.0.0.0', 8443);
  
  await for (final client in server) {
    final secure = SecureSocketOpenSSLAsync.serverFromSocket(
      client,
      certFile: '/path/to/server.crt',
      keyFile: '/path/to/server.key',
    );
    
    await secure.ensureHandshakeCompleted();
    final request = await secure.recv(4096);
    await secure.send(Uint8List.fromList('HTTP/1.1 200 OK\r\n\r\nHello!'.codeUnits));
    await secure.close();
  }
}
```

#### Example: Custom Transport (Callbacks)

For scenarios where TLS runs over a non-socket transport (e.g., encapsulated protocols):

```dart
final secure = SecureSocketOpenSSLAsync.clientWithCallbacks(
  writer: (ciphertext) async {
    // Send ciphertext over your custom transport
    await myTransport.write(ciphertext);
  },
  reader: (size) async {
    // Read ciphertext from your custom transport
    return await myTransport.read(size);
  },
);

await secure.ensureHandshakeCompleted();
await secure.send(myPlaintext);
```




