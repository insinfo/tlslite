# tlslite

#### start implementation of the TLS protocol in pure dart

## BIO-backed TLS transports

`SecureSocketOpenSSL` now keeps the OpenSSL engine connected through memory
BIOs instead of binding directly to the OS socket descriptor. Every encrypted
byte that OpenSSL produces flows through the injected `RawTransport`, which
makes it possible to implement framed protocols such as SQL Server TDS.

To tunnel TLS records inside a custom framing layer:

1. Implement `RawTransport` (or wrap an existing one) so that `send()/sendall`
	 write framed TLS segments and `recv()` strips the frame before handing the
	 ciphertext to TLS.
2. Pass that transport to `SecureSocketOpenSSL.fromTransport(...)` and run the
	 handshake as usual. Because the TLS engine no longer touches OS handles, the
	 transport has full control over how bytes hit the wire.
3. When legacy modes require dropping back to clear text, swap the transport as
	 before (e.g. `SecureSocketOpenSSL.revert_to_clear`).

## Async integration helpers

For runtimes that expose asynchronous channels (such as the `mssql_dart`
driver), the new `SecureSocketOpenSSLAsync` class offers the same BIO-backed
engine but exposes two callbacks:

```dart
final tls = SecureSocketOpenSSLAsync.client(
	writer: (ciphertext) async {
		// Encapsule ciphertext dentro de um pacote TDS PRELOGIN e escreva no socket.
		await framedSocket.sendPrelogin(ciphertext);
	},
	reader: (preferred) async {
		// Leia um pacote TDS, extraia o payload TLS e retorne-o.
		return framedSocket.readTlsPayload(preferred);
	},
);

await tls.ensureHandshakeCompleted();
await tls.send(loginBlob);
final response = await tls.recv(4096);
```

The callbacks decide how TLS bytes map to the underlying protocol, so the same
engine can be reused for TDS 7.x, STARTTLS-style upgrades, or any transport that
requires hand-crafted framing.

