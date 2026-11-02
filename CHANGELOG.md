## 1.0.1

- Translate the remaining Portuguese documentation, comments and error
  messages to English (mostly the experimental assembly code)
- No functional changes

## 1.0.0

First public release: a pure-Dart port of
[tlslite-ng](https://github.com/tlsfuzzer/tlslite-ng).

### TLS
- TLS 1.0, 1.1, 1.2 and 1.3 client and server (`TlsConnection`), with SSLv3
  record compatibility.
- Cipher suites: AES-GCM, AES-CCM, ChaCha20-Poly1305, AES-CBC/3DES with
  HMAC (incl. encrypt-then-MAC), RC4 (legacy).
- Key exchange: RSA, (EC)DHE with FFDHE groups, P-256/P-384/P-521, X25519,
  X448 and hybrid post-quantum groups (X25519MLKEM768, SecP256r1MLKEM768,
  SecP384r1MLKEM1024).
- Signatures: RSA PKCS#1 v1.5, RSA-PSS, ECDSA, EdDSA (Ed25519, Ed448), DSA.
- Session resumption (session IDs, tickets, TLS 1.3 PSK), HelloRetryRequest,
  KeyUpdate, ALPN, SNI, OCSP stapling, heartbeat, record size limit,
  certificate compression (zlib, Brotli, Zstandard).
- `TlsConnection.custom(BinaryInput, BinaryOutput)` to run TLS over any
  transport (e.g. TLS encapsulated in another protocol such as TDS/PRELOGIN).
- Helpers for SMTP, POP3, IMAP and HTTP over TLS.

### X.509 certificate validation (new)
- `X509Validator`: certificate path building and validation against trust
  anchors (signatures, validity period, basicConstraints / pathLen,
  keyUsage, extendedKeyUsage, DNS/IP nameConstraints, unknown critical
  extensions) plus RFC 6125 host name verification (subjectAltName DNS with
  single-label wildcards, iPAddress, CN fallback only without SANs).
- `X509Validator.checker(hostname: ...)` plugs into
  `TlsConnection.handshakeClient(checker: ...)`: the chain is verified as
  soon as the server Certificate message arrives and the handshake aborts
  with a fatal alert and `TLSCertificateVerificationError` on failure.
- `loadPemCertificates`, `loadPemCertificatesFromFile` and
  `loadSystemTrustAnchors` (honours `SSL_CERT_FILE`, then the usual Linux /
  macOS CA bundle locations).
- `X509.verify` now really supports RSA PKCS#1 v1.5 and RSA-PSS
  (SHA-1/224/256/384/512, PSS salt length from the certificate), ECDSA and
  EdDSA; certificate extensions (subjectAltName, basicConstraints, keyUsage,
  extendedKeyUsage) are now parsed correctly, and `dnsNames`,
  `ipAddresses`, `subjectCommonNames`, `criticalExtensions` and name
  constraints are exposed.
- Without a checker, `handshakeClient` only checks the validity period of
  the server's end-entity certificate (extra certificates in the chain are
  no longer rejected for being expired).

### OpenSSL (optional, FFI)
- `SecureSocketOpenSSLAsync` / `SecureSocketOpenSSLSync` and DTLS bindings
  using the system OpenSSL 3 / 1.1 libraries (`package:tlslite/openssl.dart`).
- The `logger` parameter of `SecureSocketOpenSSLAsync` is now a plain
  `void Function(String message)?` callback (no `package:logging`
  dependency).

### Dependencies
- Runtime dependencies reduced to `crypto`, `ffi`, `fixnum` and
  `pointycastle`.
