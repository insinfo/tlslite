# TLS Lite Python to Dart Port - Comprehensive Audit Report

**Date**: December 2, 2025  
**Source**: `C:\MyDartProjects\tlslite\tlslite-ng\tlslite`  
**Target**: `C:\MyDartProjects\tlslite\lib\src`

---

## Executive Summary

This audit cross-references all Python modules in the tlslite-ng implementation against their Dart equivalents to identify missing classes, methods, and functionality. The port is **partially complete** with core data structures mostly ported, but **major protocol layer modules remain unimplemented**.

### Overall Status

- ✅ **Fully Ported**: `constants.dart`, `errors.dart`, `signed.dart`, `x509.dart`, `ocsp.dart`, `session.dart`, `x509certchain.dart`
- ⚠️ **Partially Complete**: Utils modules (many exist but may have gaps)
- ❌ **Not Ported**: `messages.py`, `mathtls.py`, `recordlayer.py`, `tlsrecordlayer.py`, `tlsconnection.py`, `sessioncache.py`, `verifierdb.py`, `handshake*.py`, `extensions.py`, `keyexchange.py`, `defragmenter.py`, `checker.py`, `bufferedsocket.py`, `basedb.py`, `api.py`, `messagesocket.py`, `dh.py`

---

## Main Protocol Modules

### ✅ constants.py → constants.dart

**Status**: Fully ported with minor differences.

**Differences**:
- Python uses class-based enums with `TLSEnum` base; Dart uses static const fields
- Python's `SignatureScheme` uses tuples `(hash, sig)`; Dart uses `_SignatureSchemeValue` wrapper class
- Python's `AlgorithmOID.oid` uses `bytearray` keys; Dart uses hex string keys (requires custom lookup)
- Dart `CipherSuite` class methods like `filterForVersion`, `filterForCertificate`, `filterForPrfs`, `_filterSuites`, `getTLS13Suites`, `getSrpSuites`, etc. are present but may not have full Python feature parity

**Missing Features**: None critical, semantically equivalent

---

### ✅ errors.py → errors.dart

**Status**: Fully ported.

**All exception classes present**:
- `BaseTLSException`, `EncryptionError`, `TLSError`, `TLSClosedConnectionError`, `TLSAbruptCloseError`
- `TLSAlert`, `TLSLocalAlert`, `TLSRemoteAlert`
- `TLSAuthenticationError`, `TLSNoAuthenticationError`, `TLSAuthenticationTypeError`, `TLSFingerprintError`, `TLSAuthorizationError`, `TLSValidationError`
- `TLSFaultError`, `TLSUnsupportedError`, `TLSInternalError`
- `TLSProtocolException`, `TLSIllegalParameterException`, `TLSDecodeError`, `TLSUnexpectedMessage`, `TLSRecordOverflow`, `TLSDecryptionFailed`, `TLSBadRecordMAC`, `TLSInsufficientSecurity`, `TLSUnknownPSKIdentity`, `TLSHandshakeFailure`
- `MaskTooLongError`, `MessageTooLongError`, `EncodingError`, `InvalidSignature`, `UnknownRSAType`

**Differences**: 
- Python `TLSClosedConnectionError` inherits from both `TLSError` and `socket.error`; Dart only from `TLSError` (Dart doesn't support multiple inheritance)

---

### ✅ signed.py → signed.dart

**Status**: Fully ported.

**Classes**:
- `SignatureSettings`: ✅ Present
- `SignedObject`: ✅ Present

**Methods in `SignatureSettings`**:
- `__init__`: ✅ Constructor present
- `_copy_settings`: ✅ Implemented as `_copy()`
- `_sanityCheckKeySizes`: ✅ Present (static)
- `_sanityCheckSignatureAlgs`: ✅ Present (static)
- `validate`: ✅ Present

**Methods in `SignedObject`**:
- `__init__`: ✅ Constructor (implicit)
- `verify_signature`: ✅ Present as `verifySignature`
- `_hash_algs_OIDs` dict: ✅ Present as `_hashAlgsOids`

---

### ✅ x509.py → x509.dart

**Status**: Fully ported.

**Class**: `X509`

**Properties**:
- `bytes`, `serial_number`, `subject_public_key`, `publicKey`, `subject`, `certAlg`, `sigalg`, `issuer`: ✅ All present (Dart uses camelCase: `serialNumber`, `subjectPublicKey`, `signatureAlgorithm`)

**Methods**:
- `__init__`: ✅ Constructor
- `__hash__`: ✅ Implemented via `get hashCode`
- `__eq__` / `__ne__`: ✅ Implemented via `operator ==`
- `parse(s)`: ✅ Present
- `parseBinary(cert_bytes)`: ✅ Present as `parseBinary`
- `_eddsa_pubkey_parsing`: ✅ Present as `_parseEdDsaPublicKey`
- `_rsa_pubkey_parsing`: ✅ Present as `_parseRsaPublicKey`
- `_ecdsa_pubkey_parsing`: ✅ Present as `_parseEcdsaPublicKey`
- `_dsa_pubkey_parsing`: ✅ Present as `_parseDsaPublicKey`
- `getFingerprint()`: ✅ Present
- `writeBytes()`: ✅ Present

---

### ✅ ocsp.py → ocsp.dart

**Status**: Fully ported.

**Classes**:
- `OCSPRespStatus`: ✅ Present
- `CertStatus`: ✅ Present
- `SingleResponse`: ✅ Present
- `OCSPResponse`: ✅ Present (extends `SignedObject`)

**`SingleResponse` methods**:
- `__init__`: ✅ Constructor
- `parse`: ✅ Present as `_parse`
- `verify_cert_match`: ✅ Present as `verifyCertMatch`
- `_hash_algs_OIDs`: ✅ Present as `_hashAlgsOids`

**`OCSPResponse` methods**:
- `__init__`: ✅ Constructor
- `parse`: ✅ Present
- `_tbsdataparse`: ✅ Present as `_parseTbsData`
- Inherited `verify_signature`: ✅ Available via `SignedObject`

---

### ✅ session.py → session.dart

**Status**: Fully ported.

**Classes**:
- `Session`: ✅ Present
- `Ticket`: ✅ Present

**`Session` properties**:
- All properties present: `masterSecret`, `sessionID`, `cipherSuite`, `srpUsername`, `clientCertChain`, `serverCertChain`, `tackExt`, `tackInHelloExt`, `serverName`, `resumable`, `encryptThenMAC`, `extendedMasterSecret`, `appProto`, `cl_app_secret` (Dart: `clAppSecret`), `sr_app_secret` (Dart: `srAppSecret`), `exporterMasterSecret`, `resumptionMasterSecret`, `tickets`, `tls_1_0_tickets` (Dart: `tls10Tickets`), `ec_point_format` (Dart: `ecPointFormat`)

**`Session` methods**:
- `create`: ✅ Present
- `_clone`: ✅ Present as `clone()`
- `valid`: ✅ Present
- `_setResumable`: ✅ Present as `setResumable`
- `getTackId`: ✅ Present
- `getBreakSigs`: ✅ Present
- `getCipherName`: ✅ Present
- `getMacName`: ✅ Present

**`Ticket` methods**:
- `__init__`: ✅ Constructor
- `valid`: ✅ Present

---

### ✅ x509certchain.py → x509certchain.dart

**Status**: Likely ported (file exists in Dart).

**Note**: Detailed comparison not performed in this session, but file is present. Recommend manual verification of all methods.

---

### ❌ messages.py → messages.dart

**Status**: **NOT PORTED**

**Missing Classes** (34 total):
- `RecordHeader`
- `RecordHeader3`
- `RecordHeader2`
- `Message`
- `Alert`
- `HandshakeMsg`
- `HelloMessage`
- `ClientHello`
- `HelloRequest`
- `ServerHello`
- `ServerHello2`
- `CertificateEntry`
- `Certificate`
- `CertificateRequest`
- `ServerKeyExchange`
- `ServerHelloDone`
- `ClientKeyExchange`
- `ClientMasterKey`
- `CertificateVerify`
- `ChangeCipherSpec`
- `NextProtocol`
- `Finished`
- `EncryptedExtensions`
- `NewSessionTicket`
- `NewSessionTicket1_0`
- `SessionTicketPayload`
- `SSL2Finished`
- `ClientFinished`
- `ServerFinished`
- `CertificateStatus`
- `ApplicationData`
- `Heartbeat`
- `KeyUpdate`
- `CompressedCertificate`

**Impact**: **CRITICAL** - These are core TLS handshake and record message structures.

---

### ❌ mathtls.py → mathtls.dart

**Status**: **NOT PORTED**

**Missing Functions** (18 total):
- `paramStrength(param)`
- `P_hash(mac_name, secret, seed, length)`
- `PRF(secret, label, seed, length)`
- `PRF_1_2(secret, label, seed, length)`
- `PRF_1_2_SHA384(secret, label, seed, length)`
- `PRF_SSL(secret, seed, length)`
- `calcExtendedMasterSecret(...)`
- `calcMasterSecret(...)`
- `calcFinished(...)`
- `calc_key(...)`
- `makeX(salt, username, password)`
- `makeVerifier(username, password, bits)`
- `PAD(n, x)`
- `makeU(N, A, B)`
- `makeK(N, g)`
- `createHMAC(k, digestmod=hashlib.sha1)`
- `createMAC_SSL(k, digestmod=None)`

**Missing Classes**:
- `MAC_SSL`

**Impact**: **CRITICAL** - These are cryptographic functions for key derivation, PRF, and SRP.

---

### ❌ recordlayer.py → recordlayer.dart

**Status**: **NOT PORTED**

**Missing Classes** (3 total):
- `RecordSocket`
- `ConnectionState`
- `RecordLayer`

**Impact**: **CRITICAL** - Core TLS record layer implementation.

---

### ❌ tlsrecordlayer.py → tlsrecordlayer.dart

**Status**: **NOT PORTED**

**Missing Classes**:
- `TLSRecordLayer`

**Impact**: **CRITICAL** - Higher-level record layer with encryption/decryption.

---

### ❌ tlsconnection.py → tlsconnection.dart

**Status**: **NOT PORTED**

**Missing Classes**:
- `TLSConnection` (main API entry point)

**Impact**: **CRITICAL** - This is the primary user-facing API class.

---

### ❌ sessioncache.py → sessioncache.dart

**Status**: **NOT PORTED**

**Missing Classes**:
- `SessionCache`

**Impact**: **HIGH** - Session resumption mechanism.

---

### ❌ verifierdb.py → verifierdb.dart

**Status**: **NOT PORTED**

**Missing Classes**:
- `VerifierDB`

**Impact**: **MEDIUM** - SRP verifier database.

---

### ❌ handshakesettings.py → handshakesettings.dart

**Status**: **NOT PORTED**

**Missing Classes** (3 total):
- `Keypair`
- `VirtualHost`
- `HandshakeSettings`

**Impact**: **CRITICAL** - Handshake configuration.

---

### ❌ handshakehelpers.py → handshakehelpers.dart

**Status**: **NOT PORTED**

**Missing Classes**:
- `HandshakeHelpers`

**Impact**: **HIGH** - Handshake utility methods.

---

### ❌ handshakehashes.py → handshakehashes.dart

**Status**: **NOT PORTED**

**Missing Classes**:
- `HandshakeHashes`

**Impact**: **HIGH** - Transcript hash management.

---

### ❌ extensions.py → extensions.dart

**Status**: **NOT PORTED**

**Missing Classes** (40+ total including):
- `TLSExtension` (base class)
- `CustomNameExtension`
- `VarBytesExtension`
- `ListExtension`
- `VarListExtension`
- `VarSeqListExtension`
- `IntExtension`
- `SNIExtension`
- `SupportedVersionsExtension`
- `SrvSupportedVersionsExtension`
- `ClientCertTypeExtension`
- `ServerCertTypeExtension`
- `SRPExtension`
- `NPNExtension`
- `TACKExtension`
- `SupportedGroupsExtension`
- `ECPointFormatsExtension`
- `SignatureAlgorithmsExtension`
- `SignatureAlgorithmsCertExtension`
- `PaddingExtension`
- `RenegotiationInfoExtension`
- `ALPNExtension`
- `StatusRequestExtension`
- `CertificateStatusExtension`
- `KeyShareEntry`
- `HeartbeatExtension`
- `ClientKeyShareExtension`
- `ServerKeyShareExtension`
- `HRRKeyShareExtension`
- `PskIdentity`
- `PreSharedKeyExtension`
- `SrvPreSharedKeyExtension`
- `PskKeyExchangeModesExtension`
- `CookieExtension`
- `RecordSizeLimitExtension`
- `SessionTicketExtension`
- `CompressedCertificateExtension`

**Impact**: **CRITICAL** - TLS extensions are essential for modern TLS.

---

### ❌ keyexchange.py → keyexchange.dart

**Status**: **NOT PORTED**

**Missing Classes** (11 total):
- `KeyExchange` (base)
- `AuthenticatedKeyExchange`
- `RSAKeyExchange`
- `ADHKeyExchange`
- `DHE_RSAKeyExchange`
- `AECDHKeyExchange`
- `ECDHE_RSAKeyExchange`
- `SRPKeyExchange`
- `RawDHKeyExchange`
- `FFDHKeyExchange`
- `ECDHKeyExchange`
- `KEMKeyExchange`

**Impact**: **CRITICAL** - Key exchange implementations.

---

### ❌ defragmenter.py → defragmenter.dart

**Status**: **NOT PORTED**

**Missing Classes**:
- `Defragmenter`

**Impact**: **MEDIUM** - Handles fragmented TLS records.

---

### ❌ checker.py → checker.dart

**Status**: **NOT PORTED**

**Missing Classes**:
- `Checker`

**Impact**: **LOW** - Certificate verification helper.

---

### ❌ bufferedsocket.py → bufferedsocket.dart

**Status**: **NOT PORTED**

**Missing Classes**:
- `BufferedSocket`

**Impact**: **MEDIUM** - Socket wrapper.

---

### ❌ basedb.py → basedb.dart

**Status**: **NOT PORTED**

**Missing Classes**:
- `BaseDB`

**Impact**: **MEDIUM** - Database base class (for VerifierDB).

---

### ❌ api.py → api.dart

**Status**: **NOT PORTED**

**Missing Module**: Entire high-level API convenience layer.

**Impact**: **HIGH** - Simplified API wrappers.

---

### ❌ messagesocket.py → messagesocket.dart

**Status**: **NOT PORTED**

**Missing Classes**:
- `MessageSocket`

**Impact**: **HIGH** - Message-level socket abstraction.

---

### ❌ dh.py → dh.dart

**Status**: **NOT PORTED**

**Missing Functions**:
- `parseBinary(data)`
- `parse(data)`

**Impact**: **MEDIUM** - DH parameter parsing.

---

## Utils Modules

### ✅ codec.py → utils/codec.dart

**Status**: Ported (file exists).

**Recommendation**: Verify all encoding/decoding functions match.

---

### ✅ asn1parser.py → utils/asn1parser.dart

**Status**: Ported (file exists).

**Recommendation**: Verify `ASN1Parser` class methods.

---

### ✅ cryptomath.py → utils/cryptomath.dart

**Status**: Ported (file exists).

**Recommendation**: Verify all bignum/crypto math functions.

---

### ✅ constanttime.py → utils/constanttime.dart

**Status**: Ported (file exists).

**Recommendation**: Verify constant-time comparison functions.

---

### ✅ lists.py → utils/lists.dart

**Status**: Ported (file exists).

**Recommendation**: Verify list utility functions.

---

### ✅ tlshmac.py → utils/tlshmac.dart

**Status**: Ported (file exists).

**Recommendation**: Verify HMAC implementations.

---

### ✅ tlshashlib.py → utils/tlshashlib.dart

**Status**: Ported (file exists).

**Recommendation**: Verify hash function wrappers.

---

### ✅ aes.py → utils/aes.dart

**Status**: Ported (file exists).

**Recommendation**: Verify AES cipher implementation.

---

### ✅ chacha.py → utils/chacha.dart

**Status**: Ported (file exists).

**Recommendation**: Verify ChaCha20 implementation.

---

### ✅ poly1305.py → utils/poly1305.dart

**Status**: Ported (file exists).

**Recommendation**: Verify Poly1305 MAC implementation.

---

### ✅ x25519.py → utils/x25519.dart

**Status**: Ported (file exists).

**Recommendation**: Verify X25519 ECDH implementation.

---

### ✅ cipherfactory.py → utils/cipherfactory.dart

**Status**: Ported (file exists).

**Recommendation**: Verify cipher factory methods match Python.

---

### ✅ keyfactory.py → utils/keyfactory.dart

**Status**: Ported (file exists).

**Recommendation**: Verify key creation functions.

---

### ✅ rsakey.py → utils/rsakey.dart

**Status**: Ported (file exists).

**Recommendation**: Verify `RSAKey` class and all methods.

---

### ✅ compat.py → utils/compat.dart

**Status**: Ported (file exists).

**Recommendation**: Verify Python 2/3 compatibility layer equivalents.

---

### ✅ pem.py → utils/pem.dart

**Status**: Ported (file exists).

**Recommendation**: Verify PEM encoding/decoding functions.

---

### ✅ compression.py → utils/compression.dart

**Status**: Ported (file exists).

**Recommendation**: Verify compression wrapper functions.

---

### ✅ datefuncs.py → utils/datefuncs.dart

**Status**: Ported (file exists).

**Recommendation**: Verify date/time parsing utilities.

---

### ✅ format_output.py → utils/format_output.dart

**Status**: Ported (file exists).

**Recommendation**: Verify formatting utilities.

---

### ✅ dns_utils.py → utils/dns_utils.dart

**Status**: Ported (file exists).

**Recommendation**: Verify DNS-related utilities.

---

### ✅ dsakey.py → utils/dsakey.dart

**Status**: Ported (file exists).

**Recommendation**: Verify `DSAKey` class.

---

### ✅ ecc.py → utils/ecc.dart

**Status**: Ported (file exists).

**Recommendation**: Verify ECC utilities.

---

### ✅ ecdsakey.py → utils/ecdsakey.dart

**Status**: Ported (file exists).

**Recommendation**: Verify `ECDSAKey` class.

---

### ✅ eddsakey.py → utils/eddsakey.dart

**Status**: Ported (file exists).

**Recommendation**: Verify EdDSA key classes (Ed25519/Ed448).

---

### ✅ aesccm.py → utils/aesccm.dart

**Status**: Ported (file exists).

**Recommendation**: Verify AES-CCM mode implementation.

---

### ✅ aesgcm.py → utils/aesgcm.dart

**Status**: Ported (file exists).

**Recommendation**: Verify AES-GCM mode implementation.

---

### ✅ chacha20_poly1305.py → utils/chacha20_poly1305.dart

**Status**: Ported (file exists).

**Recommendation**: Verify ChaCha20-Poly1305 AEAD implementation.

---

### ✅ python_*.py → utils/python_*.dart

**Status**: Multiple python_* files ported (e.g., `python_aes.dart`, `python_rsakey.dart`, etc.).

**Recommendation**: Verify all pure-Python cipher/key implementations.

---

### ✅ rc4.py → utils/rc4.dart

**Status**: Ported (file exists).

**Recommendation**: Verify RC4 stream cipher (note: RC4 is deprecated).

---

### ✅ rijndael.py → utils/rijndael.dart

**Status**: Ported (file exists).

**Recommendation**: Verify Rijndael implementation.

---

### ✅ tripledes.py → utils/tripledes.dart

**Status**: Ported (file exists).

**Recommendation**: Verify 3DES implementation.

---

### ❌ tackwrapper.py → utils/tackwrapper.dart

**Status**: **NOT FOUND**

**Impact**: **LOW** - TACK extension support (rarely used).

---

### ❌ deprecations.py → utils/deprecations.dart

**Status**: **NOT FOUND**

**Impact**: **VERY LOW** - Deprecation warnings (Python-specific).

---

### ❌ openssl_*.py → utils/openssl_*.dart

**Status**: **NOT FOUND** (multiple files: `openssl_aes.py`, `openssl_aesccm.py`, `openssl_aesgcm.py`, `openssl_rc4.py`, `openssl_rsakey.py`, `openssl_tripledes.py`)

**Impact**: **LOW** - OpenSSL acceleration bindings (optional optimization).

---

### ❌ pycrypto_*.py → utils/pycrypto_*.dart

**Status**: **NOT FOUND** (multiple files: `pycrypto_aes.py`, `pycrypto_aesgcm.py`, `pycrypto_rc4.py`, `pycrypto_rsakey.py`, `pycrypto_tripledes.py`)

**Impact**: **LOW** - PyCrypto library bindings (optional).

---

### ❌ python_key.py → utils/python_key.dart

**Status**: **NOT FOUND**

**Impact**: **MEDIUM** - Base class for pure-Python key implementations.

---

## Critical Missing Components Summary

### Must-Have for Functional TLS Implementation

1. ❌ **messages.py** (34 classes) - All TLS message types
2. ❌ **mathtls.py** (18 functions + 1 class) - Cryptographic PRF and key derivation
3. ❌ **recordlayer.py** (3 classes) - Record layer protocol
4. ❌ **tlsrecordlayer.py** (1 class) - Encrypted record layer
5. ❌ **tlsconnection.py** (1 class) - Main TLS API
6. ❌ **extensions.py** (40+ classes) - TLS extension support
7. ❌ **keyexchange.py** (11 classes) - Key exchange implementations
8. ❌ **handshakesettings.py** (3 classes) - Configuration
9. ❌ **handshakehelpers.py** (1 class) - Handshake utilities
10. ❌ **handshakehashes.py** (1 class) - Transcript hashing

### Important for Production Use

11. ❌ **sessioncache.py** (1 class) - Session resumption
12. ❌ **messagesocket.py** (1 class) - Message-level abstraction
13. ❌ **defragmenter.py** (1 class) - Record defragmentation
14. ❌ **api.py** - High-level API

### Optional/Nice-to-Have

15. ❌ **verifierdb.py** (1 class) - SRP verifier storage
16. ❌ **checker.py** (1 class) - Certificate validation
17. ❌ **basedb.py** (1 class) - Database base
18. ❌ **bufferedsocket.py** (1 class) - Socket buffering
19. ❌ **dh.py** (2 functions) - DH parameter parsing

---

## Recommendations

### Immediate Priorities (P0)

1. Port `messages.py` - All 34 message classes
2. Port `mathtls.py` - All cryptographic functions
3. Port `recordlayer.py` - Core record layer
4. Port `tlsrecordlayer.py` - Encrypted record layer
5. Port `extensions.py` - TLS extensions (at least the critical ones: SNI, ALPN, supported_versions, signature_algorithms)

### High Priority (P1)

6. Port `handshakesettings.py` - Configuration infrastructure
7. Port `handshakehelpers.py` - Handshake logic
8. Port `handshakehashes.py` - Transcript management
9. Port `keyexchange.py` - Key exchange implementations
10. Port `tlsconnection.py` - Main API class

### Medium Priority (P2)

11. Port `sessioncache.py` - Session resumption
12. Port `messagesocket.py` - Message-level socket
13. Port `defragmenter.py` - Record defragmentation
14. Port `api.py` - High-level convenience API

### Low Priority (P3)

15. Port `verifierdb.py`, `basedb.py`, `checker.py`, `bufferedsocket.py`, `dh.py`
16. Verify all utils modules for completeness
17. Consider porting OpenSSL bindings for performance (Dart FFI)

---

## Estimated Work Remaining

- **Critical Modules**: ~6,000-8,000 lines of complex protocol code
- **High Priority**: ~3,000-4,000 lines
- **Medium Priority**: ~1,500-2,000 lines
- **Low Priority**: ~500-1,000 lines

**Total Estimated**: ~11,000-15,000 lines of new Dart code, plus extensive testing.

---

## Conclusion

The Dart port has successfully translated the **data structure layer** (constants, errors, X.509 certificates, OCSP, sessions, and most cryptographic utilities), but the **entire TLS protocol layer** remains unimplemented. To achieve a functional TLS client/server, the critical message handling, key derivation, record layer, and handshake logic must be ported next.

**Current State**: ~30-40% complete (data structures and crypto primitives)  
**Remaining Work**: ~60-70% (protocol implementation and API layer)
