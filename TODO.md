# TODO - TLSLite Dart Port

**Status**: 45% completo | **Testes**: 446+ passando

## PRIORIDADES

### 🔴 CRÍTICO (para TLS funcionar)
1. **recordlayer.py** → recordlayer.dart (1.376 linhas) - ✅ PORT COMPLETO
2. **keyexchange.py** → key_exchange.dart (1.100 linhas) - ✅ ~95% completo (falta ML-KEM/PQC)
3. **tlsconnection.py** → tls_connection.dart (4.535 linhas) - 🔄 ~60% completo

### ✅ IMPORTANTE  
4. **handshakesettings.py** → handshake_settings.dart (716 linhas) - ✅ COMPLETO
5. **tlsrecordlayer.py** → tls_record_layer.dart (1.345 linhas) - ✅ COMPLETO
6. **handshakehelpers.py** → handshake_helpers.dart (789 linhas) - ✅ COMPLETO

### 🔵 BAIXA (pode esperar)
7. verifierdb.py, dh.py, checker.py
8. api.py, basedb.py, messagesocket.py

---

## COMPLETO ✅

**Utils**: codec, asn1parser, pem, x25519, aes, chacha20, poly1305, rsa, ecdsa, eddsa, dsa, hmac, compression, constanttime, datefuncs, lists, dns_utils, format_output, keyfactory, tlshashlib, tlshmac, tripledes, rc4

**Core**: constants, errors, x509, x509certchain, ocsp, signed, session, mathtls, ffdhe_groups, defragmenter, handshake_hashes, sessioncache

**Crypto**: AES (CBC/CTR/GCM/CCM/CCM8), ChaCha20-Poly1305, TripleDES, RC4

**Parcial**: tls_messages (80%), tls_extensions (85%), buffered_socket

---

## COMANDOS

```bash
dart test                    # rodar testes
dart analyze                 # análise estática
```

## Notas de planejamento

### PEM com senha
- ✅ PBES2 (PBKDF2/HMAC-SHA256 + AES-256-CBC) implementado em `pkcs8.dart`, com suporte integrado aos writers de RSA/ECDSA/Ed25519 e placeholders de Ed448.
- ✅ `keyfactory` agora importa blocos `ENCRYPTED PRIVATE KEY` usando callback de senha.
- ✅ Novos testes cobrem serialização/parsing protegida para todas as chaves suportadas.
- 🔜 Gerar vetores cruzados (OpenSSL) e adicionar suporte a prompts amigáveis (CLI/UI) para senhas.

### EdDSA / Ed448
- ✅ Placeholder de chave privada Ed448 com PKCS#8 + PEM (incluindo senha) e parsing no `keyfactory`.
- 🔜 Portar a matemática completa de Ed448 (ed448goldilocks) para substituir o placeholder e liberar assinatura/verificação reais.
- 🔜 Conectar suporte Ed448 aos pontos que ainda lançam `UnsupportedError` (cert parsing, tlsrecordlayer, key generation).

### SignedObject / OCSP
- ✅ `SignedObject.verify` agora aceita RSA, ECDSA, DSA e Ed25519 reutilizando o mesmo mecanismo de mapeamento de OID que o Python, cobrindo todos os certificados disponíveis.
- ✅ `OCSPResponse.verifySignature` delega para o novo caminho genérico e os testes `test/signed/signed_test.dart`/`test/ocsp/ocsp_test.dart` garantem regressão contra casos RSA, ECDSA e Ed25519.
- 🔜 Integrar Ed448/TLS 1.3 signature schemes assim que a matemática de Ed448 estiver pronta e alinhar os `SignatureSettings` com as policies padrão do Python.

### MessageSocket / SSLv2
- ✅ `MessageSocket.recvMessage` passa a detectar `RecordHeader2` (SSLv2) e devolve o registro diretamente, igual ao gerador Python, evitando que o defragmenter quebre mensagens já alinhadas.
- ✅ Novo teste `test/messagesocket_test.dart` cobre o curto-circuito com um stub de `Defragmenter`, garantindo que o caminho legado continue funcionando ao portar TLSConnection.
- ✅ Variantes `*_blocking` (recv/queue/send/flush) foram reintroduzidas como wrappers síncronos para manter paridade com o gerador Python e facilitar o porte de `tlsconnection.py`.
- 🔜 Implementar o restante da API estilo gerador (`recvMessageBlocking`, `queueMessageBlocking`, etc.) e conectar o fluxo SSLv2/SSLv3 híbrido às camadas `tlsconnection.dart` quando elas forem portadas.

### TLSConnection / Handshake plumbing
- ✅ `TlsConnection` ganhou fila interna de handshakes e helpers `recvHandshakeMessage`/`recvHandshakeFlight`, com parsing automático usando `messages.dart` e verificação opcional de tipos esperados.
- ✅ Novos helpers `queueHandshakeMessage`, `sendHandshakeMessage` e `sendHandshakeFlight` permitem reenviar flights completos reaproveitando os buffers da `MessageSocket`, com cobertura em `test/tlsconnection_test.dart`.
- ✅ `TlsConnection` agora preserva registros não-handshake ao buscar handshakes e acusa `TLSUnexpectedMessage` quando o fluxo diverge, desbloqueando o porte incremental de `_getMsg` do Python.
- ✅ A fila de handshakes ignora registros pendentes ao buscar novos dados, reenfileirando `application_data` para consumo posterior e disparando `TLSRemoteAlert` imediatamente quando um alerta chega fora de ordem (testado em `test/tlsconnection_test.dart`).
- ✅ Heartbeats são respondidos/ignorados conforme o RFC 6520 (`heartbeatSupported`/`heartbeatCanReceive`) e tentativas de renegociação em conexões estabelecidas geram `no_renegotiation`, alinhando o comportamento com `_getMsg` (novos testes em `test/tlsconnection_test.dart`).
- ✅ Conexões TLS 1.3 agora rejeitam registros intercalados durante o handshake e exigem que ClientHello/ServerHello/Finished/KeyUpdate fiquem sozinhos no record, com regressões em `test/tlsconnection_test.dart`.
- ✅ `_bufferHandshakeMessages` atualiza `HandshakeHashes`, processa KeyUpdate/NewSessionTicket pós-handshake (com ACK automático e armazenamento de tickets TLS 1.3) e expõe os novos testes em `test/tlsconnection_test.dart`.
- ✅ Os flights agora passam pelo `PureDartTlsHandshakeStateMachine`, o que marca `handshakeEstablished` automaticamente e impede sequências inválidas sem quebrar os testes existentes.
- ✅ Tickets TLS 1.3 recém-recebidos são persistidos no `Session` e propagados para o `SessionCache`, liberando testes de resumption (`tlsconnection_test.dart`).
- ✅ `TlsConnection` agora expõe `configureHandshakeSettings`, `buildFinishedVerifyData` e `buildCertificateVerifyBytes`, reaproveitando `HandshakeHelpers`/`HandshakeSettings` para gerar Finished/CertificateVerify com o mesmo fluxo do tlslite-ng.
- ✅ Novo teste integra resumption TLS 1.3 end-to-end usando tickets do cache ao mesmo tempo em que exercita KeyUpdate/NewSessionTicket (`test/tlsconnection_test.dart`).
- ✅ Fluxo de binders PSK TLS 1.3 portado: `TlsClientHello` agora expõe `pskTruncate/psk_truncate`, `TlsExtensionBlock`/`TlsPreSharedKeyExtension` foram adicionados e `TlsConnection` ganhou helpers para assinar/verificar binders com `HandshakeHelpers`, cobertos em `test/tlsconnection_test.dart`.
- ✅ O envio de ClientHello agora recalcula automaticamente os binders PSK com base nos `HandshakeSettings` e tickets TLS 1.3 persistidos no `SessionCache`, garantindo que `queueHandshakeMessage`/`sendHandshakeMessage` emitam extensões válidas mesmo quando os binders vierem como placeholders.
- ✅ No modo servidor, `TlsConnection` passa a validar binders recebidos em ClientHello, disparando `illegal_parameter` quando o valor não confere e expondo `negotiatedClientHelloPsk*` para que as rotas de handshake escolham PSK externos posteriormente; novos testes em `test/tlsconnection_test.dart` cobrem sucesso/falha.
- ✅ **NOVO**: `selectPskFromClientHello` seleciona automaticamente o PSK anunciado (externo ou TLS 1.3 ticket), valida binders e retorna `PskSelectionResult` para construção do ServerHello.
- ✅ **NOVO**: `buildServerPreSharedKeyExtension` gera `TlsServerPreSharedKeyExtension` com índice do PSK selecionado.
- ✅ **NOVO**: `_tryDecryptTicket` deriva PSK de tickets armazenados usando HKDF-expand-label com resumption master secret.
- 🔜 Conectar `PskSelectionResult` ao fluxo completo de handshake para resumptions reais sem full handshake.

### Session cache
- ✅ `SessionCache` foi portada para `lib/src/sessioncache.dart`, preservando a ordem circular e as políticas de expiração/evicção usadas no Python.
- ✅ Novos testes em `test/sessioncache_test.dart` cobrem expiração imediata e rotação quando o cache estoura a capacidade.
- ✅ Integração básica com `TlsConnection` para armazenar/recuperar sessões.
- 🔜 Integrar completamente ao handshake server-side para resumption automática.

### ECDH clássico
- ✅ `ECDHKeyExchange` agora calcula key shares para curvas NIST/Brainpool usando PointyCastle, eliminando vários `UnimplementedError`.
- ✅ Teste de regressão `test/keyexchange_test.dart` cobre o fluxo completo em `secp256r1`.
- ✅ Suporte à negociação da extensão `ec_point_formats` com fallback seguro para `uncompressed`, garantindo erros antecipados quando o peer recusa o formato suportado.
- ✅ `TlsClientHello`/`TlsServerHello` agora expõem `getExtension(...)`, com parsing dedicado das extensões `supported_groups` e `ec_point_formats`, destravando o reuso direto nos key exchanges.
- ✅ As propriedades `supportedGroups` e `ecPointFormats` são preenchidas automaticamente em `TlsClientHello` e `TlsServerHello`, permitindo que os key exchanges usem dados normalizados sem varrer extensões manualmente.
- ✅ A seleção RFC 7919 reaproveita `supportedGroups` direto do `TlsClientHello`, mantendo compatibilidade mesmo quando a extensão não é enviada explicitamente.
- 🔜 Validar curvas adicionais (brainpool, secp384r1/secp521r1) e conectar os novos caminhos aos handshakes que ainda evitam ECDH clássico.

### SRP
- ✅ `SRPKeyExchange.processServerKeyExchange` agora valida `(g, N)` contra `goodGroupParameters` e aplica os limites `minKeySize`/`maxKeySize` dos `HandshakeSettings`, removendo os TODOs remanescentes.
- ✅ Casos de teste em `test/keyexchange_test.dart` cobrem grupos desconhecidos e tamanhos fora da janela configurada, garantindo falhas previsíveis.

### FFDHE / DH clássico
- ✅ `ADHKeyExchange` e derivados passam a aplicar `HandshakeSettings.minKeySize`/`maxKeySize` ao validar `dhP`, substituindo o limite fixo de 1024 bits.
- ✅ Novos testes em `test/keyexchange_test.dart` cobrem rejeição de primos abaixo/acima dos limites configurados.

### ML-KEM / Post-Quantum Cryptography
- 🔜 `KEMKeyExchange` possui stubs para ML-KEM-768/1024 (Kyber) - requer biblioteca PQC externa.
- 🔜 Grupos híbridos `x25519mlkem768`, `secp256r1mlkem768`, `secp384r1mlkem1024` aguardam implementação.

---

## UnimplementedError / UnsupportedError restantes

### Ed448 (eddsakey.dart)
- `Ed448PublicKey._hashAndSign` → precisa math Ed448
- `Ed448PublicKey._hashAndVerify` → precisa math Ed448

### ML-KEM (keyexchange.dart)
- `KEMKeyExchange.getRandomPrivateKey` → requer lib PQC
- `KEMKeyExchange.calcPublicValue` → requer lib PQC  
- `KEMKeyExchange.encapsulateKey` → requer lib PQC
- `KEMKeyExchange.calcSharedKey` → requer lib PQC

---

## Next Steps

1️⃣ ~~Teach the handshake routines to pick a validated PSK~~ ✅ DONE
2️⃣ Connect `PskSelectionResult` to actual handshake flow for resumptions
3️⃣ Port Ed448 math from ed448goldilocks for full EdDSA support
4️⃣ Evaluate ML-KEM library options for post-quantum support
