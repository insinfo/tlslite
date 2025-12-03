# TODO - TLSLite Dart Port

**Status**: 40% completo | **Testes**: 446 passando

## PRIORIDADES

### 🔴 CRÍTICO (para TLS funcionar)
1. **recordlayer.py** → recordlayer.dart (1.376 linhas) - STUB criado, port completo pendente
2. **keyexchange.py** → key_exchange.dart (1.100 linhas)  
3. **tlsconnection.py** → tls_connection.dart (4.535 linhas)

###  IMPORTANTE
4. **handshakesettings.py**  handshake_settings.dart (716 linhas)
5. **tlsrecordlayer.py**  tls_record_layer.dart (1.345 linhas)
6. **handshakehelpers.py**  handshake_helpers.dart (789 linhas)

###  BAIXA (pode esperar)
7. verifierdb.py, dh.py, checker.py
8. api.py, basedb.py, messagesocket.py

---

## COMPLETO 

**Utils**: codec, asn1parser, pem, x25519, aes, chacha20, poly1305, rsa, ecdsa, eddsa, dsa, hmac, compression, constanttime, datefuncs, lists, dns_utils, format_output, keyfactory, tlshashlib, tlshmac, tripledes, rc4

**Core**: constants, errors, x509, x509certchain, ocsp, signed, session, mathtls, ffdhe_groups, defragmenter, handshake_hashes

**Parcial**: tls_messages (70%), tls_extensions (70%), buffered_socket

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
- 🔜 Portar o restante da lógica de `_getMsg` (alert handling, heartbeats e renegociação) e conectar o handshake hash/HandshakeHelpers para processar flights reais.

### Session cache
- ✅ `SessionCache` foi portada para `lib/src/sessioncache.dart`, preservando a ordem circular e as políticas de expiração/evicção usadas no Python.
- ✅ Novos testes em `test/sessioncache_test.dart` cobrem expiração imediata e rotação quando o cache estoura a capacidade.
- 🔜 Integrar o cache ao handshake server-side em `tlsconnection.dart` assim que o módulo existir, garantindo cobertura de resumption/stapling em testes integrados.

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

continue implementando os TODO e os UnimplementedError e os not implemented e os UnsupportedError e os placeholders  e stub afim de comcluir o port
continue portando o C:\MyDartProjects\tlslite\tlslite-ng para dart e atualize o C:\MyDartProjects\tlslite\TODO.md    