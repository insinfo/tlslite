# TODO geral
- continuar portando o puro python C:\MyDartProjects\tlslite\tlslite-ng  para dart e manter C:\MyDartProjects\tlslite\TODO.md

acelerar o porte da coisas necessarias para criar um Servidor HTTPS e um https client em puro dart, se necessario usando ffi para chamar as funções de Windows Sockets 2 (Winsock)  do windows e do linux libc Sockets diretamente para construir uma API de Sockets SSL semelhante a implementação do python para facilitar no futuro portar outras bibliotecas python para dart como python-oracledb (https://github.com/oracle/python-oracledb) que pretendo portar mais depende de uma implementação de Sockets como a do python 

portar os testes de C:\MyDartProjects\tlslite\tlslite-ng\tests
C:\MyDartProjects\tlslite\tlslite-ng\unit_tests para dart

coloque um comentario // TODO onde não etiver completo

## Feito recentemente
- [x] Implementado `lib/src/utils/zstd/zstd_encoder.dart` (frames RAW single-segment com checksum opcional), exposto via `compressionAlgoImpls` e coberto por testes de ida e volta (`test/utils/zstd_encoder_test.dart`).
- [x] Atualizado o encoder Zstd para detectar runs de bytes repetidos e emitir blocos RLE (com divisão automática acima de `zstdBlockSizeMax`), com cobertura adicional em `test/utils/zstd_encoder_test.dart`.
- [x] Criado `bin/zstd_sequence_benchmark.dart` para medir o impacto do `SequenceSectionDecoder.decodeAll` (fixture real `zstd_seq_sample.zst`), com ~0,032 ms por iteração/0,016 ms por sequência em 500 execuções.
- [x] Encoder agora gera blocos "compressed" somente com literals + header de sequências vazio quando há espaço no limite de bloco, garantindo compatibilidade com o pipeline de literal/sequence do decodificador.
- [x] Adicionado `lib/src/utils/zstd/encoder_match_finder.dart`, um planejador guloso que detecta matches (janela 256 KiB) e já possui testes dedicados em `test/utils/zstd_encoder_match_finder_test.dart`.
- [x] Benchmark `bin/zstd_sequence_benchmark.dart` agora também mede o custo/benefício do heurístico de matches, exibindo quantidade de sequências e bytes cobertos.
- [x] Portado tlslite/utils/compression.py para lib/src/utils/compression.dart (compressionAlgoImpls e chooseCompressionSendAlgo) com testes em test/utils/compression_test.dart replicando o comportamento do Python
- [x] Portado tlslite/utils/tripledes.py e tlslite/utils/python_tripledes.py para lib/src/utils/tripledes.dart e lib/src/utils/python_tripledes.dart (DES base, encrypt/decrypt CBC puro Dart)
- [x] Adicionados testes em test/utils/python_tripledes_test.dart cobrindo vetores KAT KO1/KO2/KO3 e chaves de 16/24 bytes
- [x] Atualizado lib/src/utils/cipherfactory.dart para expor createTripleDES usando a implementacao python
- [x] Portado tlslite/utils/datefuncs.py para lib/src/utils/datefuncs.dart (parse/impressao de datas, funcoes de comparacao e helpers de tempo)
- [x] Adicionados testes em test/utils/datefuncs_test.dart cobrindo parse, impressao e verificacoes basicas de tempo
- [x] Executado `dart test` para validar o novo modulo
- [x] Portado tlslite/utils/constanttime.py (funcoes de comparacao e ct_compare_digest) para lib/src/utils/constanttime.dart
- [x] Adicionados testes em test/utils/constanttime_test.dart cobrindo operacoes bitwise e ctCompareDigest
- [x] Executado `dart test` apos portar constanttime
- [x] Portado tlslite/utils/lists.py para lib/src/utils/lists.dart (getFirstMatching e toStrDelimiter)
- [x] Criados testes em test/utils/lists_test.dart cobrindo cenarios de listas vazias, unicas e multiplas
- [x] Executado `dart test` apos adicionar lists
- [x] Centralizado helpers de polling/timeouts com `TransportEvent` e `TransportRuntime`, abrindo reuso para TLS/DB
- [x] Criado `SecureTransport` (interface + mixin) e provider TLS puro (`SecureSocketPureDart` + `PureDartTlsEngine`) posicionando TODOs do porte tlslite-ng
- [x] Portado tlslite/utils/format_output.py para lib/src/utils/format_output.dart (noneAsUnknown)
- [x] Criados testes em test/utils/format_output_test.dart cobrindo textos nulos e vazios
- [x] Executado `dart test` apos adicionar format_output
- [x] Portado tlslite/utils/pem.py para lib/src/utils/pem.dart (dePem, dePemList, pem, pemSniff)
- [x] Criados testes em test/utils/pem_test.dart validando decode unico/multiplo e encode
- [x] Executado `dart test` apos adicionar pem
- [x] Portado tlslite/utils/tlshashlib.py para lib/src/utils/tlshashlib.dart (wrappers hashlib-compat para md5/sha*)
- [x] Criados testes em test/utils/tlshashlib_test.dart cobrindo update incremental e copy
- [x] Executado `dart test` apos adicionar tlshashlib
- [x] Portado tlslite/utils/tlshmac.py para lib/src/utils/tlshmac.dart (HMAC wrapper e compareDigest)
- [x] Criados testes em test/utils/tlshmac_test.dart garantindo compatibilidade com package:crypto e copia de estado
- [x] Executado `dart test` apos adicionar tlshmac
- [x] Atualizado lib/src/utils/cryptomath.dart para usar TlsHmac (secureHMAC/HKDF alinhados com Python)
- [x] Adicionados testes em test/utils/cryptomath_hmac_test.dart validando sha256/md5
- [x] Executado `dart test` apos integrar cryptomath com tlshmac
- [x] Portados testes de dns_utils (unit_tests/test_tlslite_utils_dns_utils.py) para test/utils/dns_utils_test.dart
- [x] Executado `dart test` apos adicionar dns_utils_test
- [x] Portado tlslite/utils/asn1parser.py para lib/src/utils/asn1parser.dart
- [x] Criados testes em test/utils/asn1parser_test.dart cobrindo sequencias e comprimentos longos
- [x] Executado `dart test` apos adicionar asn1parser
- [x] Ajustado getFirstMatching em lib/src/utils/lists.dart para validar matches nulos/vazios igual ao Python
- [x] Expandido test/utils/lists_test.dart com novos cenarios e reexecutado `dart test`
- [x] Portado tlslite/utils/rsakey.py e tlslite/utils/python_rsakey.py para lib/src/utils/rsakey.dart (incluindo PythonRSAKey com CRT/blinding)
- [x] Criados testes em test/utils/python_rsakey_test.dart cobrindo MGF1, EMSA-PSS encode/verify, PKCS#1 sign/verify e encrypt/decrypt usando vetores da base Python
- [x] Executado `dart test test/utils/python_rsakey_test.dart` para validar o porte de RSA
- [x] Portado tlslite/utils/keyfactory.py (parse/generate de chaves RSA PKCS#1/PKCS#8, flag public/private) para lib/src/utils/keyfactory.dart
- [x] Adicionados testes em test/utils/keyfactory_test.dart cobrindo PEMs com/sem quebras de linha e chaves RSA-PSS
- [x] Executado `dart test test/utils/keyfactory_test.dart` após adicionar keyfactory
- [x] Portado tlslite/utils/python_rc4.py para lib/src/utils/python_rc4.dart (RC4 puro em Dart, testes ainda pendentes)
- [x] Adicionado lib/src/utils/cipherfactory.dart com createAES/CTR/RC4 usando implementacao python e stubs para AEAD/3DES
- [x] Portado tlslite/utils/poly1305.py para lib/src/utils/poly1305.dart e criado testes em test/utils/poly1305_test.dart cobrindo vetores RFC 7539
- [x] Portado tlslite/utils/chacha20_poly1305.py e python_chacha20_poly1305.py para lib/src/utils/chacha20_poly1305.dart e lib/src/utils/python_chacha20_poly1305.dart, com testes em test/utils/chacha20_poly1305_test.dart
- [x] Portado tlslite/bufferedsocket.py para lib/src/net/buffered_socket.dart (com TODO para adaptar a um socket Dart real) e criados testes em test/net/buffered_socket_test.dart cobrindo send/flush/recv/shutdown
- [x] Iniciado o porte de `tlslite-ng/tlslite/messages.py` em `lib/src/net/security/pure_dart/tls_messages.dart` (ContentType, Alert/Handshake enums, RecordHeader/TlsPlaintext e mensagens `ClientHello`, `ServerHello`, `Finished`).
- [x] Atualizado `lib/src/net/security/pure_dart/tls_record_layer.dart` e `tls_connection.dart` para usar os novos parsers, retornar fragmentos de handshake e manter um transcript enquanto o porte completo de `tlsconnection.py` não chega.
- [x] Adicionadas mensagens de handshake restantes (`Certificate`, `CertificateRequest`, `CertificateVerify`, `KeyUpdate`, `ChangeCipherSpec`) em `lib/src/net/security/pure_dart/tls_messages.dart`, incluindo entradas TLS 1.3.
- [x] Criado `PureDartTlsHandshakeStateMachine` e integrado ao `PureDartTlsConnection` para controlar a progressão do handshake e marcar o `recordLayer` quando um `Finished` for observado.
- [x] Conectado `PureDartTlsConfig` às cadeias PEM reais (`tlslite-ng/tests`) e adicionados testes (`test/net/security/pure_dart/…`) exercitando certificados e o novo estado de handshake.
- [x] Adicionados `TlsEncryptedExtensions` e `TlsNewSessionTicket` em `lib/src/net/security/pure_dart/tls_messages.dart`, com suporte a `recordVersion` na decodificação.
- [x] Atualizado `PureDartRecordLayer.ensureHandshake` para propagar a versão observada do record para o parser, desbloqueando mensagens TLS 1.3.
- [x] `PureDartTlsHandshakeStateMachine` agora aceita tráfego pós-handshake (tickets, key updates e client-auth) e ganhou testes dedicados em `test/net/security/pure_dart`.
- [x] Parseado a extensão `supported_versions` em `TlsClientHello`/`TlsServerHello`, escolhendo a versão negociada real para o estado do handshake e para o record layer.
- [x] Adicionados testes em `test/net/security/pure_dart` validando o parsing de `supported_versions` e a propagação da versão negociada.
- [x] Portado `tlslite-ng/tlslite/extensions.py` para `lib/src/net/security/pure_dart/tls_extensions.dart`, expondo SNI/ALPN/supported_versions via `TlsExtensionBlock` e integrando `ClientHello`, `ServerHello`, `EncryptedExtensions` e `CertificateRequest` com o novo parser/testes.
- [x] Expandido `TlsExtensionBlock` para cobrir `status_request`, `key_share` e `signature_algorithms_cert`, expondo esses dados em `TlsClientHello`, `TlsServerHello` e `TlsCertificateRequest` e armazenando os metadados no `PureDartTlsConnection` para futuros consumidores.
- [x] Adicionado `tls_handshake_parameters.dart` com o coordenador de key_share e selecionador de esquemas de assinatura, ligado ao `PureDartTlsConnection` para guiar OCSP/client-auth e validar HelloRetryRequest; criado `tls_handshake_parameters_test.dart` cobrindo a negociação.

## Proximos passos sugeridos
- [ ] Finalizar o porte dos módulos nucleares de TLS (`tlsconnection.py`, extensões em `messages.py`, `recordlayer.py`) e implementar `ensureHandshakeCompleted/sendApplicationData/receiveApplicationData` no `PureDartTlsEngine`.
- [ ] Portar `EncryptedExtensions`, `CertificateRequest` e `Certificate` helpers avançados de `tlslite-ng/tlslite/messages.py`, alinhando com `extensions.py` assim que o módulo for portado.
- [ ] Continuar expandindo suporte às mensagens restantes de TLS 1.3 (post-handshake auth completa, `HelloRetryRequest`, `NewSessionTicket` resumption logic) e validar com testes adicionais.
- [ ] Conectar o `PureDartKeyShareCoordinator` à geração real de shares (ECDHE/X25519) e produzir o segredo compartilhado que alimentará o key schedule em `tls_connection.dart`.
- [ ] Integrar `PureDartTlsConfig` com parsing real de certificados/chaves (via `keyfactory.dart`) e criar testes com vetores de `tlslite-ng/tests`.
- [ ] Expor as funcoes de datefuncs num ponto de entrada publico se necessario (ex: via lib/tlslite.dart)
- [ ] Expor e validar funcoes const-time via lib/tlslite.dart ou outro agrupador publico
- [ ] Implementar ct_check_cbc_mac_and_pad e utilitarios relacionados (depende de um HMAC incremental em Dart)
- [ ] Revisar demais usos de datas na arvore python para garantir que o modulo Dart cubra todos os cenarios
- [ ] Avaliar onde getFirstMatching/toStrDelimiter sao usados e integrar com os chamadores portados
- [ ] Mapear usos de none_as_unknown na base python e re-exportar helper no pacote publico
- [ ] Portar consumidores de PEM (certificados/chaves) para garantir compatibilidade com o helper Dart
- [ ] Integrar tlshmac.dart aos demais chamadores (mathtls, handshakes, etc.) e validar fluxo HMAC completo

## Auditoria tlslite-ng/tlslite (2025-11-28)

### Modulos de alto nivel ainda nao portados
- [ ] `api.py`, `basedb.py`, `bufferedsocket.py`, `checker.py`, `defragmenter.py` – nenhuma contraparte em `lib/`, precisam ser reescritos para expor conexoes TLS e bancos/verificadores
- [ ] `dh.py`, `keyexchange.py`, `mathtls.py` – logica de Diffie-Hellman e combinadores matematicos ausentes em Dart
- [ ] `extensions.py`, `handshakehashes.py`, `handshakehelpers.py`, `handshakesettings.py` – necessario para negociacao TLS; nada portado
- [ ] `messages.py`, `messagesocket.py`, `recordlayer.py`, `tlsrecordlayer.py`, `tlsconnection.py` – camada de mensagens/registro ainda 100% Python
- [ ] `session.py`, `sessioncache.py`, `signed.py`, `verifierdb.py` – controle de sessao e cache nao implementados
- [ ] `ocsp.py`, `x509.py`, `x509certchain.py` – validacao de certificados/OCSP falta totalmente
- [ ] `integration/*` (clienthelper, async mixins, smtp/pop/imap, xmlrpc) – nenhuma porta iniciada

-### Utils nao portados (ainda pendentes)
- [ ] `aesccm.py`, `aesgcm.py`
- [ ] `deprecations.py`, `openssl_*` wrappers, `pycrypto_*`, `python_aesccm.py`, `python_aesgcm.py`
- [ ] `python_key.py`, `python_tripledes.py`, `tackwrapper.py`, `tripledes.py`, `x25519.py`
- [ ] `tlslite/utils/__init__.py` exports ainda nao refletidos em Dart

### Outros itens derivados da auditoria
- [ ] Mapear quais dos modulos acima sao criticos para um servidor/cliente HTTPS minimo (recordlayer, messages, tlsconnection, session, x509) e priorizar o porte
- [ ] Garantir que `constants.py`/`errors.py` ja portados continuem sincronizados com futuras mudancas no upstream Python
- [ ] Planejar estrutura de testes unitarios para cada modulo migrado (usar `tlslite-ng/tests` e `unit_tests` como referencia)