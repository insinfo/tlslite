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
7. sessioncache.py, verifierdb.py, dh.py, checker.py
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