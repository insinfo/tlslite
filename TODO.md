# TODO geral
- continuar portando o puro python C:\MyDartProjects\tlslite\tlslite-ng  para dart e manter este arquivo sincronizado com o progresso

acelerar o porte da coisas necessarias para criar um Servidor HTTPS e um https client em puro dart se necessario usando ffi para chamar as funções de Windows Sockets 2 (Winsock)  do windows e do linux libc Sockets diretamente para construir uma API de Sockets SSL semelhante a implementação do python para facilitar no futuro portar outras bibliotecas python para dart como python-oracledb (https://github.com/oracle/python-oracledb) que pretendo portar mais depende de uma implementação de Sockets como a do python 

portar os testes de C:\MyDartProjects\tlslite\tlslite-ng\tests
C:\MyDartProjects\tlslite\tlslite-ng\unit_tests para dart

## Feito recentemente
- [x] Portado tlslite/utils/datefuncs.py para lib/src/utils/datefuncs.dart (parse/impressao de datas, funcoes de comparacao e helpers de tempo)
- [x] Adicionados testes em test/utils/datefuncs_test.dart cobrindo parse, impressao e verificacoes basicas de tempo
- [x] Executado `dart test` para validar o novo modulo
- [x] Portado tlslite/utils/constanttime.py (funcoes de comparacao e ct_compare_digest) para lib/src/utils/constanttime.dart
- [x] Adicionados testes em test/utils/constanttime_test.dart cobrindo operacoes bitwise e ctCompareDigest
- [x] Executado `dart test` apos portar constanttime
- [x] Portado tlslite/utils/lists.py para lib/src/utils/lists.dart (getFirstMatching e toStrDelimiter)
- [x] Criados testes em test/utils/lists_test.dart cobrindo cenarios de listas vazias, unicas e multiplas
- [x] Executado `dart test` apos adicionar lists
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

## Proximos passos sugeridos
- [ ] Expor as funcoes de datefuncs num ponto de entrada publico se necessario (ex: via lib/tlslite.dart)
- [ ] Expor e validar funcoes const-time via lib/tlslite.dart ou outro agrupador publico
- [ ] Implementar ct_check_cbc_mac_and_pad e utilitarios relacionados (depende de um HMAC incremental em Dart)
- [ ] Revisar demais usos de datas na arvore python para garantir que o modulo Dart cubra todos os cenarios
- [ ] Avaliar onde getFirstMatching/toStrDelimiter sao usados e integrar com os chamadores portados
- [ ] Mapear usos de none_as_unknown na base python e re-exportar helper no pacote publico
- [ ] Portar consumidores de PEM (certificados/chaves) para garantir compatibilidade com o helper Dart
- [ ] Integrar tlshmac.dart aos demais chamadores (mathtls, handshakes, etc.) e validar fluxo HMAC completo