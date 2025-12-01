# Zstd Decoder and Encoder Port to dart Plan
referencia em https://github.com/facebook/zstd
referencia em https://github.com/klauspost/compress
referencia em https://github.com/airlift/aircompressor
referencia em https://github.com/101arrowz/fzstd
referencia em https://github.com/oleg-st/ZstdSharp/tree/master/src/ZstdSharp
referencia em  https://github.com/klauspost/compress/tree/master/zstd
referencia C:\MyDartProjects\tlslite\aircompressor
C:\MyDartProjects\tlslite\aircompressor\src\main\java\io\airlift\compress\v3\zstd
C:\MyDartProjects\tlslite\aircompressor\src\main\java\io\airlift\compress\v3\zstd\Huffman.java
referencia de brotli C:\MyDartProjects\tlslite\brotli-google
https://github.com/foliojs/brotli.js

C:\MyDartProjects\tlslite\brotli-go
C:\MyDartProjects\tlslite\brotli-google
C:\MyDartProjects\tlslite\archive-main

This document tracks the incremental port of `zstddeclib.c` into pure Dart. The
objective is to progressively expose the functionality required by
`lib/src/utils/compression.dart` without relying on `dart:ffi`.
use o comando rg para buscas em codigo fonte
## Guiding principles

1. **Reuse existing pure Dart tooling.** The `brotlidecpy` translation already
   provides bit-level helpers, dictionary loading patterns and unit-test
   scaffolding. Each new Zstd component will reuse the same conventions (little
   endian helpers, Uint8List based buffers, BytesBuilder for streaming output).
2. **Small, verifiable steps.** Instead of a direct rewrite of the entire
   11k-line C amalgamation, we stage the work:
   - Frame parsing + RAW/RLE block handling (current milestone)
   - Literal decoding plumbing (Huffman, FSE tables)
   - Sequence execution and window management
   - Dictionary / skippable frame support
   - Content checksum and multi-frame handling
3. **Keep TLS plumbing stable.** `compressionAlgoImpls` will only be updated
   once the Dart decoder can round-trip the block types that appear in the TLS
   certificate compression spec. Until then, the port lives under
   `lib/src/utils/zstd/` with focused tests.

## Current milestone (Raw/RLE blocks) - COMPLETED

- [x] Parse frame headers (magic validation, descriptor bits, dictionary ID,
  window size, content size) mirroring `ZSTD_getFrameHeader_advanced`.
- [x] Decode block headers (`ZSTD_getcBlockSize`) and support the RAW/RLE block
  paths (`ZSTD_copyRawBlock` and `ZSTD_setRleBlock`).
- [x] Provide a `zstdDecompressFrame` helper capable of emitting the payload for
  frames that only contain raw or RLE blocks, and that do not use checksums or
  dictionaries.
- [x] Add regression tests using handcrafted frames that cover raw and RLE
  blocks plus the relevant error paths.

## Next milestone (Literals Section)

- [x] Parse Literals Block Header (`ZSTD_decodeLiteralsBlock`).
- [x] Support Raw Literals.
- [x] Support RLE Literals.
- [x] Support Huffman Compressed Literals (requires FSE/Huffman tables).

## Sequences Section - COMPLETED

- [x] Parse Sequences Section Header (nbSeq, encoding types).
- [x] Define baseline/extra-bits tables for LL/ML/OF codes.
- [x] Implement BitReader for ANS-style reverse bit reading.
- [x] Implement FSE table entry structure and state machine.
- [x] Parse FSE symbol encoding headers (normalized counts + tableLog).
- [x] Build FSE decoding tables from compressed headers.
- [x] Decode sequences using FSE state machines.
- [x] Execute sequences (copy literals, copy matches from window).
- [x] Wire decoded sequences + literals into the compressed block path (window mgmt, edge tests).

## Dictionary / skippable frame support (in progress)

- [x] Detect and skip skippable frames before parsing the actual compressed frame.
- [x] Introduce a `ZstdDictionary` model plus lookup hooks on `zstdDecompressFrame` (map/provider, window seeding, prev offsets).
- [x] Track and reuse sequence/Huffman tables so repeat descriptors work with dictionaries.
- [x] Add regression coverage ensuring dictionary history matches decode correctly.
- [x] Parse the official `.dict` file format to hydrate entropy tables and history automatically.
- [x] Surface checksum handling once frames with dictionaries require it.
- [x] Allow multiple frames (including skippable trailers) within the same payload.

Atualizações Zstd 29/11/2025 00:35

Estruturei um buffer deslizante real (window.dart) e passei a usá‑lo em todo o pipeline (sequences.dart, zstd_decoder.dart, testes), garantindo que matches possam referenciar bytes de blocos anteriores e adicionando um guard em _readBits para detectar bitstreams inválidos.
Corrigi a inicialização do leitor de bits (bit_stream.dart), que estava consumindo 64 bits em vez de apenas os bits válidos do último byte; isso eliminou o loop infinito ao decodificar a seção de sequências real.
Reescrevi zstd_probe.dart para rodar o decodificador em um isolate secundário com timeout configurável (--timeout/--timeout-ms); agora é possível interromper a execução de forma limpa sem depender de Ctrl+C.
Adicionei o arquivo esperado zstd_seq_sample.bin e o teste de integração zstd_decoder_integration_test.dart, que valida o frame comprimido end‑to‑end via zstdDecompressFrame; atualizei zstd_port_plan.md para marcar o marco da seção de sequências como concluído.

Atualizações Zstd 29/11/2025 14:15

Implementei a resolução de dicionários diretamente no zstdDecompressFrame (novo ZstdDictionary + provider/map), incluindo a preparação do histórico via primeHistory e o reaproveitamento das offsets padrão especificadas no dicionário.
Atualizei parseFrameHeader para ignorar frames “skippable” e seguir até a próxima magia válida, permitindo encadear metadados personalizados antes do frame real.
Reestruturei sequences.dart para armazenar o estado das tabelas LL/OF/ML e aceitar descritores repeat, desbloqueando blocos que dependem das tabelas aprendidas no dicionário.
Incluí testes dedicados para dicionários (novo frame sintetizado em zstd_decoder_test.dart) e para o seed do window (zstd_window_test.dart), além de validar repeat descriptors nas unidades de sequência.

Atualizações Zstd 30/11/2025 10:20

Implementei o parser completo de dicionários oficiais (`parseZstdDictionary`) incluindo hidratação das tabelas Huffman/FSE e offsets prévios diretamente a partir do arquivo `.dict`, com fixture real em testes. Adicionei suporte a múltiplos frames concatenados e trailers skippable no `zstdDecompress`, que agora itera continuamente até o fim do buffer. Também habilitei a validação do `Content_Checksum` usando xxHash64 puro em Dart e ampliei a suíte de testes para cobrir checksum válido/corrompido e fluxos com mais de um frame.

Atualizações Zstd 30/11/2025 18:45

Comecei o porte do emissor de Huffman literals no encoder (novo `huffman_encoder.dart`), reaproveitando histogramas, construtor canônico e gerando streams 1/4 vias. O código ainda está atrás do flag `tlslite.enableHuffmanLiterals` porque o bitstream precisa ser validado contra o decoder existente; por enquanto os blocos permanecem RAW/RLE em produção, mas os testes já exercitam o fallback e o contexto compartilhado para quando habilitarmos o caminho comprimido.

Atualizações Zstd 30/11/2025 22:40

- Completei o emissor de pesos Huffman com cabeçalhos comprimidos por FSE, cobrindo alfabetos até 255 símbolos e reutilizando tabelas `repeat` quando o histograma não muda entre blocos.
- Removi o flag `tlslite.enableHuffmanLiterals`: o encoder agora tenta sempre comprimir os literais e volta automaticamente para RAW/RLE se o custo não compensar, garantindo compatibilidade com o decoder atual.
- Adicionei testes dedicados (`huffman_encoder_test.dart` e novos asserts em `zstd_encoder_test.dart`) que validam os caminhos comprimido/repeat e exercitam os cabeçalhos FSE recém-portados.

Atualizações Zstd 30/11/2025 23:55

- Portei o pipeline de emissão das tabelas FSE de LL/ML/OF no encoder: agora contamos os histogramas das sequências, normalizamos com o mesmo `FiniteStateEntropyEncoder` usado para os pesos Huffman e serializamos os cabeçalhos `FSE_NCount` completos antes do bitstream da seção de sequências.
- Adicionei `SequenceCompressionContext`, permitindo detectar automaticamente quando os histogramas são idênticos entre blocos para reutilizar descritores `repeat` e evitar retransmitir tabelas; o modo RLE também é selecionado quando todas as sequências caem em um único símbolo.
- Atualizei `zstd_encoder_test.dart` para inspecionar os cabeçalhos das seções de sequências, cobrindo tanto o caminho comprimido quanto o repeat e garantindo que o decoder continue validando as novas emissões end-to-end.

Atualizações Zstd 01/12/2025 00:15

- Introduzi `ZstdEncoderState` para acompanhar `prevOffsets` entre blocos comprimidos; o construtor de blocos agora propaga o snapshot produzido pela última sequência e garante que o bitstream ANS e o decoder compartilhem o mesmo histórico.
- Com isso, o plano das sequências continua particionando os literais nos 1/4 streams Huffman e gerando o bitstream dos símbolos, mas também mantém o alinhamento do histórico para destravar o suporte futuro a janelas reais/dicionários.
- Ajustei os testes de encoder para validar que blocos consecutivos ainda reutilizam tabelas (LL/ML em `repeat`, offsets permanecem comprimidos) e para garantir que o novo estado não quebre os cenários já portados.

Atualizações Zstd 01/12/2025 18:30

- Ensinei o `zstdCompress` a aceitar `ZstdDictionary` durante a emissão de frames: o cabeçalho agora carrega o `dictId`, as `prevOffsets` são semeadas e o histórico bruto do dicionário (limitado a 256 KiB) alimenta o match planner do primeiro bloco.
- Atualizei `encoder_match_finder.dart` para aceitar um parâmetro `history`, pré-popular a tabela de hashes e permitir que sequências de abertura façam referência direta aos bytes fornecidos pelo dicionário.
- Ampliei `zstd_encoder_test.dart` com um caso que comprime/decomprime usando um dicionário real, verificando que o frame produzido exige `dictId`, contém uma seção de sequências e continua round-trippando quando o dicionário correto é fornecido.

Atualizações Zstd 01/12/2025 22:05

- Passei a reaproveitar as tabelas Huffman/FSE embutidas no dicionário durante o primeiro bloco comprimido: o encoder semeia `HuffmanCompressionContext`/`SequenceCompressionContext` com os metadados parseados e pode emitir modos `repeat` imediatamente, sem retransmitir cabeçalhos.
- Acrescentei um rastreador de janela no encoder para que o planejador veja até 256 KiB de histórico recém-emitido; blocos posteriores (mesmo sem dicionário) agora conseguem referenciar bytes codificados anteriormente e expõem `sequence.fromHistory` para telemetria.
- Ajustei a suíte de testes (`zstd_encoder_test.dart`) para validar o reaproveitamento de tabelas do dicionário, além de garantir que o planejador registra matches oriundos do histórico inter-blocos; o plano do port foi atualizado para refletir essas capacidades.

Atualizações Zstd 02/12/2025 10:10

- Ensinei o decodificador a reconstruir tabelas Huffman diretamente a partir dos comprimentos armazenados no dicionário, garantindo que blocos literais em modo `repeat` funcionem mesmo quando o `.dict` só expõe os pesos canônicos.
- Ampliei a suíte de testes com três cenários: validação do modo `repeat` no decodificador, stream multi-frame utilizando o fixture real `http-dict-missing-symbols` e um teste de interoperabilidade onde o frame emitido pelo encoder é descompactado pelo `zstd` oficial.
- Fator comum dos testes reutiliza um helper `buildSeededDictionary`, destravando verificações compartilhadas entre encoder/decoder sem duplicar fixtures.

Atualizações Brotli 02/12/2025 16:30

- Extraí o `BitStreamWriter` compartilhado (`lib/src/utils/bit_stream_writer.dart`) e o liguei ao encoder de Zstd, adicionando `test/utils/bit_stream_writer_test.dart` para cobrir alinhamento, flush parcial e terminador — passo necessário antes do encoder Brotli.
- Implementei `brotliCompressRaw` em `lib/src/utils/brotlidecpy/brotli_encoder.dart`, que divide o payload em meta-blocos RAW (até 16.777.216 bytes), alinha os dados e encerra o fluxo com um meta-bloco vazio sinalizado como último.
- Criei `test/brotli/brotli_encoder_raw_test.dart`, que valida os headers dos meta-blocos via `BrotliBitReader` e mantém um smoke test com a CLI (`brotli -d`), além do helper `tool/brotli_cli_roundtrip.dart` para investigações manuais.

## Encoder scaffolding (in progress)

- [x] Criei um `zstd_encoder.dart` capaz de embrulhar o payload em um frame single-segment composto apenas por blocos RAW (sem compressão de fato, mas compatível com decodificadores).
- [x] Permiti a emissão opcional do `Content_Checksum` para espelhar o comportamento do encoder de referência.
- [x] Exposei `zstd_compress` em `compressionAlgoImpls` para que o restante do TLS plumbing possa usar o encoder puro Dart.
- [x] Adicionei testes de ida e volta garantindo que `zstdCompress` + `zstdDecompressFrame` preservem o payload (inclusive para entradas maiores que o limite de bloco).
- [x] Detectei sequências com bytes repetidos e passei a emitir blocos RLE, incluindo a divisão automática em múltiplos blocos quando o run excede `zstdBlockSizeMax`.
- [x] Passei a escrever blocos do tipo "compressed" compostos somente por literals (RAW) + cabeçalho de sequências vazio, preparando o terreno para emissões reais de LL/ML/OF (somente quando há folga no limite de bloco).
- [x] Criei `bin/zstd_sequence_benchmark.dart` para medir o custo do `SequenceSectionDecoder.decodeAll` num trecho real (fixture `zstd_seq_sample.zst`), registrando ~0,032 ms/iter (~0,016 ms por sequência) em 500 iterações na VM do Dart SDK 3.6.
- [x] Adicionei `encoder_match_finder.dart`, um planejador guloso LZ77-lite que identifica sequências com deslocamentos limitados (256 KiB) e devolve o buffer de literais compartilhado — primeiro passo antes de alimentar verdadeiramente os escritores FSE/Huffman.
- [x] Estendi `bin/zstd_sequence_benchmark.dart` para também medir o tempo do heurístico de correspondência (via `planMatches`), reportando número de sequências e cobertura total de bytes reutilizados.
- [x] Ensinei o encoder a serializar sequências reais reutilizando as tabelas `predefined` de LL/ML/OF e, agora, também a emitir offsets "repeat" (códigos com `extraBits <= 1`) compartilhando o estado de `prevOffsets`, com telemetria opcional para testes.

## Encoder work still pending

### Zstd encoder gaps

- [x] Integrar `planMatches` ao `zstd_encoder.dart`, gerando sequências reais (litLength/matchLength/offset) com tabelas `predefined` e emitindo blocos comprimidos completos (literals + sequence section) quando couber no limite de bloco single-segment.
- [x] Implementar a escrita das tabelas Huffman/FSE para LL/ML/OF (o caminho de literais já está pronto), reutilizando o `FiniteStateEntropyEncoder` para normalizar, suportando cabeçalhos comprimidos/RLE e cacheando descritores `repeat` entre blocos.
- [ ] Adicionar um construtor de blocos comprimidos completo: particionar os literais entre as quatro streams, gerar o bitstream das sequências e garantir alinhamento do window / prevOffsets para futuros frames.
- [ ] Honrar dicionários (`ZstdDictionary`) e fornecer APIs para reuso de tabelas aprendidas, inclusive quando múltiplos frames são concatenados.
- [ ] Expor knobs mínimos (nível de compressão, limite de janela, checksum opcional) e validar via testes que o encoder permanece compatível com decoders de referência (zstd-cli) para blocos simples.
- [ ] Estender a suíte de testes com cases que verifiquem match emission, serialização das tabelas e round-trips via `zstd` oficial; adicionar benchmarks comparando throughput/rácios antes/depois das heurísticas.

### Brotli encoder backlog

- A pasta `lib/src/utils/brotlidecpy/` contém apenas a pilha de _decoding_ (`decode.dart`, `context.dart`, `huffman.dart`, etc.). Para oferecer um encoder é necessário portar o pipeline inverso (brotli bit writer, gerador de metadados, construção de meta-blocks, transform pipelines, etc.).
- Itens mínimos: bit writer/`prefix` reverso, construtor de histogramas + Huffman encoding, compressor de context maps, gerador de meta-blocks (literal/copy distance), e suporte a dicionários compartilhados (`brotli_dict.dart`).
- Recomendação: seguir a mesma abordagem incremental usada no Zstd – começar emitindo apenas meta-blocks RAW para habilitar a API pública, depois evoluir para match finding, context modeling e, por fim, tunáveis de qualidade.

#### Brotli encoder roadmap proposto

1. **Metablocos RAW + bit writer**: reutilizar o `BitStreamWriter` recém-adicionado ao encoder de Zstd para gerar o fluxo Brotli e expor uma API que apenas embrulha payloads sem compressão, garantindo compatibilidade com decoders existentes.
2. **Histogramas e Huffman básicos**: compartilhar a infraestrutura de contagem/Huffman já usada no decoder (classes em `huffman.dart`) para construir árvores de literais e distâncias e serializá-las via o mesmo escritor bit a bit.
3. **Planejamento de matches**: adaptar o heurístico `planMatches` (ou camada derivada) ao formato Brotli, emitindo comandos literal/cópia com suporte às distâncias padrão e iniciando a reutilização do dicionário embutido (`brotli_dict.dart`).
4. **Context modeling e tunáveis**: adicionar compaction de context maps, transforms e parâmetros de qualidade (modo texto, níveis) reutilizando o esqueleto de metadados e testes criados nas fases anteriores.

### Brotli encoder execution plan (2025-12)

1. **Bit writer + plumbing compartilhado**
  - [x] Extrair um `BitStreamWriter` reutilizável em `lib/src/utils/bit_stream_writer.dart`, com helpers para writeBits, alignToByte e flush em `Uint8List`.
  - [x] Atualizar o encoder de Zstd para consumir o mesmo writer (facilita testes de regressão) e adicionar `test/utils/bit_stream_writer_test.dart` cobrindo casos de borda.
  - Objetivo: destravar o emissor Brotli sem duplicar lógica e garantir que ambas as stacks usam a mesma API de baixo nível.
2. **Metablocos RAW e CLI smoke test**
  - [x] Criar `lib/src/utils/brotlidecpy/brotli_encoder.dart` com um modo inicial `brotliCompressRaw` que emite apenas meta-blocks RAW (isLast=0 nos blocos de dados + terminador vazio) e reaproveita o bit writer para gerar o stream.
  - [x] Adicionar `test/brotli/brotli_encoder_raw_test.dart` validando os headers emitidos e mantendo um round-trip via `brotli` CLI (`brotli -d`). Criar `tool/brotli_cli_roundtrip.dart` análogo ao helper de Zstd para facilitar diagnósticos.
  - Entrega: API pública capaz de embrulhar payload sem compressão, mantendo compatibilidade com decodificadores existentes e preparando o terreno para etapas subsequentes.
3. **Histogramas, Huffman e meta-blocks comprimidos**
  - Portar o construtor de histogramas já usado no decoder (`lib/src/utils/brotlidecpy/huffman.dart`) para o caminho de encode, gerando code lengths e serializando-os conforme o formato Brotli (tree codes, run-length encoding).
  - Implementar compressão básica de literais/distâncias dentro do mesmo `brotil_encoder.dart`, com testes focados em alfabetos pequenos e verificação cruzada contra o decoder nativo.
  - Atualizar o plano com métricas de compressão (bytes emitidos, entropia) usando um novo benchmark em `bin/brotli_encoder_benchmark.dart`.
4. **Planejamento de matches e dicionário embutido**
  - Adaptar `encoder_match_finder.dart` para expor um modo Brotli (distâncias + comandos copy/literal). Incluir suporte às transformações/dicionário de `brotli_dict.dart`.
  - Adicionar telemetria em `brotli_encoder.dart` (contagem de comandos, razão literal/match) e expandir a suíte de testes com fixtures reais (HTTP headers, WOFF2) para validar o ganho frente ao modo RAW.
5. **Context modeling, tunáveis e CI**
  - Implementar compaction de context maps, modos texto vs genérico, e parâmetros básicos (`quality`, `window`).
  - Integrar smoke tests no CI reutilizando os helpers CLI para garantir que cada release do encoder continue compatível com a referência oficial.

## File-by-file status snapshot (2025-11-30)

### lib/src/utils/zstd/

- `bit_stream.dart`: somente leitores/loader (BitStreamInitializer/Loader, peekBits). Falta um escritor bit a bit para o encoder gerar os quatro fluxos de literais e o payload de sequências.
- `block.dart`: cobre parsing (readBlockHeader/ensureBlockSizeWithinWindow). Para o encoder ainda precisamos de helpers públicos que emitam cabeçalhos e validem limites ao construir blocos comprimidos reais.
- `byte_reader.dart`: utilitário só de leitura. Encoder carece de um ByteWriter/BitWriter complementar para montar frame/block payloads sem cópias supérfluas.
- `constants.dart`: alinhado com spec; nada pendente imediato.
- `dictionary.dart`: parser e modelo (`ZstdDictionary`). Encoder ainda não consome dicionários nem suporta o formato `.dict` para pré-carregar tabelas/offsets.
- `encoder_match_finder.dart`: heurística gulosa já integrada ao `zstd_encoder.dart`, ainda limitada a uma janela singla e sem heurísticas mais avançadas (lazy, chain, etc.).
- `frame_header.dart`: apenas parsing + skip de frames "skippable". Encoder precisa de um emissor de descritor (frame descriptor, Window_Descriptor, dictID, contentSize) para suportar cenários multi-frame/dicionário.
- `fse.dart`: implementa o caminho de decodificação (readFseTable/buildSequenceDecodingTable). A lógica de normalização/compressão vive no `FiniteStateEntropyEncoder` dentro de `huffman_encoder.dart` e agora é reaproveitada pela etapa de emissão das tabelas LL/ML/OF.
- `literals.dart`: todo o pipeline de decoding (parse header, Huffman table builder, streams). O encoder consome o novo `huffman_encoder.dart` (atrás do flag `tlslite.enableHuffmanLiterals`), que por enquanto só cobre o header "raw" das weights (≤128 símbolos) e não reutiliza tabelas repeat.
- `literals.dart`: todo o pipeline de decoding (parse header, Huffman table builder, streams). O encoder consome `huffman_encoder.dart`, que agora decide automaticamente entre RAW/RLE/comprimido e reutiliza tabelas repeat.
- `huffman_encoder.dart`: cobre histogramas, construtor canônico, cabeçalhos comprimidos por FSE, compressão em 1/4 streams e cache de tabelas para repetir pesos sem retransmitir o header.
- `sequences.dart`: decodificador completo (headers, tabelas, execução); serve como referência para o emissor, que já gera `SequencesHeader` com modos compressed/RLE/repeat e bitstreams ANS reais.
- `window.dart`: apenas lógica de janela para o decodificador. Encoder vai precisar de um histórico análogo para cumprir os limites de offset e compatibilidade com dicionários.
- `xxhash64.dart`: pronto (checksum). Já usado por encoder/decoder.
- `zstd_decoder.dart`: completo dentro do escopo atual ou seja aida falta coisas para ficar completo
- `zstd_encoder.dart`: emite RAW/RLE, blocos somente-literal e blocos comprimidos completos; tenta Huffman em todos os blocos, gera tabelas FSE de LL/ML/OF (com repeat/RLE quando adequado), guarda `SequenceCompressionContext` e o novo `ZstdEncoderState` (prevOffsets) para reuso inter-blocos. Seguem pendentes dicionários, writer multi-stream e knobs avançados.

### lib/src/utils/brotlidecpy/

- `bit_reader.dart`: infraestrutura de leitura usada pelo decoder; encoder precisa do equivalente bit_writer.
- `brotli_dict.dart`: apenas dados de dicionário e utilitários de lookup para decoder. Encoder deverá expor APIs para aplicar transformações/dicionário ao comprimir.
- `context.dart`: lógica de contexto de decoding. Encoder ainda não calcula context IDs nem atualiza histogramas baseados em contexto.
- `decode.dart`: pipeline completo de decomposição (meta-block parsing, literal/copy ops). Não existe contraparte de encode.
- `dictionary.dart`: parse/uso de dicionários para decoder. Encoder precisa gerar referências corretas/deltas.
- `huffman.dart`: somente construtor de tabelas de decoding; falta escritor de Huffman code lengths / tree serialization.
- `prefix.dart`: metadados de comandos para decoder; encode precisa gerar prefix tables e comprimir context maps.
- `transform.dart`: aplica transformações pós-decodificação; encoder requer caminho inverso (descobrir transform pipelines e codificá-los na stream).

## Future milestones

`zstddeclib.c`, reusing the same approach that worked for the `brotlidecpy`
module: carve out a self-contained portion, translate it alongside its tests,
plug it into the Dart decoder, and only then move to the next chunk.

## falta implementar o ZSTD Encoder e o brotli Encoder

### Próximos passos imediatos (02/12/2025)

- Reutilizar as tabelas Huffman/FSE fornecidas pelos dicionários também no decodificador para validar automaticamente os modos `repeat` dos literais e acelerar o diagnóstico de discrepâncias.
- Ampliar a cobertura de testes com fixtures reais `.dict`, exercitando o reaproveitamento das tabelas em cenários com múltiplos frames concatenados e validando o round-trip com o `zstd` oficial.

### Próximos passos estendidos

1. **CLI regression tests mais abrangentes.** Assim que o checksum emitido pelo encoder bater com o `zstd` oficial, ampliar o teste de interoperabilidade para cobrir frames com dicionário (incluindo `dictId`/`prevOffsets`) e para validar o caminho com `Content_Checksum` habilitado. O plano é reaproveitar o helper existente que grava o frame em disco e direcionar o `zstd` para decodificá-lo, adicionando variantes com dicionário e checksum.
2. **Scaffolding do encoder Brotli.** A partir do inventário da pasta `lib/src/utils/brotlidecpy/`, iniciar o espelhamento incremental: (a) adicionar um `BitStreamWriter` compartilhado com o encoder de Zstd para emitir meta-blocos RAW; (b) portar o construtor de histogramas + serialização Huffman usando as estruturas já presentes em `huffman.dart`; (c) planejar o equivalente de `encoder_match_finder.dart` visando comandos literal/cópia e suporte ao dicionário embutido em `brotli_dict.dart`. Documentar cada etapa com testes mínimos a exemplo do pipeline de Zstd.

### CLI parity plan (checksum + dicionário)

- [x] **Frame sem dicionário, checksum on.** `test/utils/zstd_encoder_test.dart` agora cobre o caminho `includeChecksum: true`, persistindo o frame em um diretório temporário e verificando a saída do `zstd -d` contra o payload original.
- [x] **Frame com dicionário oficial.** O teste adiciona um round-trip usando o fixture real `test/fixtures/http-dict-missing-symbols`, copiando o `.dict` para o diretório temporário antes de chamar `zstd -d --dict=...`.
- [x] **Smoke test automatizado.** Novo helper `tool/zstd_cli_roundtrip.dart` aceita `--dict`, `--checksum`, `--keep-artifacts` e realiza compressão + validação via CLI, deixando artefatos em caso de falha.
- [x] **Telemetria e logging.** Falhas do round-trip agora registram `xxHash64` (32 bits) do payload, header completo e o caminho dos artefatos para depuração via `zstd --list`.

referencia C:\tools\brotli-1.2.0

referencia https://github.com/google/brotli/tree/master/java/org/brotli/dec
C:\MyDartProjects\tlslite\brotli-google\java\org\brotli

tudo relacionado ao brotli deve esta neste diteorio C:\MyDartProjects\tlslite\lib\src\utils\brotlidecpy e tudo relacionando ao zstd deve esta neste diretorio C:\MyDartProjects\tlslite\lib\src\utils\zstd pois no futuro eu posso priclicar isso como pacotes se parados no pub.dev

continue trabalhando na implementação do brotli encoder e decoder C:\MyDartProjects\tlslite\lib\src\utils\brotlidecpy

comando rg para busca no codigo se necessario 