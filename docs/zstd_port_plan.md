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

## Encoder scaffolding (in progress)

- [x] Criei um `zstd_encoder.dart` capaz de embrulhar o payload em um frame single-segment composto apenas por blocos RAW (sem compressão de fato, mas compatível com decodificadores).
- [x] Permiti a emissão opcional do `Content_Checksum` para espelhar o comportamento do encoder de referência.
- [x] Exposei `zstd_compress` em `compressionAlgoImpls` para que o restante do TLS plumbing possa usar o encoder puro Dart.
- [x] Adicionei testes de ida e volta garantindo que `zstdCompress` + `zstdDecompressFrame` preservem o payload (inclusive para entradas maiores que o limite de bloco).
- [x] Detectei sequências com bytes repetidos e passei a emitir blocos RLE, incluindo a divisão automática em múltiplos blocos quando o run excede `zstdBlockSizeMax`.
- [x] Passei a escrever blocos do tipo "compressed" compostos somente por literals (RAW) + cabeçalho de sequências vazio, preparando o terreno para emissões reais de LL/ML/OF (somente quando há folga no limite de bloco).
- [x] Criei `bin/zstd_sequence_benchmark.dart` para medir o custo do `SequenceSectionDecoder.decodeAll` num trecho real (fixture `zstd_seq_sample.zst`), registrando ~0,032 ms/iter (~0,016 ms por sequência) em 500 iterações na VM do Dart SDK 3.6.

## Future milestones

`zstddeclib.c`, reusing the same approach that worked for the `brotlidecpy`
module: carve out a self-contained portion, translate it alongside its tests,
plug it into the Dart decoder, and only then move to the next chunk.

## falta implementar o ZSTD Encoder e o brotli Encoder