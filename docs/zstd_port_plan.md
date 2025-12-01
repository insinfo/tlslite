# Zstd Decoder and Encoder Port to dart Plan
referencia em https://github.com/facebook/zstd
referencia em https://github.com/klauspost/compress
referencia em https://github.com/airlift/aircompressor
# TLS Compression Port Plan (2025-12-01)

Este documento acompanha o porte dos encoders/decoders de Zstd e Brotli para
Dart puro. A meta é substituir o uso de `dart:ffi`, mantendo paridade de bits
com as referências oficiais e reaproveitando os testes que já sustentam a
stack TLS de `tlslite`.

## Referências principais

- Zstd: https://github.com/facebook/zstd (`zstddeclib.c`)
- Complementos: https://github.com/klauspost/compress,
  https://github.com/airlift/aircompressor, https://github.com/101arrowz/fzstd,
  https://github.com/oleg-st/ZstdSharp
- Brotli: https://github.com/google/brotli (C/Java), `c:/MyDartProjects/tlslite/brotli-go`,
  `c:/MyDartProjects/tlslite/brotli-google`, `c:/tools/brotli-1.2.0`
- Código Dart: `lib/src/utils/zstd/` e `lib/src/utils/brotlidecpy/`
- Use `rg` (ripgrep) para buscas no código.

## Guard rails

- Java `byte` é assinado (-128..127); Dart usa `Uint8List` / `int` de 64 bits.
  Sempre aplique `& 0xFF` ao portar tabelas/bitfields do Java.
- Brotli é altamente sensível a erros de codificação (RFC 7932); mantenha nomes
  de arquivos/constantes/structs idênticos ao Go/Java para facilitar diffs.
- Lembre-se dos limites de janela: `_minWindowBits = 16`, `_maxWindowBits = 24`.

## Snapshot atual

### Zstd

- Decoder já cobre: leitura de múltiplos frames (incluindo skippable), blocos
  RAW/RLE/comprimidos, tabelas FSE/Huffman, dicionários `.dict`, checksum e
  janela real (`window.dart`).
- Encoder atual: blocos RAW/RLE, blocos comprimidos com literais Huffman
  (stream 1/4), tabelas LL/ML/OF emitidas via FSE, `SequenceCompressionContext`
  + `ZstdEncoderState` preservando offsets, suporte a dicionários e helper CLI
  (`tool/zstd_cli_roundtrip.dart`).
- Faltam: writer multi-stream definitivo, heurísticas melhores para o
  matchfinder, knobs (quality/window/checksum) e cobertura CLI oficial para
  cargas maiores (ver "Zstd encoder gaps").

### Brotli

- Decoder Dart (`lib/src/utils/brotlidecpy/dec`) espelha o pacote Java.
- Encoder já possui:
  - `BitStreamWriter` 
  - `brotliCompressRaw`, validado contra `brotli.exe` (metablocos RAW + terminador).
  - `BrotliEncoder` (nova classe em `lib/src/brotli/enc/brotli_encoder.dart`)
    com os metadados portados de `brotli-go` (`_kInsertBase`, `_kCopyBase`,
    `_combineLengthCodes`, histogramas e escrita das árvores literal/command/distance).
  - `brotliCompressLiteral` reescrito para usar o encoder novo, porém apenas com
    comandos "insert-only" (nenhum copy real).
- Ainda faltam: match finder, block splitting, context maps, dicionário e
  transforms ― tudo descrito na seção seguinte.

## Gap analysis – Brotli encoder vs `brotli-go`

1. **Match finder e comandos**  
   - `brotli-go/matchfinder` gera `Match` (unmatched/length/distance) e mantém um
     ring buffer de distâncias (short codes 0..15). A versão Dart depende de
     `BrotliMatch` fornecido pelo chamador e hoje só conhece o caso
     literal-only. Precisamos portar um match finder (pode aproveitar
     `encoder_match_finder.dart` como base) com janela Brotli (até 16 MiB) e
     heurísticas equivalentes ao Go.

2. **Meta-block splitting & context maps**  
   - `brotli_bit_stream.go` seleciona tipos de bloco e context maps usando
     `blockSplitCode`/`storeBlockSwitchCommand`. No Dart sempre emitimos um único
     tipo de bloco por categoria (`writer.writeBits(0, 13)`). Precisamos portar
     o mesmo fluxo (block types, comprimentos, context map tree + RLE) e os
     parâmetros `npostfix`/`ndirect` para a codificação de distâncias.

3. **Context modeling e transforms**  
   - O decoder já usa `Context.dart` e `Transform.dart`; o encoder precisa
     calcular context IDs, modos texto/genérico e aplicar as transformações do
     dicionário (`brotli_dict.dart`). Atualmente não calculamos context IDs nem
     emitimos o mapa de contextos.

4. **Dicionário embutido e distâncias longas**  
   - Falta incorporar o dicionário estático, escolher transformações e emitir os
     comandos especiais de distância (códigos >= 128, postfix, `dictionary_word_id`).
     Sem isso o encoder não consegue aproveitar os ganhos de compressão usados
     nos fixtures oficiais.

5. **Helpers “fast” + parity bit a bit**  
   - O Go possui variantes otimizadas (`buildAndStoreHuffmanTreeFastBW`,
     `storeMetaBlockHeaderBW`). O Dart atualmente gera as árvores usando o
     builder genérico. Precisamos portar os mesmos atalhos e validar alinhamento
     de bits (`jumpToByteBoundary`, padding) contra `brotli-go`.

6. **Testes e CLI**  
   - Falta `test/brotli/brotli_encoder_test.dart` (o plano antigo citava o
     cenário "literal-only meta-blocks round trip"). Também falta um helper CLI
     (`tool/brotli_cli_roundtrip.dart`) para comparar o bitstream com `brotli.exe`.

## Plano de ação (Brotli)

### Imediato (dez/2025)

1. Portar um match finder mínimo (baseado em `matchfinder/m0.go` ou `zdfast.go`)
   e integrá-lo a `brotliCompressLiteral`, garantindo que o encoder produza pelo
   menos um comando copy real.
2. Reproduzir o experimento do `sample.bin.br`, garantindo que os símbolos de
   comando/distância gerados pelo Dart batem com `brotli-go`.
3. Criar `test/brotli/brotli_encoder_test.dart` com casos literal-only e
   literal+copy, mais um round-trip via CLI.

### Curto prazo

1. Portar `blockSplitCode` + context maps (inclusive RLE dos mapas) e habilitar
   block splitting real.
2. Implementar os helpers "fast" de Huffman (`buildAndStoreHuffmanTreeFastBW`).
3. Conectar o dicionário embutido, inclusive transform stack.
4. Calcular context IDs (2nd order modeling) e serializar os context maps.

### Médio prazo

1. Expor knobs (`quality`, `windowBits`, `lgblock`, `enableDictionary`).
2. Adicionar `tool/brotli_cli_roundtrip.dart` com flags (`--dict`, `--quality`).
3. Rodar benchmarks reais (HTTP headers, WOFF2) e comparar com `brotli.exe`.
4. Atualizar `lib/src/utils/compression.dart` para usar o encoder Brotli puro
   (com fallback RAW) assim que houver match finder/CLI parity.

## Zstd encoder gaps (referência)

- [ ] Writer multi-stream (4 streams de literais + payload de sequências sem
      cópias intermediárias).
- [ ] Heurísticas de match finder mais avançadas (lazy/chain, multi-janela).
- [ ] API pública com knobs (`quality`, `windowLog`, `checksum`).
- [ ] Reuso automático de tabelas/dicionários entre múltiplos frames.
- [ ] Benchmarks e round-trips grandes contra `zstd` oficial.

## Snapshot por diretório

### `lib/src/utils/zstd/`

- `bit_stream.dart`: apenas leitores; faltam utilitários de escrita para o
  encoder multi-stream.
- `block.dart`: parsing pronto; emissor público pendente.
- `encoder_match_finder.dart`: heurística gulosa simples (janela única).
- `huffman_encoder.dart`: gera cabeçalhos Huffman + FSE dos literais.
- `sequences.dart`: decoder completo; encoder reutiliza as structs mas ainda
  necessita limpeza para escrita.
- `window.dart`: decoder-only; encoder mantém estado próprio (`ZstdEncoderState`).
- `zstd_encoder.dart`: gera blocos comprimidos completos; precisa dos itens
  listados na subseção anterior.

### `lib/src/utils/brotli/`

- `dec/*`: espelha o Java (BitReader, Context, Dictionary, Transform, Decode).
- `brotli_encoder.dart`: possui `brotliCompressRaw`, `brotliCompressLiteral` e o
  novo `BrotliEncoder`, mas ainda não integra match finder, block splitting,
  context maps e pipeline de dicionário.
- `prefix.dart`: contém as mesmas tabelas da referência; devem ser reaproveitadas
  quando o encoder gerar comandos reais.

## CLI e testes

- `tool/zstd_cli_roundtrip.dart`: cobre `--dict`, `--checksum`, `--keep-artifacts`.
- `tool/brotli_cli_roundtrip.dart`: comprime uma entrada arbitrária usando `BrotliEncoder`,
  opcionalmente redecodifica o resultado e grava os artefatos (`--output`,
  `--roundtrip-output`, `--window-bits`, `--skip-roundtrip`, `--keep-artifacts`).
  Execute `dart run tool/brotli_cli_roundtrip.dart <arquivo>` para validar os
  bytes gerados contra o decoder Dart.
- `test/brotli/brotli_encoder_test.dart`: cobre round-trips literal-only e
  literal+copy usando `BrotliEncoder` diretamente.
- `.github/workflows/dart-tests.yml`: executa `dart analyze` e `dart test` em
  cada push/PR para impedir regressões na pipeline de compressão.

### Fluxo obrigatório para mudanças no encoder Brotli

1. Rode `dart test test/brotli/brotli_encoder_test.dart` para garantir que os
  casos de round-trip literal-only e literal+copy continuam íntegros.
2. Em seguida execute `dart run tool/brotli_cli_roundtrip.dart <fixture>` (ex. um
  `sample.bin`) antes de abrir PR ou subir commits que alterem o encoder.
  Documente no PR qual fixture foi usado. Esse passo substitui por enquanto a
  automação no CI e evita regressões silenciosas.

---

Mantenha nomes de arquivos/constantes iguais aos da referência (Go/Java) para
facilitar revisões. Toda nova etapa deve vir com testes (idealmente comparando
com o CLI oficial) e telemetria suficiente para diagnosticar divergências.
Combina:

LZ77 + Huffman + 2nd order context modeling + dicionário pré-definido + janelas deslizantes específicas. 

O formato está especificado em RFC 7932, com um monte de detalhes sobre como os códigos são montados, como os blocos são divididos etc. 
IETF Datatracker

De novo: um off-by-one num código Huffman, ou interpretar um campo de tamanho como “inclusive” em vez de “exclusive”, corrompe o stream em silêncio.

Ou seja: são algoritmos bit-precisos, cheios de invariantes implícitas.