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

## Sequences Section (in progress)

- [x] Parse Sequences Section Header (nbSeq, encoding types).
- [x] Define baseline/extra-bits tables for LL/ML/OF codes.
- [x] Implement BitReader for ANS-style reverse bit reading.
- [x] Implement FSE table entry structure and state machine.
- [x] Parse FSE symbol encoding headers (normalized counts + tableLog).
- [x] Build FSE decoding tables from compressed headers.
- [x] Decode sequences using FSE state machines.
- [x] Execute sequences (copy literals, copy matches from window).
- [ ] Wire decoded sequences + literals into the compressed block path (window mgmt, edge tests).

## Future milestones

`zstddeclib.c`, reusing the same approach that worked for the `brotlidecpy`
module: carve out a self-contained portion, translate it alongside its tests,
plug it into the Dart decoder, and only then move to the next chunk.
