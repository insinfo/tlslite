import 'dart:typed_data';
import 'dart:math';

/// Implementação pura em Dart da cifra de fluxo ChaCha (RFC 7539).
class ChaCha {
  /// Constantes ChaCha "expand 32-byte k"
  static const List<int> _constants = [
    0x61707865,
    0x3320646e,
    0x79622d32,
    0x6b206574
  ];

  /// Estado interno: palavras da chave (8 uint32)
  final List<int> _keyWords;

  /// Estado interno: palavras do nonce (3 uint32)
  final List<int> _nonceWords;

  /// Valor inicial do contador
  final int initialCounter;

  /// Número de rodadas (normalmente 20)
  final int rounds;

  /// Realiza rotação à esquerda de 32 bits.
  /// Garante que o resultado permaneça na faixa de 32 bits sem sinal.
  static int _rotl32(int v, int c) {
    // Mascara v para 32 bits antes de deslocar para lidar com tamanhos potenciais de int do Dart
    final v32 = v & 0xFFFFFFFF;
    final left = (v32 << c) & 0xFFFFFFFF;
    // Usa deslocamento à direita sem sinal (>>). Se v pudesse ser negativo,
    // >>> seria mais seguro, mas as entradas aqui são mascaradas.
    final right = v32 >> (32 - c);
    return (left | right) & 0xFFFFFFFF;
  }

  /// Realiza um quarto de rodada (quarter round) do ChaCha no estado `x`.
  /// Modifica a lista `x` no local (in-place).
  /// Os índices a, b, c, d correspondem às palavras do estado sendo misturadas.
  static void quarterRound(List<int> x, int a, int b, int c, int d) {
    // Garante que todas as operações mantenham a semântica de 32 bits sem sinal
    x[a] = (x[a] + x[b]) & 0xFFFFFFFF;
    x[d] = x[d] ^ x[a];
    x[d] = _rotl32(x[d], 16);

    x[c] = (x[c] + x[d]) & 0xFFFFFFFF;
    x[b] = x[b] ^ x[c];
    x[b] = _rotl32(x[b], 12);

    x[a] = (x[a] + x[b]) & 0xFFFFFFFF;
    x[d] = x[d] ^ x[a];
    x[d] = _rotl32(x[d], 8);

    x[c] = (x[c] + x[d]) & 0xFFFFFFFF;
    x[b] = x[b] ^ x[c];
    x[b] = _rotl32(x[b], 7);
  }

  // Índices para as operações da rodada dupla (rodadas de coluna e depois rodadas diagonais)
  static const List<List<int>> _roundMixupBox = [
    // Rodadas de coluna
    [0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15],
    // Rodadas diagonais
    [0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]
  ];

  /// Realiza duas rodadas (1 rodada dupla) da cifra ChaCha no estado `x`.
  /// Modifica a lista `x` no local (in-place).
  static void _doubleRound(List<int> x) {
    // Nota: A implementação Python duplica a lógica do quarter_round aqui.
    // Uma maneira mais limpa seria chamar _quarterRound, mas isso corresponde ao Python.
    for (final mixup in _roundMixupBox) {
      final a = mixup[0];
      final b = mixup[1];
      final c = mixup[2];
      final d = mixup[3];

      // Lógica do Quarter round copiada aqui
      x[a] = (x[a] + x[b]) & 0xFFFFFFFF;
      x[d] = x[d] ^ x[a];
      x[d] = _rotl32(x[d], 16);

      x[c] = (x[c] + x[d]) & 0xFFFFFFFF;
      x[b] = x[b] ^ x[c];
      x[b] = _rotl32(x[b], 12);

      x[a] = (x[a] + x[b]) & 0xFFFFFFFF;
      x[d] = x[d] ^ x[a];
      x[d] = _rotl32(x[d], 8);

      x[c] = (x[c] + x[d]) & 0xFFFFFFFF;
      x[b] = x[b] ^ x[c];
      x[b] = _rotl32(x[b], 7);
    }
  }

  /// Gera o bloco de fluxo de chave para uma dada chave, contador e nonce.
  /// Retorna uma lista de 16 inteiros de 32 bits sem sinal.
  static List<int> _chachaBlock(
      List<int> keyWords, int counter, List<int> nonceWords, int rounds) {
    if (keyWords.length != 8)
      throw ArgumentError("A chave deve ter 8 palavras (256 bits)");
    if (nonceWords.length != 3)
      throw ArgumentError("O Nonce deve ter 3 palavras (96 bits)");

    // Inicializa o estado: constantes + chave + contador + nonce
    // Garante que o contador seja tratado como 32 bits sem sinal
    final state = List<int>.filled(16, 0);
    state.setRange(0, 4, _constants); // constantes[0..3]
    state.setRange(4, 12, keyWords); // chave[0..7]
    state[12] = counter & 0xFFFFFFFF; // contador
    state.setRange(13, 16, nonceWords); // nonce[0..2]

    // Copia o estado inicial para modificação
    final workingState = List<int>.from(state, growable: false);

    // Aplica as rodadas
    final numDoubleRounds = rounds ~/ 2; // Divisão inteira
    for (int i = 0; i < numDoubleRounds; i++) {
      _doubleRound(workingState);
    }

    // Adiciona o estado inicial ao estado de trabalho final (módulo 2^32)
    for (int i = 0; i < 16; i++) {
      workingState[i] = (workingState[i] + state[i]) & 0xFFFFFFFF;
    }

    return workingState;
  }

  /// Converte um estado (lista de 16 palavras uint32) para um fluxo de bytes
  /// little-endian (Uint8List).
  static Uint8List _wordListToBytes(List<int> state) {
    if (state.length != 16)
      throw ArgumentError("O estado deve ter 16 palavras");
    final byteData = ByteData(64); // 16 palavras * 4 bytes/palavra
    for (int i = 0; i < 16; i++) {
      byteData.setUint32(i * 4, state[i], Endian.little);
    }
    // Retorna o buffer de bytes subjacente como Uint8List
    return byteData.buffer.asUint8List();
  }

  /// Converte um array de bytes (Uint8List) para uma lista de palavras de 32 bits (little-endian).
  static List<int> _bytesToWordList(Uint8List data) {
    if (data.length % 4 != 0)
      throw ArgumentError("O comprimento dos dados deve ser um múltiplo de 4");
    final words = <int>[];
    // Usa uma view ByteData para leitura eficiente
    final byteData =
        ByteData.view(data.buffer, data.offsetInBytes, data.lengthInBytes);
    for (int i = 0; i < data.lengthInBytes; i += 4) {
      words.add(byteData.getUint32(i, Endian.little));
    }
    return words;
  }

  /// Configura o estado inicial para a cifra ChaCha.
  ///
  /// - `key`: Chave de 32 bytes (256 bits) como Uint8List.
  /// - `nonce`: Nonce de 12 bytes (96 bits) como Uint8List.
  /// - `counter`: Contador de bloco inicial (o padrão é 0).
  /// - `rounds`: Número de rodadas ChaCha (o padrão é 20).
  ChaCha(Uint8List key, Uint8List nonce,
      {this.initialCounter = 0, this.rounds = 20})
      : _keyWords = _bytesToWordList(key),
        _nonceWords = _bytesToWordList(nonce) {
    if (key.length != 32) {
      throw ArgumentError(
          "A chave deve ter 32 bytes (256 bits) de comprimento");
    }
    if (nonce.length != 12) {
      throw ArgumentError("O Nonce deve ter 12 bytes (96 bits) de comprimento");
    }
    // A conversão para palavras ocorre na lista de inicializadores
  }

  /// Criptografa o plaintext (texto claro) fornecido.
  /// Retorna o ciphertext (texto cifrado) como um Uint8List.
  Uint8List encrypt(Uint8List plaintext) {
    // Usar BytesBuilder é eficiente para construir o resultado
    final ciphertextBuilder = BytesBuilder(copy: false);
    const blockSize = 64; // Tamanho do bloco ChaCha em bytes

    for (int i = 0; i < plaintext.length; i += blockSize) {
      // Calcula o contador para este bloco
      // Garante que a aritmética do contador lide com overflow potencial
      final currentBlockCounter =
          (initialCounter + (i ~/ blockSize)) & 0xFFFFFFFF; // Divisão inteira

      // Gera o bloco de fluxo de chave (16 palavras)
      final keyStreamWords =
          _chachaBlock(_keyWords, currentBlockCounter, _nonceWords, rounds);

      // Converte as palavras do fluxo de chave para bytes (64 bytes)
      final keyStreamBytes = _wordListToBytes(keyStreamWords);

      // Determina a porção do plaintext para este bloco
      final blockEnd = min(i + blockSize, plaintext.length);
      final plainTextBlockLength = blockEnd - i;

      // Faz o XOR do fluxo de chave com o bloco de plaintext
      final encryptedBlock = Uint8List(plainTextBlockLength);
      for (int j = 0; j < plainTextBlockLength; j++) {
        encryptedBlock[j] = keyStreamBytes[j] ^ plaintext[i + j];
      }

      ciphertextBuilder.add(encryptedBlock);
    }

    return ciphertextBuilder.toBytes();
  }

  /// Decriptografa o ciphertext (texto cifrado) fornecido.
  /// A decriptografia ChaCha é a mesma operação que a criptografia.
  /// Retorna o plaintext (texto claro) como um Uint8List.
  Uint8List decrypt(Uint8List ciphertext) {
    // A decriptografia é idêntica à criptografia para cifras de fluxo como ChaCha
    return encrypt(ciphertext);
  }
}
