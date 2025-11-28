import 'dart:typed_data';
import 'dart:math';
import 'aes.dart'; // Contém a classe base AES
import 'rijndael.dart'; // Contém a implementação do bloco Rijndael/AES
import 'cryptomath.dart'; // Contém bytesToNumber e numberToByteArray

/// Factory function to create a new Python AES cipher instance.
///
/// - [key]: The secret key for the cipher.
/// - [mode]: The cipher mode (2 for CBC, 6 for CTR).
/// - [iv]: The initialization vector (CBC) or nonce (CTR).
AES newAES(Uint8List key, int mode, Uint8List iv) {
  // IV parameter name matches the Python interface
  // ignore: non_constant_identifier_names
  final Uint8List IV = iv;

  if (mode == aesModeCBC) {
    // Mode 2
    return Python_AES(key, mode, IV);
  } else if (mode == aesModeCTR_OR_GCM) {
    // Mode 6
    return Python_AES_CTR(key, mode, IV);
  } else {
    throw UnimplementedError(
        "AES mode $mode not implemented in python_aes.dart");
  }
}

/// Pure Dart implementation of AES in CBC mode.
class Python_AES extends AES {
  late final Rijndael _rijndael;
  // Assumindo que a classe base AES tem 'Uint8List iv'
  // O IV aqui representa o estado *atual* do vetor de encadeamento.

  Python_AES(Uint8List key, int mode, Uint8List iv)
      // mode é sempre CBC (2) para esta classe
      : super(key, aesModeCBC, iv, "dart") {
    // Cria uma cópia da chave para garantir imutabilidade da entrada
    final internalKey = Uint8List.fromList(key);
    _rijndael =
        Rijndael(internalKey, blockSize: 16); // AES block size is 16 bytes
    // A classe base já deve ter armazenado o IV inicial.
    // Não precisamos de uma cópia separada aqui se a base já o fez.
    // this.iv = Uint8List.fromList(iv); // Desnecessário se a base armazena
  }

  @override
  Uint8List encrypt(Uint8List plaintext) {
    if (plaintext.lengthInBytes % 16 != 0) {
      throw ArgumentError(
          "Plaintext length must be a multiple of 16 bytes for CBC");
    }

    // Cria uma cópia mutável do plaintext para guardar o ciphertext
    final ciphertextBytes = Uint8List.fromList(plaintext);
    // Cria uma cópia mutável do IV atual para o encadeamento
    // Acessa o 'iv' da classe base (ou desta classe se a base não tiver)
    var chainBytes = Uint8List.fromList(iv);

    // CBC Mode: Para cada bloco...
    for (int i = 0; i < ciphertextBytes.lengthInBytes; i += 16) {
      final currentBlockOffset = i;

      // Pega o bloco atual de plaintext (direto do buffer que será modificado)
      // Uint8List plaintextBlock = ciphertextBytes.buffer.asUint8List(ciphertextBytes.offsetInBytes + currentBlockOffset, 16);

      // XOR com o bloco de encadeamento anterior
      for (int j = 0; j < 16; j++) {
        ciphertextBytes[currentBlockOffset + j] ^= chainBytes[j];
      }

      // Criptografa o bloco XORado (direto do buffer modificado)
      // Precisamos passar uma cópia ou view para rijndael.encrypt
      final blockToEncrypt = Uint8List.view(ciphertextBytes.buffer,
          ciphertextBytes.offsetInBytes + currentBlockOffset, 16);
      final encryptedBlock = _rijndael.encrypt(blockToEncrypt);

      // Sobrescreve o bloco original com o bloco criptografado
      ciphertextBytes.setRange(
          currentBlockOffset, currentBlockOffset + 16, encryptedBlock);

      // Define o próximo bloco de encadeamento (o ciphertext recém-gerado)
      // Cria uma cópia para evitar problemas se encryptedBlock for uma view
      chainBytes = Uint8List.fromList(encryptedBlock);
    }

    // Atualiza o IV da instância com o último bloco de ciphertext para o próximo uso
    // (Comportamento padrão do modo CBC)
    iv = chainBytes; // Atualiza o iv na classe base ou nesta classe

    return ciphertextBytes;
  }

  @override
  Uint8List decrypt(Uint8List ciphertext) {
    if (ciphertext.lengthInBytes % 16 != 0) {
      throw ArgumentError(
          "Ciphertext length must be a multiple of 16 bytes for CBC");
    }

    // Cria uma cópia mutável do ciphertext para guardar o plaintext
    final plaintextBytes = Uint8List.fromList(ciphertext);
    // Cria uma cópia mutável do IV atual para o encadeamento
    var chainBytes = Uint8List.fromList(iv);

    // CBC Mode: Para cada bloco...
    for (int i = 0; i < plaintextBytes.lengthInBytes; i += 16) {
      final currentBlockOffset = i;

      // Guarda o bloco de ciphertext *original* para o próximo encadeamento
      final originalCipherBlock = Uint8List.fromList(
          plaintextBytes.sublist(currentBlockOffset, currentBlockOffset + 16));

      // Decripta o bloco atual
      final decryptedBlock = _rijndael.decrypt(originalCipherBlock);

      // XOR com o bloco de encadeamento anterior
      for (int j = 0; j < 16; j++) {
        decryptedBlock[j] ^= chainBytes[j];
      }

      // Sobrescreve o bloco original (agora plaintextBytes) com o bloco decriptado XORado
      plaintextBytes.setRange(
          currentBlockOffset, currentBlockOffset + 16, decryptedBlock);

      // Define o próximo bloco de encadeamento (o bloco de ciphertext original)
      chainBytes = originalCipherBlock;
    }

    // Atualiza o IV da instância com o último bloco de *ciphertext* original
    iv = chainBytes;

    return plaintextBytes;
  }
}

/// Pure Dart implementation of AES in CTR mode.
class Python_AES_CTR extends AES {
  late final Rijndael _rijndael;
  // O 'iv' da classe base armazena o nonce inicial
  late Uint8List _counter; // O bloco de contador completo (nonce + counter)
  late final int
      _counterBytesLength; // Quantidade de bytes dedicados ao contador real

  Python_AES_CTR(Uint8List key, int mode, Uint8List nonce)
      // mode é sempre CTR (6) para esta classe
      : super(key, aesModeCTR_OR_GCM, nonce, "dart") {
    if (nonce.length > 16) {
      throw ArgumentError(
          "Nonce (IV) length must be at most 16 bytes for CTR mode");
    }
    final internalKey = Uint8List.fromList(key);
    _rijndael = Rijndael(internalKey, blockSize: 16);
    _counterBytesLength = 16 - nonce.length;

    // Inicializa o bloco de contador
    _counter = Uint8List(16);
    _counter.setRange(0, nonce.length, nonce); // Copia o nonce
    // O resto já está inicializado com 0 por padrão pelo Uint8List(16).
  }

  /// Gets the current value of the full counter block (nonce + counter value).
  Uint8List get counter => _counter;

  /// Sets the full counter block value. Used carefully, mainly for testing or specific state restoration.
  set counter(Uint8List newCounter) {
    if (newCounter.length != 16) {
      throw ArgumentError("Counter block must be 16 bytes long");
    }
    _counter = Uint8List.fromList(newCounter); // Cria cópia
  }

  /// Increments the counter part of the counter block.
  /// Throws StateError on overflow.
  void _counterUpdate() {
    // Converte o bloco inteiro para BigInt
    BigInt counterInt = bytesToNumber(_counter);

    // Incrementa
    counterInt += BigInt.one;

    // Converte de volta para Uint8List de 16 bytes
    Uint8List newCounterBytes;
    try {
      newCounterBytes = numberToByteArray(counterInt, howManyBytes: 16);
    } catch (e) {
      // numberToByteArray pode falhar se o número for grande demais para 16 bytes
      throw StateError("CTR counter overflowed during conversion: $e");
    }

    // Verifica o overflow específico da parte do *contador*
    // (Se a parte do contador atingiu FF..FF e estourou para 00..00,
    // o que significa que invadiria a parte do nonce no próximo incremento)
    // O overflow real já aconteceu na conversão BigInt->Bytes se foi > 2^128-1.
    // O check aqui é mais sobre a *lógica* do CTR: a parte do *contador* não deve estourar
    // e voltar a zero, pois reutilizaria keystreams.
    // A maneira mais simples é verificar se os *últimos* _counterBytesLength
    // bytes do *novo* contador são todos 0, o que indica que houve um carry
    // que passou pelo último byte do contador.

    bool counterPartIsZero = true;
    for (int i = 16 - _counterBytesLength; i < 16; i++) {
      if (newCounterBytes[i] != 0) {
        counterPartIsZero = false;
        break;
      }
    }

    // Se a parte do contador virou zero E _counterBytesLength > 0, houve overflow LÓGICO.
    // (Se _counterBytesLength == 0, o contador nunca muda, então não há overflow).
    if (_counterBytesLength > 0 && counterPartIsZero) {
      // Uma verificação mais rigorosa (como a Python) seria ver se os bytes ANTES
      // da conversão estavam todos 0xFF na parte do contador. Mas checar se
      // viraram 0 após o incremento cobre o caso de estouro lógico.
      throw StateError("CTR counter part overflowed (would reuse keystream)");
    }

    _counter = newCounterBytes; // Atualiza o contador da instância
  }

  @override
  Uint8List encrypt(Uint8List plaintext) {
    final resultBytes = Uint8List(
        plaintext.lengthInBytes); // Eficiente para construir o keystream
    //final maskBuilder = BytesBuilder(copy: false);

    int bytesToProcess = plaintext.lengthInBytes;
    int processedBytes = 0;

    while (processedBytes < bytesToProcess) {
      // Criptografa o contador atual para obter o próximo bloco de keystream
      final keystreamBlock = _rijndael.encrypt(_counter);

      // Calcula quantos bytes deste bloco de keystream precisamos
      final needed = bytesToProcess - processedBytes;
      final bytesToUse = min(16, needed); // Usa no máximo 16 bytes

      // XOR os bytes do plaintext com os bytes do keystream
      for (int i = 0; i < bytesToUse; i++) {
        resultBytes[processedBytes + i] =
            plaintext[processedBytes + i] ^ keystreamBlock[i];
      }

      processedBytes += bytesToUse;
      // Incrementa o contador para o próximo bloco, mesmo que este tenha sido o último.
      // A implementação Python avança o contador após gerar cada bloco de keystream,
      // garantindo que chamadas subsequentes continuem do ponto correto.
      try {
        _counterUpdate();
      } on StateError catch (e) {
        throw StateError("CTR counter overflow during operation: $e");
      }
    }

    return resultBytes;
  }

  @override
  Uint8List decrypt(Uint8List ciphertext) {
    // A operação CTR é a mesma para criptografia e decriptografia
    // IMPORTANTE: Se o mesmo objeto for usado para decrypt após encrypt,
    // o estado do contador deve ser resetado ou gerenciado corretamente!
    // Esta implementação continua o contador de onde parou.
    // Para usar em decrypt isoladamente, você precisaria reinicializar o contador
    // com o nonce original antes de chamar encrypt.
    // Ex: Python_AES_CTR cipher = ...; cipher.decrypt(data); // Ok se for a primeira op
    //     cipher.encrypt(data2); // Continua o contador
    //     cipher.decrypt(data3); // Continua o contador de novo
    return encrypt(ciphertext);
  }
}
