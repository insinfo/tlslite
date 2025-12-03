import 'dart:typed_data';

/// Representação abstrata da cifra de fluxo RC4.
///
/// Esta classe define a estrutura e as propriedades básicas esperadas
/// de uma implementação RC4, mas não contém a lógica de criptografia
/// em si, que deve ser fornecida por subclasses concretas.
abstract class RC4 {
  /// Indica se é uma cifra de bloco. Sempre `false` para RC4.
  final bool isBlockCipher = false;

  /// Indica se fornece criptografia autenticada com dados associados (AEAD).
  /// Sempre `false` para RC4 padrão.
  final bool isAEAD = false;

  /// Nome da cifra.
  final String name = "rc4";

  /// Referência à implementação concreta subjacente.
  /// O tipo [Object] é usado para generalidade; substitua por um tipo
  /// mais específico se os detalhes da implementação forem conhecidos.
  final Object implementation;

  /// Configura a cifra RC4.
  ///
  /// Lança um [ArgumentError] se o comprimento de [keyBytes] não estiver
  /// entre 16 e 256 bytes (inclusive).
  ///
  /// - [keyBytes]: Os bytes da chave para a cifra RC4.
  /// - [implementation]: A instância da implementação concreta.
  RC4(Uint8List keyBytes, this.implementation) {
    // Valida o comprimento da chave
    if (keyBytes.length < 16 || keyBytes.length > 256) {
      throw ArgumentError(
          'O comprimento da chave RC4 deve estar entre 16 e 256 bytes, inclusive. '
          'Recebido: ${keyBytes.length}');
    }
    // Nota: A chave em si (keyBytes) não é armazenada nesta classe abstrata.
    // Assume-se que a subclasse concreta ou a 'implementation' a gerenciará.
  }

  /// Criptografa o [plaintext] (texto claro).
  ///
  /// Retorna o [ciphertext] (texto cifrado) como [Uint8List].
  Uint8List encrypt(Uint8List plaintext);

  /// Decriptografa o [ciphertext] (texto cifrado).
  ///
  /// Para RC4, a operação é tipicamente idêntica à criptografia.
  /// Retorna o [plaintext] (texto claro) como [Uint8List].
  Uint8List decrypt(Uint8List ciphertext);
}