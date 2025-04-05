import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;

// Assume que existe uma função ou classe para secureHash,
// ou que será substituída pela lógica de hash abaixo.
// Se secureHash for complexo, sua lógica precisaria ser portada também.
// Por agora, vamos usar package:crypto.

/// Classe base abstrata para chaves ECDSA (Elliptic Curve Digital Signature Algorithm).
///
/// Implementações concretas de chaves ECDSA devem estender esta classe.
/// Para criar ou analisar uma chave ECDSA, utilize funções de fábrica
/// (por exemplo, em um utilitário separado ou métodos estáticos de classes concretas)
/// em vez de usar esta classe diretamente.
abstract class ECDSAKey { // Nome original da classe mantido
  /// Construtor abstrato. Subclasses devem lidar com a inicialização
  /// e armazenamento do material da chave (ponto público, escalar privado).
  ECDSAKey();

  // --- Getters Abstratos ---

  /// Retorna o tamanho da ordem da curva desta chave, em bits.
  /// Geralmente corresponde à força de segurança da chave.
  /// (Equivalente funcional ao `__len__` do Python).
  int get keySize; // Nome original mantido (equivalente a __len__)

  /// Retorna se este objeto de chave contém o componente privado.
  bool get hasPrivateKey; // Nome original mantido

  // --- Métodos Abstratos Internos (a serem implementados por subclasses) ---

  /// Método interno para realizar a operação bruta de assinatura ECDSA em um hash.
  ///
  /// - [hash]: O resumo (digest) do hash a ser assinado.
  /// - [hashAlg]: O nome do algoritmo de hash usado para gerar o [hash] (pode
  ///   ser necessário para algumas variantes/implementações ECDSA, como EdDSA).
  /// Retorna a assinatura como bytes codificados em ASN.1 DER (sequência de r, s).
  Uint8List _sign(Uint8List hash, String hashAlg); // Nome interno mantido

  /// Método interno para realizar a verificação bruta da assinatura ECDSA.
  ///
  /// - [signature]: Os bytes da assinatura codificada em ASN.1 DER.
  /// - [hash]: O resumo (digest) do hash para verificar contra a assinatura.
  /// Retorna `true` se a assinatura for válida para o hash e a chave pública.
  bool _verify(Uint8List signature, Uint8List hash); // Nome interno mantido

  // --- Métodos Públicos (Implementados na Classe Base) ---
  // Estes métodos delegam para os métodos internos abstratos (_sign, _verify)
  // após realizarem o hashing ou processarem parâmetros de compatibilidade.

  /// Calcula o hash dos dados de entrada e então assina o hash.
  ///
  /// Requer que a chave tenha um componente privado.
  /// Lança uma exceção se a chave privada não estiver disponível.
  ///
  /// - [data]: Os dados brutos a serem 'hasheados' e assinados.
  /// - [rsaScheme]: Ignorado, presente para compatibilidade de API com RSA.
  /// - [hAlg]: O nome do algoritmo de hash (padrão: 'sha1').
  /// - [sLen]: Ignorado, presente para compatibilidade de API com RSA.
  /// Retorna a assinatura ECDSA codificada em ASN.1 DER como [Uint8List].
  Uint8List hashAndSign(Uint8List data, {String? rsaScheme, String hAlg = 'sha1', int? sLen}) { // Nome original mantido
    // Obtém a implementação do hash a partir do nome
    final hashAlgorithm = _mapHashAlgorithm(hAlg);
    // Calcula o hash dos dados
    final hashBytes = Uint8List.fromList(hashAlgorithm.convert(data).bytes);

    // Chama o método público sign, que por sua vez chama _sign
    return sign(hashBytes, padding: rsaScheme, hashAlg: hAlg, saltLen: sLen);
  }

  /// Calcula o hash dos dados de entrada e então verifica a assinatura contra o hash.
  ///
  /// - [sigBytes]: A assinatura ECDSA codificada em ASN.1 DER a ser verificada.
  /// - [data]: Os dados brutos que foram originalmente assinados.
  /// - [rsaScheme]: Ignorado, presente para compatibilidade de API com RSA.
  /// - [hAlg]: O nome do algoritmo de hash usado na assinatura (padrão: 'sha1').
  /// - [sLen]: Ignorado, presente para compatibilidade de API com RSA.
  /// Retorna `true` se a assinatura for válida, `false` caso contrário.
  bool hashAndVerify(Uint8List sigBytes, Uint8List data, {String? rsaScheme, String hAlg = 'sha1', int? sLen}) { // Nome original mantido
    // Obtém a implementação do hash a partir do nome
    final hashAlgorithm = _mapHashAlgorithm(hAlg);
    // Calcula o hash dos dados
    final hashBytes = Uint8List.fromList(hashAlgorithm.convert(data).bytes);

    // Chama o método público verify, que por sua vez chama _verify
    return verify(sigBytes, hashBytes, padding: rsaScheme, hashAlg: hAlg, saltLen: sLen);
  }

  /// Assina um resumo (digest) de hash pré-calculado.
  ///
  /// Requer que a chave tenha um componente privado.
  /// Lança uma exceção se a chave privada não estiver disponível.
  ///
  /// - [hash]: O resumo (digest) do hash a ser assinado.
  /// - [padding]: Ignorado, presente para compatibilidade de API com RSA.
  /// - [hashAlg]: O nome do algoritmo de hash que foi usado para gerar o [hash].
  /// - [saltLen]: Ignorado, presente para compatibilidade de API com RSA.
  /// Retorna a assinatura ECDSA codificada em ASN.1 DER como [Uint8List].
  Uint8List sign(Uint8List hash, {String? padding, String hashAlg = "sha1", int? saltLen}) { // Nome original mantido
     if (!hasPrivateKey) {
        // É mais idiomático lançar StateError para estado inválido do objeto
        throw StateError("A chave privada é necessária para assinar.");
     }
     // Delega para o método interno abstrato
     // Passa hashAlg normalizado, pois _sign pode precisar dele
     return _sign(hash, hashAlg.toLowerCase());
  }

  /// Verifica uma assinatura contra um resumo (digest) de hash pré-calculado.
  ///
  /// - [sigBytes]: A assinatura ECDSA codificada em ASN.1 DER.
  /// - [hash]: O resumo (digest) do hash para verificar.
  /// - [padding]: Ignorado, presente para compatibilidade de API com RSA.
  /// - [hashAlg]: Ignorado nesta camada (já foi usado para gerar o hash).
  /// - [saltLen]: Ignorado, presente para compatibilidade de API com RSA.
  /// Retorna `true` se a assinatura for válida para o hash e chave pública.
  bool verify(Uint8List sigBytes, Uint8List hash, {String? padding, String? hashAlg, int? saltLen}) { // Nome original mantido
    // Delega para o método interno abstrato
    return _verify(sigBytes, hash);
  }

  // --- Outros Métodos Abstratos ---

  /// Retorna `true` se o método [write] aceitar uma senha para
  /// criptografar a chave privada.
  bool acceptsPassword(); // Nome original mantido

  /// Retorna uma string contendo a chave (geralmente em formato PEM).
  ///
  /// Opcionalmente criptografa a chave privada usando a [password] fornecida,
  /// se [acceptsPassword] retornar `true` e a implementação suportar.
  ///
  /// - [password]: A senha opcional para criptografar a chave privada.
  String write({String? password}); // Nome original mantido

  // --- Método Estático de Geração (Placeholder) ---
  // Dart não tem métodos estáticos abstratos. Lança UnimplementedError.

  /// Gera um novo par de chaves ECDSA para uma curva especificada.
  ///
  /// NOTA: O parâmetro `curveName` foi usado em vez do `bits` do Python
  /// por ser menos ambíguo.
  /// Este método deve ser implementado por uma subclasse concreta ou uma fábrica.
  ///
  /// - [curveName]: O nome da curva desejada (ex: 'secp256r1', 'secp384r1').
  /// Retorna uma nova instância de [ECDSAKey] (ou subclasse concreta).
  static ECDSAKey generate(String curveName) { // Nome original mantido
    throw UnimplementedError(
        'ECDSA key generation should be implemented by a concrete subclass or factory.');
  }

  // --- Métodos Auxiliares (Implementados na Classe Base) ---

  /// Mapeia o nome do algoritmo de hash para um objeto `crypto.Hash`.
  /// Necessário para os métodos `hashAndSign` e `hashAndVerify`.
  static crypto.Hash _mapHashAlgorithm(String hAlg) {
     // Normaliza o nome (remove traços, minúsculas)
     final String alg = hAlg.toLowerCase().replaceAll('-', '');
     switch (alg) {
        case 'sha1': return crypto.sha1;
        case 'sha224': return crypto.sha224;
        case 'sha256': return crypto.sha256;
        case 'sha384': return crypto.sha384;
        case 'sha512': return crypto.sha512;
        // Adicione outros hashes conforme necessário (ex: sha512_256 da crypto)
        // case 'sha512256': return crypto.sha512256;
        default:
          // Use a string original na mensagem de erro para clareza
          throw ArgumentError("Algoritmo de hash não suportado: $hAlg");
     }
  }
}