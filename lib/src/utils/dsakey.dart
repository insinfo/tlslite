import 'dart:typed_data';

/// Classe base abstrata para chaves DSA (Digital Signature Algorithm).
///
/// Implementações concretas de chaves DSA devem estender esta classe.
/// Para criar ou analisar uma chave DSA, utilize funções de fábrica
/// (por exemplo, em um utilitário separado ou métodos estáticos de classes concretas)
/// em vez de usar esta classe diretamente.
abstract class DSAKey { // Nome original da classe mantido

  /// Construtor abstrato. As subclasses devem lidar com a inicialização
  /// e armazenamento dos parâmetros (p, q, g) e chaves (x, y).
  DSAKey();

  // --- Getters Abstratos ---

  /// Retorna o tamanho da ordem do subgrupo primo q desta chave, em bits.
  /// Geralmente corresponde à força de segurança da chave.
  /// (Equivalente funcional ao `__len__` do Python).
  int get keySize;

  /// Retorna se este objeto de chave contém o componente privado (x).
  bool get hasPrivateKey; // Nome original do método/getter mantido

  /// Retorna o parâmetro de domínio p (número primo definindo o corpo de Galois).
  BigInt get p;

  /// Retorna o parâmetro de domínio q (fator primo de p-1).
  BigInt get q;

  /// Retorna o parâmetro de domínio g (gerador do grupo cíclico de ordem q).
  BigInt get g;

  /// Retorna a chave pública y.
  BigInt get y;

  /// Retorna a chave privada x, ou null se não estiver presente.
  BigInt? get x;

  // --- Métodos Abstratos ---

  /// Calcula o hash dos dados de entrada usando o algoritmo [hAlg] especificado
  /// e então assina o hash resultante usando a chave privada.
  ///
  /// Requer que a chave tenha um componente privado.
  /// Lança uma exceção se a chave privada não estiver disponível ou se [hAlg]
  /// não for suportado pela implementação concreta.
  ///
  /// - [data]: Os dados brutos a serem 'hasheados' e assinados.
  /// - [hAlg]: O nome do algoritmo de hash (ex: 'SHA-1', 'SHA-256').
  /// Retorna a assinatura DSA codificada em ASN.1 DER (sequência de r, s) como bytes.
  Uint8List hashAndSign(Uint8List data, String hAlg); // Nome original mantido

  /// Assina um hash pré-calculado usando a chave privada.
  ///
  /// Requer que a chave tenha um componente privado.
  /// Lança uma exceção se a chave privada não estiver disponível.
  ///
  /// - [hash]: O resumo (digest) do hash pré-calculado dos dados a serem assinados.
  /// Retorna a assinatura DSA codificada em ASN.1 DER (sequência de r, s) como bytes.
  Uint8List sign(Uint8List hash); // Nome original mantido

  /// Calcula o hash dos dados de entrada usando o algoritmo [hAlg] especificado e
  /// verifica a [signature] fornecida contra o hash usando a chave pública.
  ///
  /// - [signature]: A assinatura codificada em ASN.1 DER (sequência de r, s) a ser verificada.
  /// - [data]: Os dados brutos que foram originalmente assinados.
  /// - [hAlg]: O nome do algoritmo de hash usado durante a assinatura (padrão: 'sha1').
  /// Retorna `true` se a assinatura for válida para os dados e a chave pública,
  /// `false` caso contrário.
  bool hashAndVerify(Uint8List signature, Uint8List data, [String hAlg = 'sha1']); // Nome original mantido

  // --- Métodos Estáticos (Placeholders) ---
  // Dart não tem métodos estáticos abstratos. Estes lançam UnimplementedError
  // para indicar que devem ser fornecidos por implementações concretas ou fábricas.
  // O tipo de retorno aqui é a própria classe abstrata, esperando que a implementação
  // retorne uma instância de uma subclasse concreta.

  /// Gera um novo par de chaves DSA (incluindo parâmetros de domínio p, q, g).
  ///
  /// Este método deve ser implementado por uma subclasse concreta ou uma fábrica.
  ///
  /// - [L]: Comprimento de bits desejado para o módulo primo p.
  /// - [N]: Comprimento de bits desejado para a ordem do subgrupo primo q.
  /// Retorna uma nova instância de [DSAKey] (ou subclasse concreta) contendo
  /// os parâmetros e chaves gerados.
  static DSAKey generate(int L, int N) { // Nome original mantido
    throw UnimplementedError(
        'DSA key generation should be implemented by a concrete subclass or factory.');
  }

  /// Gera apenas novos parâmetros de domínio DSA (p, q).
  ///
  /// Este método deve ser implementado por uma subclasse concreta ou uma fábrica.
  /// O gerador 'g' normalmente seria derivado de p e q posteriormente.
  ///
  /// - [L]: Comprimento de bits desejado para o módulo primo p.
  /// - [N]: Comprimento de bits desejado para a ordem do subgrupo primo q.
  /// Retorna um [Record] contendo os primos p e q gerados.
  static ({BigInt p, BigInt q}) generate_qp(int L, int N) {
     throw UnimplementedError(
        'DSA parameter generation (p, q) should be implemented by a concrete subclass or factory.');
  }
}