//cryptomath.dart

/// cryptomath module
///
/// This module has basic math/crypto code.
import 'dart:typed_data';
import 'dart:math' as math;
import 'dart:convert' show utf8;
// Dependências de pacotes (adicione ao seu pubspec.yaml)
import 'package:crypto/crypto.dart' as crypto;
import 'package:pointycastle/api.dart';
import 'package:pointycastle/random/fortuna_random.dart';

import 'package:pointycastle/digests/md5.dart';
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/src/platform_check/platform_check.dart'
    show Platform;

// Assumindo que você tem este arquivo com a classe Writer implementada
import 'codec.dart'; // Importe sua implementação de Writer
import 'tlshmac.dart';

// --- Helper Functions ---

/// Converte um BigInt para Uint8List (big-endian, unsigned).
/// [byteLength] especifica o tamanho desejado. Zeros à esquerda são adicionados se necessário.
/// Se o número for muito grande para caber, ele será truncado (bytes mais significativos removidos).
Uint8List bigIntToBytes(BigInt number, int byteLength, {bool signed = false}) {
  if (number == BigInt.zero) {
    return Uint8List(byteLength);
  }

  // A implementação toRadixString(16) e manipulação de string é uma forma,
  // mas pode ser ineficiente. Usar operações bit a bit é geralmente melhor.

  Uint8List bytes = Uint8List(byteLength);
  for (int i = 0; i < byteLength; i++) {
    bytes[byteLength - 1 - i] = (number & BigInt.from(0xff)).toInt();
    number = number >> 8;
  }

  // Se o número original era maior que o byteLength permitido, `number` ainda
  // terá bits restantes aqui. A lógica acima já truncou efetivamente.
  // Para representação signed (two's complement), a lógica seria diferente.
  // Esta função foca na representação unsigned como a maioria das operações crypto.

  return bytes;
}

/// Converte um Uint8List para BigInt (assumindo big-endian, unsigned).
BigInt _bytesToBigInt(Uint8List bytes) {
  BigInt result = BigInt.zero;
  for (int i = 0; i < bytes.length; i++) {
    result = (result << 8) | BigInt.from(bytes[i]);
  }
  return result;
}

// **************************************************************************
// PRNG Functions (Usando PointyCastle)
// **************************************************************************

// Configuração do SecureRandom (exemplo com Fortuna)
final SecureRandom _secureRandom = FortunaRandom()
  ..seed(KeyParameter(Platform.instance.platformEntropySource().getBytes(32)));

/// Gera um Uint8List de bytes aleatórios seguros.
Uint8List getRandomBytes(int howMany) {
  final bytes = _secureRandom.nextBytes(howMany);
  assert(bytes.length == howMany);
  return bytes;
}

const String prngName = "PointyCastle Fortuna";

// **************************************************************************
// Simple hash functions
// **************************************************************************

Digest _getDigest(String algorithm) {
  switch (algorithm.toLowerCase()) {
    case 'md5':
      return MD5Digest();
    case 'sha1':
      return SHA1Digest();
    case 'sha256':
      return SHA256Digest();
    case 'sha384':
      return SHA384Digest();
    case 'sha512':
      return SHA512Digest();
    default:
      throw ArgumentError('Unsupported hash algorithm: $algorithm');
  }
}

/// Retorna um digest MD5 dos dados.
Uint8List MD5(Uint8List b) {
  return crypto.md5.convert(b).bytes as Uint8List;
}

/// Retorna um digest SHA1 dos dados.
Uint8List SHA1(Uint8List b) {
  return crypto.sha1.convert(b).bytes as Uint8List;
}

/// Retorna um digest dos `data` usando `algorithm`.
Uint8List secureHash(Uint8List data, String algorithm) {
  switch (algorithm.toLowerCase()) {
    case 'md5':
      return crypto.md5.convert(data).bytes as Uint8List;
    case 'sha1':
      return crypto.sha1.convert(data).bytes as Uint8List;
    case 'sha256':
      return crypto.sha256.convert(data).bytes as Uint8List;
    case 'sha384':
      return crypto.sha384.convert(data).bytes as Uint8List;
    case 'sha512':
      return crypto.sha512.convert(data).bytes as Uint8List;
    default:
      // Usando PointyCastle para flexibilidade se 'crypto' não suportar
      final digest = _getDigest(algorithm);
      return digest.process(data);
  }
}

/// Retorna um HMAC usando `b` e `k` com `algorithm`.
Uint8List secureHMAC(Uint8List k, Uint8List b, String algorithm) {
  final mac = TlsHmac(k, digestmod: algorithm);
  mac.update(b);
  return mac.digest();
}

Uint8List HMAC_MD5(Uint8List k, Uint8List b) {
  return secureHMAC(k, b, 'md5');
}

Uint8List HMAC_SHA1(Uint8List k, Uint8List b) {
  return secureHMAC(k, b, 'sha1');
}

Uint8List HMAC_SHA256(Uint8List k, Uint8List b) {
  return secureHMAC(k, b, 'sha256');
}

Uint8List HMAC_SHA384(Uint8List k, Uint8List b) {
  return secureHMAC(k, b, 'sha384');
}

// Helper para obter o tamanho do digest
int _getDigestSize(String algorithm) {
  switch (algorithm.toLowerCase()) {
    case 'md5':
      return 16;
    case 'sha1':
      return 20;
    case 'sha256':
      return 32;
    case 'sha384':
      return 48;
    case 'sha512':
      return 64;
    default:
      // Use PointyCastle para calcular se não for um dos acima
      return _getDigest(algorithm).digestSize;
  }
}

Uint8List HKDF_expand(Uint8List PRK, Uint8List info, int L, String algorithm) {
  final digestSize = _getDigestSize(algorithm);
  final N = divceil(BigInt.from(L), BigInt.from(digestSize)).toInt();
  final T = BytesBuilder(); // Mais eficiente para concatenação
  Uint8List Titer = Uint8List(0);

  for (int i = 1; i <= N; i++) {
    // O loop original ia até N+1, mas T só é adicionado *antes* do cálculo
    // e o último Titer não é usado se for até N+1. O correto é até N.
    // Construir a entrada para HMAC
    final hmacInput = BytesBuilder();
    hmacInput.add(Titer);
    hmacInput.add(info);
    hmacInput.addByte(i); // Adiciona o byte contador

    Titer = secureHMAC(PRK, hmacInput.toBytes(), algorithm);
    T.add(Titer);
  }
  // Retorna os primeiros L bytes
  return T.toBytes().sublist(0, L);
}

/// Função de derivação de chave TLS 1.3 (HKDF-Expand-Label).
Uint8List HKDF_expand_label(Uint8List secret, Uint8List label,
    Uint8List hashValue, int length, String algorithm) {
  final hkdfLabel = Writer();
  hkdfLabel.addTwo(length);
  // Concatena "tls13 " com o label
  final labelPrefix = utf8.encode("tls13 ");
  final fullLabel = Uint8List.fromList(labelPrefix + label);
  hkdfLabel.addVarSeq(
      fullLabel, 1, 1); // Assumindo que addVarSeq lida com Uint8List
  hkdfLabel.addVarSeq(
      hashValue, 1, 1); // Assumindo que addVarSeq lida com Uint8List

  return HKDF_expand(secret, hkdfLabel.bytes, length, algorithm);
}

/// Função de derivação de chave TLS 1.3 (Derive-Secret).
/// Nota: O tipo HandshakeHashes não foi fornecido, então assumimos que ele tem
/// um método `digest(String algorithm)` que retorna `Uint8List` ou é `null`.
/// Se for diferente, ajuste a lógica de `hs_hash`.
Uint8List derive_secret(Uint8List secret, Uint8List label,
    dynamic /*HandshakeHashes?*/ handshake_hashes, String algorithm) {
  Uint8List hs_hash;
  if (handshake_hashes == null) {
    hs_hash = secureHash(Uint8List(0), algorithm);
  } else {
    // Assumindo que handshake_hashes tem um método digest
    // Adapte esta linha se a estrutura for diferente
    hs_hash = handshake_hashes.digest(algorithm) as Uint8List;
  }

  final digestSize = _getDigestSize(algorithm);
  return HKDF_expand_label(secret, label, hs_hash, digestSize, algorithm);
}

// **************************************************************************
// Converter Functions
// **************************************************************************

/// Converte um número armazenado em Uint8List para BigInt.
/// Por padrão, assume codificação big-endian.
BigInt bytesToNumber(Uint8List b, {String endian = "big"}) {
  if (endian.toLowerCase() == "little") {
    // Implementação little-endian
    BigInt result = BigInt.zero;
    for (int i = 0; i < b.length; i++) {
      result |= BigInt.from(b[i]) << (8 * i);
    }
    return result;
  } else {
    // Implementação big-endian (padrão)
    return _bytesToBigInt(b);
  }
}

/// Converte um BigInt em um Uint8List, preenchido com zeros até howManyBytes.
/// O Uint8List retornado pode ser menor que howManyBytes se o número não couber,
/// mas não será maior (será truncado). Usa codificação big- or little-endian.
/// Big endian é o padrão.
Uint8List numberToByteArray(BigInt n,
    {int? howManyBytes, String endian = "big"}) {
  if (n < BigInt.zero) {
    // A implementação original parece assumir números positivos.
    // A conversão de BigInt negativo para bytes requer lógica de complemento de dois.
    // Por simplicidade e para corresponder ao original, lançamos um erro ou lidamos com isso.
    // Esta implementação se concentrará em números não negativos.
    throw ArgumentError("Number must be non-negative for this conversion.");
  }
  if (n == BigInt.zero) {
    return Uint8List(howManyBytes ?? 1); // Retorna [0] ou lista de zeros
  }

  int length = (n.bitLength + 7) ~/ 8; // Calcula o número mínimo de bytes
  int targetLength =
      howManyBytes ?? length; // Usa howManyBytes se fornecido, senão o mínimo

  Uint8List bytes = Uint8List(targetLength);
  BigInt tempN = n;

  if (endian.toLowerCase() == "little") {
    for (int i = 0; i < targetLength; i++) {
      if (tempN == BigInt.zero) break; // Para de preencher se o número acabar
      bytes[i] = (tempN & BigInt.from(0xff)).toInt();
      tempN >>= 8;
    }
    // Truncamento: Se howManyBytes foi fornecido e era menor que 'length',
    // os bytes mais significativos já foram ignorados pelo loop limitado por targetLength.
  } else {
    // Big-endian
    int startIdx =
        targetLength - length; // Onde começar a preencher no array de saída
    if (startIdx < 0) {
      // O número é maior que howManyBytes, precisamos truncar
      // Descartar os bytes mais significativos do número
      tempN >>= ((-startIdx) * 8);
      startIdx = 0;
    }

    for (int i = targetLength - 1; i >= startIdx; i--) {
      bytes[i] = (tempN & BigInt.from(0xff)).toInt();
      tempN >>= 8;
      if (tempN == BigInt.zero && i > startIdx)
        break; // Otimização: parar se o resto for zero
    }
    // Preenchimento com zero: Os bytes antes de startIdx já são zero pela inicialização do Uint8List.
    // Truncamento: Já tratado pelo cálculo de startIdx e/ou deslocamento de tempN.
  }

  return bytes;
}

/// Converte um MPI (string bignum OpenSSL) para BigInt.
BigInt mpiToNumber(Uint8List mpi) {
  // MPI format: 4 bytes de tamanho (big-endian), seguidos pelos bytes do número (big-endian)
  if (mpi.length < 4) {
    throw ArgumentError("Invalid MPI format: too short");
  }
  // Lê o tamanho (ignoramos por enquanto, usamos o comprimento real dos dados)
  // int length = (mpi[0] << 24) | (mpi[1] << 16) | (mpi[2] << 8) | mpi[3];

  final dataBytes = mpi.sublist(4);

  // Verifica o bit de sinal (o original checava o primeiro byte dos dados)
  if (dataBytes.isNotEmpty && (dataBytes[0] & 0x80) != 0) {
    // Nota: A implementação original lançava erro para negativos.
    // O formato MPI pode incluir um byte 0x00 extra no início para indicar positivo
    // se o bit mais significativo do próximo byte for 1.
    // Se quisermos suportar negativos, precisaríamos de lógica de complemento de dois.
    // Mantendo a restrição original:
    throw ArgumentError("Input must be a positive integer (MPI sign bit set)");
  }
  return bytesToNumber(dataBytes); // Usa big-endian por padrão
}

/// Converte um BigInt para um MPI (string bignum OpenSSL).
Uint8List numberToMPI(BigInt n) {
  if (n < BigInt.zero) {
    throw ArgumentError(
        "Cannot convert negative number to MPI format (in this implementation)");
  }

  Uint8List b = numberToByteArray(n, endian: "big"); // Obtem bytes do número

  // Remove zeros à esquerda, exceto se for o único byte [0]
  int firstNonZero = 0;
  while (firstNonZero < b.length - 1 && b[firstNonZero] == 0) {
    firstNonZero++;
  }
  if (firstNonZero > 0) {
    b = b.sublist(firstNonZero);
  }

  bool prependZero = false;
  // Se o bit mais significativo do primeiro byte estiver definido,
  // adicione um byte zero extra no início para indicar que é positivo.
  if (b.isNotEmpty && (b[0] & 0x80) != 0) {
    prependZero = true;
  }
  if (n == BigInt.zero && b.isEmpty) {
    // Caso especial para o número 0
    b = Uint8List(1); // Representa como um único byte 0
    // prependZero continua false
  }

  int length = b.length + (prependZero ? 1 : 0);

  // Cria o resultado final: 4 bytes de tamanho + [0x00 opcional] + bytes do número
  final result = Uint8List(4 + length);

  // Escreve o tamanho (big-endian)
  result[0] = (length >> 24) & 0xFF;
  result[1] = (length >> 16) & 0xFF;
  result[2] = (length >> 8) & 0xFF;
  result[3] = length & 0xFF;

  int dataOffset = 4;
  if (prependZero) {
    result[dataOffset] = 0x00;
    dataOffset++;
  }

  // Copia os bytes do número
  result.setRange(dataOffset, dataOffset + b.length, b);

  return result;
}

// **************************************************************************
// Misc. Utility Functions
// **************************************************************************

/// Retorna o número de bits necessários para representar o número.
int numBits(BigInt n) {
  return n.bitLength;
}

/// Retorna o número de bytes necessários para representar o número.
int numBytes(BigInt n) {
  if (n == BigInt.zero) return 1;
  return (n.bitLength + 7) ~/ 8;
}

// **************************************************************************
// Big Number Math
// **************************************************************************

/// Gera um número aleatório BigInt no intervalo [low, high).
BigInt getRandomNumber(BigInt low, BigInt high) {
  assert(low < high);

  BigInt range = high - low;
  int bits = range.bitLength;
  int bytes = (bits + 7) ~/ 8;

  BigInt result;
  do {
    Uint8List randomBytes = getRandomBytes(bytes);
    result = _bytesToBigInt(randomBytes); // Big-endian unsigned

    // Garante que o número gerado não exceda o range (importante para distribuição uniforme)
    // Se o número aleatório gerado (result) for maior ou igual ao tamanho do range,
    // descarte-o e gere outro. Isso evita bias.
    // Ex: range = 10 (0-9), bits = 4. Se gerar 1111 (15), não é válido.
  } while (result >= range);

  return low + result;
}

/// Máximo Divisor Comum.
BigInt gcd(BigInt a, BigInt b) {
  return a.gcd(b);
}

/// Mínimo Múltiplo Comum.
BigInt lcm(BigInt a, BigInt b) {
  if (a == BigInt.zero || b == BigInt.zero) return BigInt.zero;
  return (a * b).abs() ~/ a.gcd(b);
}

/// Retorna o inverso de a mod b, zero se não existir.
BigInt invMod(BigInt a, BigInt b) {
  try {
    // modInverse lança RangeError se a == 0 ou se o inverso não existir (gcd != 1)
    if (a == BigInt.zero || b <= BigInt.zero) return BigInt.zero;
    if (a.gcd(b) != BigInt.one) return BigInt.zero; // Inverso não existe
    return a.modInverse(b);
  } catch (e) {
    // Captura especificamente RangeError se gcd != 1
    if (e is RangeError) {
      return BigInt.zero;
    }
    // Relança outros erros inesperados
    rethrow;
  }
}

/// Calcula (base^power) % modulus.
BigInt powMod(BigInt base, BigInt power, BigInt modulus) {
  return base.modPow(power, modulus);
}

/// Divisão inteira com arredondamento para cima.
BigInt divceil(BigInt dividend, BigInt divisor) {
  if (divisor == BigInt.zero) throw ArgumentError("Division by zero");
  // Equivalente a (dividend + divisor - 1) / divisor para inteiros positivos
  // Cuidado com negativos se for necessário suportar
  if (dividend == BigInt.zero) return BigInt.zero;
  final one = BigInt.one;
  return (dividend + divisor - one) ~/ divisor;
}

// Pré-calcula um crivo dos primos < 1000:
List<int> makeSieve(int n) {
  if (n < 2) return [];
  List<int?> sieve = List<int?>.generate(n, (i) => i); // Usa null para marcar
  sieve[0] = null;
  sieve[1] = null;

  int limit = math.sqrt(n).toInt();
  for (int count = 2; count <= limit; count++) {
    if (sieve[count] == null) {
      continue;
    }
    // Marca múltiplos
    for (int x = count * 2; x < n; x += count) {
      sieve[x] = null;
    }
  }
  // Filtra os não-nulos e converte para List<int>
  return sieve.whereType<int>().toList();
}

// Crivo padrão para isPrime
final List<int> _defaultSieve = makeSieve(1000);

/// Testa se n é primo usando divisão por tentativa e Miller-Rabin.
bool isPrime(BigInt n,
    {int iterations = 5, bool display = false, List<int>? sieve}) {
  sieve ??= _defaultSieve;

  if (n <= BigInt.one) return false;
  if (n <= BigInt.from(3)) return true; // 2 e 3 são primos
  if (n.isEven) return false; // Pares maiores que 2 não são primos

  // Divisão por tentativa com o crivo
  for (int x in sieve) {
    BigInt bx = BigInt.from(x);
    if (bx >= n) break; // Se o primo do crivo for >= n, paramos
    if (n % bx == BigInt.zero) return false; // Divisível, não é primo
  }

  // Passou pela divisão por tentativa, prossiga para Miller-Rabin
  if (display) print("*"); // Equivalente a print("*", end=' ')

  // Calcula s, t para Miller-Rabin: n-1 = 2^t * s, onde s é ímpar
  BigInt s = n - BigInt.one;
  int t = 0;
  while (s.isEven) {
    s = s >> 1; // Divisão rápida por 2
    t++;
  }

  // Repete Miller-Rabin 'iterations' vezes
  for (int count = 0; count < iterations; count++) {
    // Escolhe uma base 'a' aleatória entre [2, n-2]
    // A primeira iteração usa a=2 para velocidade (como no original)
    BigInt a = (count == 0)
        ? BigInt.two
        : getRandomNumber(
            BigInt.two, n - BigInt.one); // Gera a no intervalo [2, n-2]

    BigInt v = powMod(a, s, n); // v = a^s mod n

    if (v == BigInt.one || v == n - BigInt.one) {
      continue; // Provavelmente primo, tenta próxima iteração
    }

    bool possiblePrime = false;
    for (int i = 1; i < t; i++) {
      // Loop de 1 até t-1
      v = powMod(v, BigInt.two, n); // v = v^2 mod n
      if (v == n - BigInt.one) {
        possiblePrime = true; // Condição de Miller-Rabin satisfeita
        break;
      }
      if (v == BigInt.one) {
        return false; // Fator não trivial encontrado (raiz quadrada de 1 mod n)
      }
    }

    if (!possiblePrime) {
      return false; // Falhou no teste de Miller-Rabin para esta base 'a'
    }
  }

  return true; // Passou em todas as iterações, provavelmente primo
}

/// Gera um número primo aleatório de 'bits' de tamanho.
/// O número terá 'bits' bits (maior que (2^(bits-1) * 3 ) / 2 e menor que 2^bits).
BigInt getRandomPrime(int bits, {bool display = false}) {
  assert(bits >= 10);

  // Garante que os 2 MSBs (bits mais significativos) sejam 1.
  // low = floor(1.5 * 2^(bits-1)) = floor(3 * 2^(bits-2))
  BigInt low = (BigInt.from(3) << (bits - 2));
  // high = 2^bits
  BigInt high = BigInt.one << bits;

  while (true) {
    if (display) print(".");

    // Gera um candidato aleatório no intervalo [low, high)
    BigInt candP = getRandomNumber(low, high);

    // Garante que seja ímpar
    if (candP.isEven) {
      candP += BigInt.one;
      // Se candP se tornar >= high após adicionar 1, precisa gerar um novo número.
      // Isso é raro, mas possível. Uma forma simples é continuar o loop.
      if (candP >= high) continue;
    }

    // Testa a primalidade com um número razoável de iterações
    // (mais iterações aumentam a confiança)
    if (isPrime(candP, iterations: 15, display: display)) {
      return candP;
    }
  }
}

/// Gera um "safe prime" aleatório p com 'bits' de tamanho,
/// tal que p é primo e (p-1)/2 também é primo (q).
BigInt getRandomSafePrime(int bits, {bool display = false}) {
  assert(bits >= 10);

  // Gera q no intervalo apropriado para que p = 2q+1 tenha 'bits' bits.
  // Se p ~ 2^bits, então q ~ 2^(bits-1).
  // Usamos um intervalo semelhante a getRandomPrime para q.
  BigInt qLow = (BigInt.from(3) << (bits - 3)); // Para q ~ 2^(bits-1)
  BigInt qHigh = BigInt.one << (bits - 1);

  while (true) {
    if (display) print(".");

    // Gera um candidato para q
    BigInt q = getRandomNumber(qLow, qHigh);

    // Garante que q seja ímpar (necessário para p=2q+1 ser primo > 3)
    if (q.isEven) {
      q += BigInt.one;
      if (q >= qHigh) continue;
    }

    // Testa a primalidade de q primeiro (mais rápido falhar aqui)
    // Usamos menos iterações para q, e mais para p se q for primo
    if (isPrime(q, iterations: 5, display: display)) {
      BigInt p = (q * BigInt.two) + BigInt.one;

      // Verifica se p tem o número de bits desejado.
      // Se q estava perto do limite superior, p pode ter bits+1 bits.
      if (p.bitLength != bits) {
        continue; // Tenta um novo q
      }

      // Testa a primalidade de p com mais rigor
      if (isPrime(p, iterations: 15, display: display)) {
        // Re-testar q com mais rigor por segurança (opcional, mas bom)
        if (isPrime(q, iterations: 15, display: display)) {
          return p; // Encontrou um safe prime!
        }
      }
    }
  }
}
