import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/brainpoolp160r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp160t1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp192r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp192t1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp224r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp224t1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp256r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp256t1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp320r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp320t1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp384r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp384t1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp512r1.dart';
import 'package:pointycastle/ecc/curves/brainpoolp512t1.dart';
import 'package:pointycastle/ecc/curves/gostr3410_2001_cryptopro_a.dart';
import 'package:pointycastle/ecc/curves/gostr3410_2001_cryptopro_b.dart';
import 'package:pointycastle/ecc/curves/gostr3410_2001_cryptopro_c.dart';
import 'package:pointycastle/ecc/curves/gostr3410_2001_cryptopro_xcha.dart';
import 'package:pointycastle/ecc/curves/gostr3410_2001_cryptopro_xchb.dart';
import 'package:pointycastle/ecc/curves/prime192v1.dart';
import 'package:pointycastle/ecc/curves/prime192v2.dart';
import 'package:pointycastle/ecc/curves/prime192v3.dart';
import 'package:pointycastle/ecc/curves/prime239v1.dart';
import 'package:pointycastle/ecc/curves/prime239v2.dart';
import 'package:pointycastle/ecc/curves/prime239v3.dart';
import 'package:pointycastle/ecc/curves/prime256v1.dart';
import 'package:pointycastle/ecc/curves/secp112r1.dart';
import 'package:pointycastle/ecc/curves/secp112r2.dart';
import 'package:pointycastle/ecc/curves/secp128r1.dart';
import 'package:pointycastle/ecc/curves/secp128r2.dart';
import 'package:pointycastle/ecc/curves/secp160k1.dart';
import 'package:pointycastle/ecc/curves/secp160r1.dart';
import 'package:pointycastle/ecc/curves/secp160r2.dart';
import 'package:pointycastle/ecc/curves/secp192k1.dart';
import 'package:pointycastle/ecc/curves/secp192r1.dart';
import 'package:pointycastle/ecc/curves/secp224k1.dart';
import 'package:pointycastle/ecc/curves/secp224r1.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';
import 'package:pointycastle/ecc/curves/secp256r1.dart';
import 'package:pointycastle/ecc/curves/secp384r1.dart';
import 'package:pointycastle/ecc/curves/secp521r1.dart';

/// Mapeia nomes de curvas (em minúsculas) para funções que fornecem
/// ECDomainParameters do PointyCastle.
final Map<String, ECDomainParameters Function()> _registroCurvas = {
  // --- Curvas SECP (NIST/SECG) ---
  'secp112r1': () => ECCurve_secp112r1(),
  'secp112r2': () => ECCurve_secp112r2(),
  'secp128r1': () => ECCurve_secp128r1(),
  'secp128r2': () => ECCurve_secp128r2(),
  'secp160k1': () => ECCurve_secp160k1(),
  'secp160r1': () => ECCurve_secp160r1(),
  'secp160r2': () => ECCurve_secp160r2(),
  'secp192k1': () => ECCurve_secp192k1(),
  'secp192r1': () =>
      ECCurve_secp192r1(), // Também conhecida como prime192v1, nistp192
  'secp224k1': () => ECCurve_secp224k1(),
  'secp224r1': () => ECCurve_secp224r1(), // Também conhecida como nistp224
  'secp256k1': () => ECCurve_secp256k1(), // Usada pelo Bitcoin
  'secp256r1': () =>
      ECCurve_secp256r1(), // Também conhecida como prime256v1, nistp256
  'secp384r1': () => ECCurve_secp384r1(), // Também conhecida como nistp384
  'secp521r1': () => ECCurve_secp521r1(), // Também conhecida como nistp521
  'nistp256': () => ECCurve_secp256r1(),
  'nist256p': () => ECCurve_secp256r1(),
  'nistp384': () => ECCurve_secp384r1(),
  'nist384p': () => ECCurve_secp384r1(),
  'nistp521': () => ECCurve_secp521r1(),
  'nist521p': () => ECCurve_secp521r1(),

  // --- Curvas Prime (algumas são aliases para secp) ---
  'prime192v1': () => ECCurve_prime192v1(), // Geralmente == secp192r1
  'prime192v2': () => ECCurve_prime192v2(),
  'prime192v3': () => ECCurve_prime192v3(),
  'prime239v1': () => ECCurve_prime239v1(),
  'prime239v2': () => ECCurve_prime239v2(),
  'prime239v3': () => ECCurve_prime239v3(),
  'prime256v1': () => ECCurve_prime256v1(), // Geralmente == secp256r1

  // --- Curvas Brainpool (r = random, t = twisted) ---
  'brainpoolp160r1': () => ECCurve_brainpoolp160r1(),
  'brainpoolp160t1': () => ECCurve_brainpoolp160t1(),
  'brainpoolp192r1': () => ECCurve_brainpoolp192r1(),
  'brainpoolp192t1': () => ECCurve_brainpoolp192t1(),
  'brainpoolp224r1': () => ECCurve_brainpoolp224r1(),
  'brainpoolp224t1': () => ECCurve_brainpoolp224t1(),
  'brainpoolp256r1': () => ECCurve_brainpoolp256r1(),
  'brainpoolp256t1': () => ECCurve_brainpoolp256t1(),
  'brainpoolp320r1': () => ECCurve_brainpoolp320r1(),
  'brainpoolp320t1': () => ECCurve_brainpoolp320t1(),
  'brainpoolp384r1': () => ECCurve_brainpoolp384r1(),
  'brainpoolp384t1': () => ECCurve_brainpoolp384t1(),
  'brainpoolp512r1': () => ECCurve_brainpoolp512r1(),
  'brainpoolp512t1': () => ECCurve_brainpoolp512t1(),

  // Aliases TLS 1.3 para Brainpool
  'brainpoolp256r1tls13': () => ECCurve_brainpoolp256r1(),
  'brainpoolp384r1tls13': () => ECCurve_brainpoolp384r1(),
  'brainpoolp512r1tls13': () => ECCurve_brainpoolp512r1(),

  // --- Curvas GOST R 34.10-2001 ---
  // Os nomes exatos aqui podem variar bastante, usando nomes derivados dos arquivos:
  'gostr3410_2001_cryptopro_a': () => ECCurve_gostr3410_2001_cryptopro_a(),
  'gostr3410_2001_cryptopro_b': () => ECCurve_gostr3410_2001_cryptopro_b(),
  'gostr3410_2001_cryptopro_c': () => ECCurve_gostr3410_2001_cryptopro_c(),
  'gostr3410_2001_cryptopro_xcha': () =>
      ECCurve_gostr3410_2001_cryptopro_xcha(),
  'gostr3410_2001_cryptopro_xchb': () =>
      ECCurve_gostr3410_2001_cryptopro_xchb(),
};

/// Retorna os parâmetros de domínio da curva elíptica (ECDomainParameters do PointyCastle)
/// identificados pelo [nomeCurva].
///
/// Lança um [ArgumentError] se o nome da curva for desconhecido ou não suportado.
/// Requer o pacote `package:pointycastle`.
ECDomainParameters getCurveByName(String nomeCurva) {
  // Normaliza o nome para minúsculas para consistência
  final String nomeNormalizado = nomeCurva.toLowerCase();
  final curvaFunc = _registroCurvas[nomeNormalizado];

  if (curvaFunc != null) {
    try {
      return curvaFunc();
    } catch (e) {
      // Captura erros potenciais durante a criação do objeto da curva
      print("AVISO: Possível erro ao instanciar a curva '$nomeCurva' "
          "com a função mapeada. Verifique o nome exato em pointycastle. Erro: $e");
      throw StateError("Erro ao criar a curva '$nomeCurva': $e");
    }
  } else {
    // Se não encontrou no mapa, lança o erro diretamente.
    // O bloco 'if (!eccTodasCurvasDisponiveis ...)' foi removido pois a flag não existe mais
    // e o mapa agora contém todas as curvas explicitamente.
    throw ArgumentError(
        "Curva com nome '$nomeCurva' (normalizado: '$nomeNormalizado') "
        "desconhecida ou não suportada por este mapeamento.");
  }
}

/// Retorna o tamanho em bytes necessário para uma coordenada de um ponto na curva.
///
/// Aceita um objeto [ECPoint], [ECCurve], ou [ECDomainParameters] do `package:pointycastle`.
/// Lança um [ArgumentError] se o tipo de entrada não for reconhecido ou se
/// o ponto não tiver uma curva associada.
int getPointByteSize(dynamic pontoOuCurvaOuParams) {
  ECCurve? curva; // A curva elíptica base

  if (pontoOuCurvaOuParams is ECPoint) {
    // Atribui a uma variável local primeiro
    final ECCurve? pointCurve = pontoOuCurvaOuParams.curve;
    // Verifica a variável local
    if (pointCurve == null) {
      // Verifica se a curva DO PONTO é nula
      throw ArgumentError("O ECPoint de entrada não tem uma curva associada.");
    }
    // Se não for nulo, atribui à variável 'curva' principal
    curva = pointCurve;
  } else if (pontoOuCurvaOuParams is ECCurve) {
    curva = pontoOuCurvaOuParams;
  } else if (pontoOuCurvaOuParams is ECDomainParameters) {
    curva = pontoOuCurvaOuParams.curve;
    // Adicionar uma verificação aqui se .curve pudesse ser nulo em ECDomainParameters
    // if (curva == null) {
    //   throw ArgumentError("Os parâmetros de domínio de entrada não têm uma curva associada.");
    // }
  } else {
    throw ArgumentError(
        "A entrada deve ser um ECPoint, ECCurve, ou ECDomainParameters do pointycastle.");
  }

  // Neste ponto, 'curva' foi promovido para não-nulo (ECCurve)
  // devido às verificações e/ou atribuições acima.
  final int tamanhoCampoBits = curva.fieldSize;
  return (tamanhoCampoBits + 7) ~/ 8; // Divisão inteira
}
