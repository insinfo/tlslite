import 'dart:convert'; // Para ascii
import 'dart:typed_data'; // Para Uint8List

/// Verifica se o parâmetro é um nome de host (hostname) DNS válido.
///
/// Segue regras comuns de validação, incluindo RFC 1035/1123 para caracteres e estrutura.
///
/// [hostnameInput]: A String ou Uint8List (assumido como ASCII) para verificar.
/// Retorna `true` se for um nome de host válido, `false` caso contrário.
bool isValidHostname(Object hostnameInput) {
  String hostname;

  // 1. Trata o tipo de entrada e decodifica se for Uint8List (ASCII)
  if (hostnameInput is String) {
    hostname = hostnameInput;
  } else if (hostnameInput is Uint8List) {
    try {
      // Tenta decodificar como ASCII estrito
      hostname = ascii.decode(hostnameInput, allowInvalid: false);
    } on FormatException {
      return false; // Falha na decodificação ASCII
    }
  } else {
    // Tipo de entrada inválido
    return false;
    // Alternativamente, poderia lançar um ArgumentError:
    // throw ArgumentError("Input must be a String or Uint8List representing ASCII");
  }

  // Hostname não pode ser vazio após a decodificação
  if (hostname.isEmpty) {
    return false;
  }

  // 2. Remove um ponto final, se presente
  // Nomes de host FQDN podem terminar com '.', representando a raiz.
  // Para validação de rótulos (labels), removemos esse ponto final.
  if (hostname.endsWith('.')) {
    hostname = hostname.substring(0, hostname.length - 1);
    // Se o hostname era apenas '.', agora está vazio, o que é inválido
    if (hostname.isEmpty) {
      return false;
    }
  }

  // 3. Verifica o comprimento total (RFC 1035)
  // O comprimento máximo total de um nome de host na representação
  // de texto (com pontos) é 253 caracteres (excluindo o ponto final da raiz).
  if (hostname.length > 253) {
    return false;
  }

  // 4. Verifica se é totalmente numérico com pontos (para evitar confusão com IP)
  // Esta não é uma regra estrita de RFC, mas uma prática comum.
  final numericRegex = RegExp(r'^[\d.]+$');
  if (numericRegex.hasMatch(hostname)) {
    return false;
  }

  // 5. Valida cada rótulo (label) individualmente
  final labels = hostname.split('.');

  // Não pode haver rótulos vazios (ex: "host..name")
  if (labels.any((label) => label.isEmpty)) {
    return false;
  }

  // Regex para caracteres permitidos em cada rótulo (RFC 1123 amplia RFC 952/1035)
  // Permite letras (a-z, A-Z), números (0-9) e hífen (-)
  // Comprimento de 1 a 63 caracteres.
  // Não verifica início/fim com hífen aqui; faremos isso separadamente.
  final labelRegex = RegExp(r'^[a-zA-Z0-9-]{1,63}$');

  // Verifica cada rótulo
  return labels.every((label) {
    // Verifica caracteres e comprimento com a regex
    if (!labelRegex.hasMatch(label)) {
      return false;
    }
    // Verifica se o rótulo começa ou termina com hífen (RFC 1123)
    if (label.startsWith('-') || label.endsWith('-')) {
      return false;
    }
    // Se passou em todas as verificações para este rótulo
    return true;
  });
}
