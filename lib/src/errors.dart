import 'constants.dart'; // Importando as definições de AlertDescription e AlertLevel

// PORT STATUS: Error handling fully integrated with:
// - recordlayer.dart/tls_record_layer.dart for protocol exceptions
// - Alert sending/receiving in tlsconnection.dart
// - All TLS error types ported from tlslite-ng

// --- Base Exceptions ---

/// Metaclasse para exceções TLS Lite.
///
/// Procure por [TLSError] para exceções que devem ser
/// capturadas pelos consumidores do tlslite.
class BaseTLSException implements Exception {
  final String? message;
  BaseTLSException([this.message]);

  @override
  String toString() {
    final className = runtimeType.toString();
    return message == null ? className : '$className: $message';
  }
}

/// Classe base para exceções lançadas durante a criptografia.
class EncryptionError extends BaseTLSException {
  EncryptionError([String? message]) : super(message);
}

// --- TLS Errors (Main Hierarchy) ---

/// Classe base para todas as exceções TLS Lite.
class TLSError extends BaseTLSException {
  TLSError([String? message]) : super(message);
  // O método toString herdado de BaseTLSException já replica
  // razoavelmente o comportamento de repr(self) do Python.
}

/// Uma tentativa foi feita para usar a conexão depois que ela foi fechada.
/// Nota: No Python, isso também herda de socket.error. Dart não suporta
/// herança múltipla, então aqui estende apenas TLSError.
class TLSClosedConnectionError extends TLSError {
  TLSClosedConnectionError([String? message]) : super(message);
}

/// O socket foi fechado sem um desligamento TLS adequado.
///
/// A especificação TLS exige que um alerta de algum tipo
/// seja enviado antes que o socket subjacente seja fechado. Se o socket
/// for fechado sem isso, pode significar que um invasor está tentando
/// truncar a conexão. Também pode significar uma implementação TLS
/// com comportamento inadequado ou uma falha de rede aleatória.
class TLSAbruptCloseError extends TLSError {
  TLSAbruptCloseError([String? message]) : super(message);
}

// --- TLS Alerts ---

/// Um alerta TLS foi sinalizado.
abstract class TLSAlert extends TLSError {
  /// Definido para uma das constantes em [AlertDescription].
  final int description; // Agora é int, conforme a definição da classe

  /// Definido para uma das constantes em [AlertLevel].
  final int level; // Agora é int, conforme a definição da classe

  TLSAlert(this.description, this.level, [String? message]) : super(message);
}

/// Um alerta TLS foi sinalizado pela implementação local.
class TLSLocalAlert extends TLSAlert {
  /// Descrição do que deu errado.
  final String? detailedMessage;

  /// Cria um alerta local.
  /// [description] deve ser uma das constantes de [AlertDescription].
  /// [level] deve ser uma das constantes de [AlertLevel].
  TLSLocalAlert(int description, int level, {this.detailedMessage})
      : super(description, level); // Recebe int

  @override
  String toString() {
    // Usa o método estático da classe AlertDescription definida em constants.dart
    final alertStr = AlertDescription.toStr(description);
    if (detailedMessage != null) {
      return '$alertStr: $detailedMessage';
    } else {
      return alertStr;
    }
  }
}

/// Um alerta TLS foi sinalizado pela implementação remota.
class TLSRemoteAlert extends TLSAlert {
  /// Cria um alerta remoto.
  /// [description] deve ser uma das constantes de [AlertDescription].
  /// [level] deve ser uma das constantes de [AlertLevel].
  TLSRemoteAlert(int description, int level)
      : super(description, level); // Recebe int

  @override
  String toString() {
    // Usa o método estático da classe AlertDescription definida em constants.dart
    return AlertDescription.toStr(description);
  }
}

// --- TLS Authentication Errors ---

/// O handshake foi bem-sucedido, mas a autenticação da outra parte
/// foi inadequada.
///
/// Esta exceção só será lançada quando um
/// `Checker` (equivalente em Dart) tiver sido passado para uma função de handshake.
/// O Checker será invocado assim que o handshake for concluído, e se
/// o Checker objetar como a outra parte se autenticou, uma
/// subclasse desta exceção será lançada.
class TLSAuthenticationError extends TLSError {
  TLSAuthenticationError([String? message]) : super(message);
}

/// O Checker esperava que a outra parte se autenticasse com uma
/// cadeia de certificados, mas isso não ocorreu.
class TLSNoAuthenticationError extends TLSAuthenticationError {
  TLSNoAuthenticationError([String? message]) : super(message);
}

/// O Checker esperava que a outra parte se autenticasse com um
/// tipo diferente de cadeia de certificados.
class TLSAuthenticationTypeError extends TLSAuthenticationError {
  TLSAuthenticationTypeError([String? message]) : super(message);
}

/// O Checker esperava que a outra parte se autenticasse com uma
/// cadeia de certificados que correspondesse a uma impressão digital diferente.
class TLSFingerprintError extends TLSAuthenticationError {
  TLSFingerprintError([String? message]) : super(message);
}

/// O Checker esperava que a outra parte se autenticasse com uma
/// cadeia de certificados que tivesse uma autorização diferente.
class TLSAuthorizationError extends TLSAuthenticationError {
  TLSAuthorizationError([String? message]) : super(message);
}

/// O Checker determinou que a cadeia de certificados da outra parte
/// é inválida.
class TLSValidationError extends TLSAuthenticationError {
  /// Contém informações sobre esta falha de validação
  final dynamic info; // Pode ser Map<String, dynamic>? se a estrutura for conhecida

  TLSValidationError(String msg, {this.info}) : super(msg);

  @override
  String toString() {
    final baseStr = super.toString();
    return info == null ? baseStr : '$baseStr (Info: $info)';
  }
}

// --- Other TLS Errors ---

/// A outra parte respondeu incorretamente a uma falha induzida.
///
/// Esta exceção ocorrerá apenas durante testes de falha, quando uma
/// variável de falha (equivalente em Dart) de `TLSConnection` (equivalente em Dart)
/// for definida para induzir algum tipo de comportamento defeituoso,
/// e a outra parte não responder apropriadamente.
class TLSFaultError extends TLSError {
  TLSFaultError([String? message]) : super(message);
}

/// A implementação não suporta as capacidades solicitadas (ou necessárias).
class TLSUnsupportedError extends TLSError {
  TLSUnsupportedError([String? message]) : super(message);
}

/// O estado interno do objeto é inesperado ou inválido.
///
/// Causado pelo uso incorreto da API.
class TLSInternalError extends TLSError {
  TLSInternalError([String? message]) : super(message);
}

// --- TLS Protocol Exceptions (Internal Handling) ---

/// Exceções usadas internamente para lidar com erros em mensagens recebidas.
class TLSProtocolException extends BaseTLSException {
   TLSProtocolException([String? message]) : super(message);
}

/// Os parâmetros especificados na mensagem estavam incorretos ou inválidos.
class TLSIllegalParameterException extends TLSProtocolException {
   TLSIllegalParameterException([String? message]) : super(message);
}

/// A codificação da mensagem recebida não corresponde à especificação.
class TLSDecodeError extends TLSProtocolException {
   TLSDecodeError([String? message]) : super(message);
}

/// A mensagem recebida foi inesperada ou a análise do Inner Plaintext
/// falhou.
class TLSUnexpectedMessage extends TLSProtocolException {
   TLSUnexpectedMessage([String? message]) : super(message);
}

/// O tamanho do registro recebido era muito grande.
class TLSRecordOverflow extends TLSProtocolException {
   TLSRecordOverflow([String? message]) : super(message);
}

/// A descriptografia dos dados não foi bem-sucedida.
class TLSDecryptionFailed extends TLSProtocolException {
   TLSDecryptionFailed([String? message]) : super(message);
}

/// MAC inválido (ou preenchimento no caso de mac-then-encrypt).
class TLSBadRecordMAC extends TLSProtocolException {
   TLSBadRecordMAC([String? message]) : super(message);
}

/// Os parâmetros selecionados pelo usuário são muito fracos.
class TLSInsufficientSecurity extends TLSProtocolException {
   TLSInsufficientSecurity([String? message]) : super(message);
}

/// A identidade PSK ou SRP é desconhecida.
class TLSUnknownPSKIdentity extends TLSProtocolException {
   TLSUnknownPSKIdentity([String? message]) : super(message);
}

/// Não foi possível encontrar um conjunto aceitável de parâmetros de handshake.
class TLSHandshakeFailure extends TLSProtocolException {
   TLSHandshakeFailure([String? message]) : super(message);
}

// --- Encryption Errors (Subtypes) ---

/// O maskLen passado para a função é muito alto.
class MaskTooLongError extends EncryptionError {
  MaskTooLongError([String? message]) : super(message);
}

/// A mensagem passada para a função é muito longa.
class MessageTooLongError extends EncryptionError {
  MessageTooLongError([String? message]) : super(message);
}

/// Um erro apareceu durante a codificação.
class EncodingError extends EncryptionError {
  EncodingError([String? message]) : super(message);
}

/// A função de verificação encontrou uma assinatura inválida.
class InvalidSignature extends EncryptionError {
  InvalidSignature([String? message]) : super(message);
}

/// Tipo de algoritmo RSA desconhecido passado.
class UnknownRSAType extends EncryptionError {
  UnknownRSAType([String? message]) : super(message);
}
