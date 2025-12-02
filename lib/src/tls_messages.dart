import 'dart:typed_data';

import 'constants.dart' as tls_constants;
import 'utils/codec.dart';
import 'utils/cryptomath.dart';
import 'net/security/pure_dart/tls_extensions.dart';
import 'tls_protocol.dart';


/// Content types alinhados com TLS 1.2/1.3.
enum TlsContentType {
  changeCipherSpec(tls_constants.ContentType.change_cipher_spec),
  alert(tls_constants.ContentType.alert),
  handshake(tls_constants.ContentType.handshake),
  applicationData(tls_constants.ContentType.application_data),
  heartbeat(tls_constants.ContentType.heartbeat),
  unknown(-1);

  const TlsContentType(this.code);
  final int code;

  static TlsContentType fromByte(int value) {
    for (final type in TlsContentType.values) {
      if (type.code == value) {
        return type;
      }
    }
    return TlsContentType.unknown;
  }

  String get name => this == TlsContentType.unknown
      ? 'unknown($code)'
      : tls_constants.ContentType.toStr(code);
}

enum TlsAlertLevel {
  warning(tls_constants.AlertLevel.warning),
  fatal(tls_constants.AlertLevel.fatal),
  unknown(-1);

  const TlsAlertLevel(this.code);
  final int code;

  static TlsAlertLevel fromByte(int value) {
    for (final level in TlsAlertLevel.values) {
      if (level.code == value) {
        return level;
      }
    }
    return TlsAlertLevel.unknown;
  }

  String get name => this == TlsAlertLevel.unknown
      ? 'unknown($code)'
      : tls_constants.AlertLevel.toStr(code);
}

enum TlsAlertDescription {
  closeNotify(tls_constants.AlertDescription.close_notify),
  unexpectedMessage(tls_constants.AlertDescription.unexpected_message),
  handshakeFailure(tls_constants.AlertDescription.handshake_failure),
  decodeError(tls_constants.AlertDescription.decode_error),
  protocolVersion(tls_constants.AlertDescription.protocol_version),
  insufficientSecurity(tls_constants.AlertDescription.insufficient_security),
  internalError(tls_constants.AlertDescription.internal_error),
  noApplicationProtocol(tls_constants.AlertDescription.no_application_protocol),
  unknown(-1);

  const TlsAlertDescription(this.code);
  final int code;

  static TlsAlertDescription fromByte(int value) {
    for (final description in TlsAlertDescription.values) {
      if (description.code == value) {
        return description;
      }
    }
    return TlsAlertDescription.unknown;
  }

  String get name => this == TlsAlertDescription.unknown
      ? 'unknown($code)'
      : tls_constants.AlertDescription.toStr(code);
}

enum TlsHandshakeType {
  helloRequest(tls_constants.HandshakeType.hello_request),
  clientHello(tls_constants.HandshakeType.client_hello),
  serverHello(tls_constants.HandshakeType.server_hello),
  newSessionTicket(tls_constants.HandshakeType.new_session_ticket),
  helloRetryRequest(tls_constants.HandshakeType.hello_retry_request),
  encryptedExtensions(tls_constants.HandshakeType.encrypted_extensions),
  certificate(tls_constants.HandshakeType.certificate),
  serverKeyExchange(tls_constants.HandshakeType.server_key_exchange),
  certificateRequest(tls_constants.HandshakeType.certificate_request),
  serverHelloDone(tls_constants.HandshakeType.server_hello_done),
  certificateVerify(tls_constants.HandshakeType.certificate_verify),
  clientKeyExchange(tls_constants.HandshakeType.client_key_exchange),
  finished(tls_constants.HandshakeType.finished),
  certificateStatus(tls_constants.HandshakeType.certificate_status),
  keyUpdate(tls_constants.HandshakeType.key_update),
  nextProtocol(tls_constants.HandshakeType.next_protocol),
  unknown(-1);

  const TlsHandshakeType(this.code);
  final int code;

  static TlsHandshakeType fromByte(int value) {
    for (final type in TlsHandshakeType.values) {
      if (type.code == value) {
        return type;
      }
    }
    return TlsHandshakeType.unknown;
  }

  String get name => this == TlsHandshakeType.unknown
      ? 'unknown($code)'
      : tls_constants.HandshakeType.toStr(code);
}

class TlsRecordHeader {
  TlsRecordHeader({
    required this.contentType,
    required this.protocolVersion,
    required this.fragmentLength,
  });

  static const int serializedLength = 5;

  final TlsContentType contentType;
  final TlsProtocolVersion protocolVersion;
  final int fragmentLength;

  Uint8List serialize() {
    final writer = Writer();
    writer.add(contentType.code, 1);
    writer.add(protocolVersion.major, 1);
    writer.add(protocolVersion.minor, 1);
    writer.add(fragmentLength, 2);
    return writer.bytes;
  }

  factory TlsRecordHeader.fromBytes(Uint8List bytes) {
    if (bytes.length != serializedLength) {
      throw ArgumentError('TLS record header precisa conter 5 bytes');
    }
    final parser = Parser(bytes);
    final typeByte = parser.get(1);
    final versionMajor = parser.get(1);
    final versionMinor = parser.get(1);
    final length = parser.get(2);
    return TlsRecordHeader(
      contentType: TlsContentType.fromByte(typeByte),
      protocolVersion: TlsProtocolVersion(versionMajor, versionMinor),
      fragmentLength: length,
    );
  }
}

class TlsPlaintext {
  TlsPlaintext({required this.header, required Uint8List fragment})
      : fragment = Uint8List.fromList(fragment) {
    if (header.fragmentLength != this.fragment.length) {
      throw ArgumentError(
        'Comprimento do fragmento (${this.fragment.length}) '
        'não bate com o header (${header.fragmentLength})',
      );
    }
  }

  final TlsRecordHeader header;
  final Uint8List fragment;

  Uint8List serialize() {
    final builder = BytesBuilder();
    builder.add(header.serialize());
    builder.add(fragment);
    return builder.toBytes();
  }
}

/// Estrutura base para mensagens TLS em Dart puro.
abstract class TlsMessage {
  const TlsMessage(this.contentType);

  final TlsContentType contentType;

  Uint8List serialize();
}

class TlsAlert extends TlsMessage {
  TlsAlert({
    required this.level,
    required this.description,
  }) : super(TlsContentType.alert);

  final TlsAlertLevel level;
  final TlsAlertDescription description;

  static const int serializedLength = 2;

  static TlsAlert parse(Uint8List bytes) {
    if (bytes.length < serializedLength) {
      throw DecodeError('Registro de alerta truncado (${bytes.length} < 2)');
    }
    final parser = Parser(bytes);
    final level = TlsAlertLevel.fromByte(parser.get(1));
    final description = TlsAlertDescription.fromByte(parser.get(1));
    return TlsAlert(level: level, description: description);
  }

  @override
  Uint8List serialize() {
    final writer = Writer();
    writer.add(level.code, 1);
    writer.add(description.code, 1);
    return writer.bytes;
  }

  @override
  String toString() => 'Alert(${level.name}, ${description.name})';
}

abstract class TlsHandshakeMessage extends TlsMessage {
  const TlsHandshakeMessage(this.handshakeType)
      : super(TlsContentType.handshake);

  final TlsHandshakeType handshakeType;

  Uint8List serializeBody();

  @override
  Uint8List serialize() {
    final body = serializeBody();
    final writer = Writer();
    writer.add(handshakeType.code, 1);
    writer.add(body.length, 3);
    writer.addBytes(body);
    return writer.bytes;
  }

  static List<TlsHandshakeMessage> parseFragment(
    Uint8List fragment, {
    TlsProtocolVersion recordVersion = TlsProtocolVersion.tls12,
  }) {
    if (fragment.isEmpty) {
      return const <TlsHandshakeMessage>[];
    }
    final parser = Parser(fragment);
    final messages = <TlsHandshakeMessage>[];
    while (!parser.isDone) {
      if (parser.getRemainingLength() < 4) {
        throw DecodeError('Fragmento de handshake truncado');
      }
      final typeByte = parser.get(1);
      final length = parser.get(3);
      if (parser.getRemainingLength() < length) {
        throw DecodeError(
          'Fragmento de handshake espera $length bytes, '
          'restam apenas ${parser.getRemainingLength()}',
        );
      }
      final body = parser.getFixBytes(length);
      final type = TlsHandshakeType.fromByte(typeByte);
      messages.add(_parseTyped(type, body, recordVersion));
    }
    return messages;
  }

  static TlsHandshakeMessage _parseTyped(
    TlsHandshakeType type,
    Uint8List body,
    TlsProtocolVersion recordVersion,
  ) {
    switch (type) {
      case TlsHandshakeType.clientHello:
        return TlsClientHello.parseBody(body);
      case TlsHandshakeType.serverHello:
        return TlsServerHello.parseBody(body);
      case TlsHandshakeType.certificate:
        return TlsCertificate.parseBody(body, version: recordVersion);
      case TlsHandshakeType.certificateRequest:
        return TlsCertificateRequest.parseBody(body, version: recordVersion);
      case TlsHandshakeType.certificateVerify:
        return TlsCertificateVerify.parseBody(body, version: recordVersion);
      case TlsHandshakeType.finished:
        return TlsFinished.parseBody(body);
      case TlsHandshakeType.encryptedExtensions:
        return TlsEncryptedExtensions.parseBody(body);
      case TlsHandshakeType.newSessionTicket:
        return TlsNewSessionTicket.parseBody(body);
      case TlsHandshakeType.keyUpdate:
        return TlsKeyUpdate.parseBody(body);
      default:
        return RawTlsHandshakeMessage(type: type, body: body);
    }
  }
}

class RawTlsHandshakeMessage extends TlsHandshakeMessage {
  RawTlsHandshakeMessage({
    required TlsHandshakeType type,
    required Uint8List body,
  })  : _body = Uint8List.fromList(body),
        super(type);

  final Uint8List _body;

  @override
  Uint8List serializeBody() => Uint8List.fromList(_body);
}

class TlsClientHello extends TlsHandshakeMessage {
  TlsClientHello({
    required this.clientVersion,
    required Uint8List random,
    required Uint8List sessionId,
    required List<int> cipherSuites,
    required List<int> compressionMethods,
    TlsExtensionBlock? extensions,
    List<TlsProtocolVersion>? supportedVersions,
    List<String>? serverNames,
    List<String>? applicationProtocols,
    List<TlsKeyShareEntry>? keyShares,
    TlsStatusRequestExtension? statusRequest,
    List<int>? signatureAlgorithmsCert,
  })  : random = Uint8List.fromList(random),
        sessionId = Uint8List.fromList(sessionId),
        cipherSuites = List<int>.from(cipherSuites, growable: false),
        compressionMethods =
            List<int>.from(compressionMethods, growable: false),
        extensions = extensions,
        supportedVersions = List<TlsProtocolVersion>.unmodifiable(
          supportedVersions ??
              extensions
                  ?.first<TlsSupportedVersionsExtension>()
                  ?.supportedVersions ??
              const <TlsProtocolVersion>[],
        ),
        serverNames = List<String>.unmodifiable(
          serverNames ??
              extensions
                  ?.first<TlsServerNameExtension>()
                  ?.hostNames ??
              const <String>[],
        ),
        applicationProtocols = List<String>.unmodifiable(
          applicationProtocols ??
              extensions?.first<TlsAlpnExtension>()?.protocols ??
                  const <String>[],
        ),
        keyShares = List<TlsKeyShareEntry>.unmodifiable(
          keyShares ??
              extensions?.first<TlsKeyShareExtension>()?.clientShares ??
              const <TlsKeyShareEntry>[],
        ),
        signatureAlgorithmsCert = List<int>.unmodifiable(
          signatureAlgorithmsCert ??
              extensions
                      ?.first<TlsSignatureAlgorithmsCertExtension>()
                      ?.signatureSchemes ??
                  const <int>[],
        ),
        statusRequest =
            statusRequest ?? extensions?.first<TlsStatusRequestExtension>(),
        super(TlsHandshakeType.clientHello) {
    if (this.random.length != 32) {
      throw ArgumentError('ClientHello.random precisa de 32 bytes');
    }
  }

  final TlsProtocolVersion clientVersion;
  final Uint8List random;
  final Uint8List sessionId;
  final List<int> cipherSuites;
  final List<int> compressionMethods;
  final TlsExtensionBlock? extensions;
  final List<String> serverNames;
  final List<String> applicationProtocols;
  final List<TlsProtocolVersion> supportedVersions;
  final List<TlsKeyShareEntry> keyShares;
  final List<int> signatureAlgorithmsCert;
  final TlsStatusRequestExtension? statusRequest;

  static TlsClientHello parseBody(Uint8List body) {
    final parser = Parser(body);
    final version = TlsProtocolVersion.parse(parser);
    final random = parser.getFixBytes(32);
    final sessionIdLength = parser.get(1);
    final sessionId = parser.getFixBytes(sessionIdLength);
    final cipherSuitesLength = parser.get(2);
    if (cipherSuitesLength % 2 != 0) {
      throw DecodeError('Lista de cipher_suites com tamanho inválido');
    }
    final cipherSuites = <int>[];
    for (int i = 0; i < cipherSuitesLength ~/ 2; i++) {
      cipherSuites.add(parser.get(2));
    }
    final compressionMethodsLength = parser.get(1);
    final compressionMethods = <int>[];
    for (int i = 0; i < compressionMethodsLength; i++) {
      compressionMethods.add(parser.get(1));
    }
    TlsExtensionBlock? extensions;
    List<TlsProtocolVersion> supportedVersions = const <TlsProtocolVersion>[];
    List<String> serverNames = const <String>[];
    List<String> applicationProtocols = const <String>[];
    List<TlsKeyShareEntry> keyShares = const <TlsKeyShareEntry>[];
    List<int> signatureAlgorithmsCert = const <int>[];
    TlsStatusRequestExtension? statusRequest;
    if (!parser.isDone) {
      final extensionsLength = parser.get(2);
      final bytes = parser.getFixBytes(extensionsLength);
      extensions = TlsExtensionBlock.fromBytes(
        bytes,
        context: TlsExtensionContext.clientHello,
      );
      supportedVersions = extensions
              .first<TlsSupportedVersionsExtension>()
              ?.supportedVersions ??
          const <TlsProtocolVersion>[];
      serverNames =
          extensions.first<TlsServerNameExtension>()?.hostNames ?? const <String>[];
      applicationProtocols =
          extensions.first<TlsAlpnExtension>()?.protocols ?? const <String>[];
      keyShares =
          extensions.first<TlsKeyShareExtension>()?.clientShares ?? const <TlsKeyShareEntry>[];
      signatureAlgorithmsCert = extensions
              .first<TlsSignatureAlgorithmsCertExtension>()
              ?.signatureSchemes ??
          const <int>[];
      statusRequest = extensions.first<TlsStatusRequestExtension>();
    }
    if (!parser.isDone) {
      throw DecodeError('Sobrou payload após ClientHello');
    }
    return TlsClientHello(
      clientVersion: version,
      random: random,
      sessionId: sessionId,
      cipherSuites: cipherSuites,
      compressionMethods: compressionMethods,
      extensions: extensions,
      supportedVersions: supportedVersions,
      serverNames: serverNames,
      applicationProtocols: applicationProtocols,
      keyShares: keyShares,
      signatureAlgorithmsCert: signatureAlgorithmsCert,
      statusRequest: statusRequest,
    );
  }

  @override
  Uint8List serializeBody() {
    final writer = Writer();
    writer.add(clientVersion.major, 1);
    writer.add(clientVersion.minor, 1);
    writer.addBytes(random);
    writer.add(sessionId.length, 1);
    writer.addBytes(sessionId);
    writer.add(cipherSuites.length * 2, 2);
    for (final suite in cipherSuites) {
      writer.add(suite, 2);
    }
    writer.add(compressionMethods.length, 1);
    for (final method in compressionMethods) {
      writer.add(method, 1);
    }
    if (extensions != null && !extensions!.isEmpty) {
      final data = extensions!.serialize();
      writer.add(data.length, 2);
      writer.addBytes(data);
    }
    return writer.bytes;
  }
}

class TlsServerHello extends TlsHandshakeMessage {
  TlsServerHello({
    required this.serverVersion,
    required Uint8List random,
    required Uint8List sessionId,
    required this.cipherSuite,
    required this.compressionMethod,
    TlsExtensionBlock? extensions,
    TlsProtocolVersion? selectedSupportedVersion,
    List<String>? applicationProtocols,
    TlsKeyShareEntry? keyShare,
  })  : random = Uint8List.fromList(random),
        sessionId = Uint8List.fromList(sessionId),
        extensions = extensions,
        selectedSupportedVersion =
            selectedSupportedVersion ??
                extensions
                    ?.first<TlsSupportedVersionsExtension>()
                    ?.selectedVersion,
        applicationProtocols = List<String>.unmodifiable(
          applicationProtocols ??
              extensions?.first<TlsAlpnExtension>()?.protocols ??
                  const <String>[],
        ),
        keyShare =
            keyShare ?? extensions?.first<TlsKeyShareExtension>()?.serverShare,
        super(TlsHandshakeType.serverHello) {
    if (this.random.length != 32) {
      throw ArgumentError('ServerHello.random precisa de 32 bytes');
    }
  }

  final TlsProtocolVersion serverVersion;
  final Uint8List random;
  final Uint8List sessionId;
  final int cipherSuite;
  final int compressionMethod;
  final TlsExtensionBlock? extensions;
  final TlsProtocolVersion? selectedSupportedVersion;
  final List<String> applicationProtocols;
  final TlsKeyShareEntry? keyShare;

  static TlsServerHello parseBody(Uint8List body) {
    final parser = Parser(body);
    final version = TlsProtocolVersion.parse(parser);
    final random = parser.getFixBytes(32);
    final sessionIdLength = parser.get(1);
    final sessionId = parser.getFixBytes(sessionIdLength);
    final cipherSuite = parser.get(2);
    final compressionMethod = parser.get(1);
    TlsExtensionBlock? extensions;
    TlsProtocolVersion? selectedSupportedVersion;
    List<String> applicationProtocols = const <String>[];
    TlsKeyShareEntry? keyShare;
    if (!parser.isDone) {
      final extensionsLength = parser.get(2);
      final bytes = parser.getFixBytes(extensionsLength);
      extensions = TlsExtensionBlock.fromBytes(
        bytes,
        context: TlsExtensionContext.serverHello,
      );
      selectedSupportedVersion = extensions
          .first<TlsSupportedVersionsExtension>()
          ?.selectedVersion;
      applicationProtocols =
          extensions.first<TlsAlpnExtension>()?.protocols ?? const <String>[];
      keyShare = extensions.first<TlsKeyShareExtension>()?.serverShare;
    }
    if (!parser.isDone) {
      throw DecodeError('Sobrou payload após ServerHello');
    }
    return TlsServerHello(
      serverVersion: version,
      random: random,
      sessionId: sessionId,
      cipherSuite: cipherSuite,
      compressionMethod: compressionMethod,
      extensions: extensions,
      selectedSupportedVersion: selectedSupportedVersion,
      applicationProtocols: applicationProtocols,
      keyShare: keyShare,
    );
  }

  @override
  Uint8List serializeBody() {
    final writer = Writer();
    writer.add(serverVersion.major, 1);
    writer.add(serverVersion.minor, 1);
    writer.addBytes(random);
    writer.add(sessionId.length, 1);
    writer.addBytes(sessionId);
    writer.add(cipherSuite, 2);
    writer.add(compressionMethod, 1);
    if (extensions != null && !extensions!.isEmpty) {
      final data = extensions!.serialize();
      writer.add(data.length, 2);
      writer.addBytes(data);
    }
    return writer.bytes;
  }
}

class TlsFinished extends TlsHandshakeMessage {
  TlsFinished({required Uint8List verifyData})
      : verifyData = Uint8List.fromList(verifyData),
        super(TlsHandshakeType.finished);

  final Uint8List verifyData;

  static TlsFinished parseBody(Uint8List body) {
    return TlsFinished(verifyData: Uint8List.fromList(body));
  }

  @override
  Uint8List serializeBody() => Uint8List.fromList(verifyData);
}

class TlsCertificateEntry {
  TlsCertificateEntry({
    required Uint8List certificate,
    Uint8List? extensions,
  })  : certificate = Uint8List.fromList(certificate),
        extensions = Uint8List.fromList(extensions ?? Uint8List(0));

  final Uint8List certificate;
  final Uint8List extensions;
}

class TlsCertificate extends TlsHandshakeMessage {
  TlsCertificate._({
    required this.version,
    required List<Uint8List> certificateChain,
    required Uint8List certificateRequestContext,
    required List<TlsCertificateEntry> certificateEntries,
  })  : certificateChain =
            certificateChain.map(Uint8List.fromList).toList(growable: false),
        certificateRequestContext =
            Uint8List.fromList(certificateRequestContext),
        certificateEntries =
            List<TlsCertificateEntry>.from(certificateEntries, growable: false),
        super(TlsHandshakeType.certificate);

  factory TlsCertificate.tls12({
    TlsProtocolVersion version = TlsProtocolVersion.tls12,
    required List<Uint8List> certificateChain,
  }) {
    return TlsCertificate._(
      version: version,
      certificateChain: certificateChain,
      certificateRequestContext: Uint8List(0),
      certificateEntries: const <TlsCertificateEntry>[],
    );
  }

  factory TlsCertificate.tls13({
    TlsProtocolVersion version = TlsProtocolVersion.tls13,
    Uint8List? certificateRequestContext,
    required List<TlsCertificateEntry> certificateEntries,
  }) {
    return TlsCertificate._(
      version: version,
      certificateChain: const <Uint8List>[],
      certificateRequestContext: certificateRequestContext ?? Uint8List(0),
      certificateEntries: certificateEntries,
    );
  }

  final TlsProtocolVersion version;
  final List<Uint8List> certificateChain;
  final Uint8List certificateRequestContext;
  final List<TlsCertificateEntry> certificateEntries;

  bool get isTls13 => version.minor >= TlsProtocolVersion.tls13.minor;

  static TlsCertificate parseBody(
    Uint8List body, {
    TlsProtocolVersion version = TlsProtocolVersion.tls12,
  }) {
    final parser = Parser(body);
    if (version.minor <= TlsProtocolVersion.tls12.minor) {
      final totalLength = parser.get(3);
      var consumed = 0;
      final certificates = <Uint8List>[];
      while (consumed < totalLength) {
        final certLength = parser.get(3);
        final cert = parser.getFixBytes(certLength);
        certificates.add(cert);
        consumed += 3 + certLength;
      }
      if (consumed != totalLength) {
        throw DecodeError('Lista de certificados truncada');
      }
      if (!parser.isDone) {
        throw DecodeError('Sobrou payload após Certificate (TLS 1.2).');
      }
      return TlsCertificate.tls12(
        version: version,
        certificateChain: certificates,
      );
    }

    final context = parser.getVarBytes(1);
    final entriesLength = parser.get(3);
    var consumed = 0;
    final entries = <TlsCertificateEntry>[];
    while (consumed < entriesLength) {
      final certLength = parser.get(3);
      final cert = parser.getFixBytes(certLength);
      final extLength = parser.get(2);
      final extensions = parser.getFixBytes(extLength);
      consumed += 3 + certLength + 2 + extLength;
      entries.add(
        TlsCertificateEntry(certificate: cert, extensions: extensions),
      );
    }
    if (consumed != entriesLength) {
      throw DecodeError('Lista de CertificateEntry truncada');
    }
    if (!parser.isDone) {
      throw DecodeError('Sobrou payload após Certificate (TLS 1.3).');
    }
    return TlsCertificate.tls13(
      version: version,
      certificateRequestContext: context,
      certificateEntries: entries,
    );
  }

  @override
  Uint8List serializeBody() {
    final writer = Writer();
    if (!isTls13) {
      final chainWriter = Writer();
      for (final cert in certificateChain) {
        chainWriter.add(cert.length, 3);
        chainWriter.addBytes(cert);
      }
      writer.add(chainWriter.length, 3);
      writer.addBytes(chainWriter.bytes);
      return writer.bytes;
    }

    writer.add(certificateRequestContext.length, 1);
    writer.addBytes(certificateRequestContext);
    final entryWriter = Writer();
    for (final entry in certificateEntries) {
      entryWriter.add(entry.certificate.length, 3);
      entryWriter.addBytes(entry.certificate);
      entryWriter.add(entry.extensions.length, 2);
      entryWriter.addBytes(entry.extensions);
    }
    writer.add(entryWriter.length, 3);
    writer.addBytes(entryWriter.bytes);
    return writer.bytes;
  }
}

class TlsCertificateRequest extends TlsHandshakeMessage {
  TlsCertificateRequest({
    required this.version,
    List<int>? certificateTypes,
    List<int>? signatureAlgorithms,
    List<Uint8List>? certificateAuthorities,
    Uint8List? certificateRequestContext,
    TlsExtensionBlock? extensions,
    List<int>? signatureAlgorithmsCert,
    TlsStatusRequestExtension? statusRequest,
  })  : certificateTypes = List<int>.from(certificateTypes ?? const <int>[]),
        signatureAlgorithms =
            List<int>.from(signatureAlgorithms ?? const <int>[]),
        certificateAuthorities = (certificateAuthorities ?? const <Uint8List>[])
            .map(Uint8List.fromList)
            .toList(growable: false),
        certificateRequestContext =
            Uint8List.fromList(certificateRequestContext ?? Uint8List(0)),
        extensions = extensions ?? TlsExtensionBlock(),
        signatureAlgorithmsCert = List<int>.unmodifiable(
          signatureAlgorithmsCert ?? const <int>[],
        ),
        statusRequest = statusRequest,
        super(TlsHandshakeType.certificateRequest);

  final TlsProtocolVersion version;
  final List<int> certificateTypes;
  final List<int> signatureAlgorithms;
  final List<Uint8List> certificateAuthorities;
  final Uint8List certificateRequestContext;
  final TlsExtensionBlock extensions;
  final List<int> signatureAlgorithmsCert;
  final TlsStatusRequestExtension? statusRequest;

  bool get isTls13 => version.minor >= TlsProtocolVersion.tls13.minor;

  static TlsCertificateRequest parseBody(
    Uint8List body, {
    TlsProtocolVersion version = TlsProtocolVersion.tls12,
  }) {
    final parser = Parser(body);
    if (version.minor <= TlsProtocolVersion.tls12.minor) {
      final certificateTypes = parser.getVarList(1, 1);
      var signatureAlgorithms = <int>[];
      if (version.minor >= TlsProtocolVersion.tls12.minor) {
        final tuples = parser.getVarTupleList(1, 2, 2);
        signatureAlgorithms = tuples
            .map((tuple) => ((tuple[0] & 0xff) << 8) | (tuple[1] & 0xff))
            .toList(growable: false);
      }
      final caListLength = parser.get(2);
      final authorities = <Uint8List>[];
      var consumed = 0;
      while (consumed < caListLength) {
        final ca = parser.getVarBytes(2);
        authorities.add(ca);
        consumed += ca.length + 2;
      }
      if (!parser.isDone) {
        throw DecodeError('Sobrou payload após CertificateRequest');
      }
      return TlsCertificateRequest(
        version: version,
        certificateTypes: certificateTypes,
        signatureAlgorithms: signatureAlgorithms,
        certificateAuthorities: authorities,
      );
    }

    final context = parser.getVarBytes(1);
    final extensionsLength = parser.get(2);
    final bytes = parser.getFixBytes(extensionsLength);
    if (!parser.isDone) {
      throw DecodeError('Sobrou payload após CertificateRequest TLS 1.3');
    }
    final block = TlsExtensionBlock.fromBytes(
      bytes,
      context: TlsExtensionContext.certificateRequest,
    );
    final statusRequest = block.first<TlsStatusRequestExtension>();
    final signatureAlgorithmsCert = block
            .first<TlsSignatureAlgorithmsCertExtension>()
            ?.signatureSchemes ??
        const <int>[];
    return TlsCertificateRequest(
      version: version,
      certificateRequestContext: context,
      extensions: block,
      statusRequest: statusRequest,
      signatureAlgorithmsCert: signatureAlgorithmsCert,
    );
  }

  @override
  Uint8List serializeBody() {
    final writer = Writer();
    if (!isTls13) {
      writer.addVarSeq(certificateTypes, 1, 1);
      if (version.minor >= TlsProtocolVersion.tls12.minor) {
        final tuples = signatureAlgorithms
            .map((scheme) => <int>[(scheme >> 8) & 0xff, scheme & 0xff])
            .toList(growable: false);
        writer.addVarTupleSeq(tuples, 1, 2);
      }
      final authoritiesWriter = Writer();
      for (final ca in certificateAuthorities) {
        authoritiesWriter.add(ca.length, 2);
        authoritiesWriter.addBytes(ca);
      }
      writer.add(authoritiesWriter.length, 2);
      writer.addBytes(authoritiesWriter.bytes);
      return writer.bytes;
    }

    writer.add(certificateRequestContext.length, 1);
    writer.addBytes(certificateRequestContext);
    final data = extensions.serialize();
    writer.add(data.length, 2);
    writer.addBytes(data);
    return writer.bytes;
  }
}

class TlsCertificateVerify extends TlsHandshakeMessage {
  TlsCertificateVerify({
    required this.version,
    required Uint8List signature,
    this.signatureScheme,
  })  : signature = Uint8List.fromList(signature),
        super(TlsHandshakeType.certificateVerify);

  final TlsProtocolVersion version;
  final Uint8List signature;
  final int? signatureScheme;

  static TlsCertificateVerify parseBody(
    Uint8List body, {
    TlsProtocolVersion version = TlsProtocolVersion.tls12,
  }) {
    final parser = Parser(body);
    int? scheme;
    if (version.minor >= TlsProtocolVersion.tls12.minor) {
      final hash = parser.get(1);
      final sig = parser.get(1);
      scheme = (hash << 8) | sig;
    }
    final signature = parser.getVarBytes(2);
    if (!parser.isDone) {
      throw DecodeError('Sobrou payload após CertificateVerify');
    }
    return TlsCertificateVerify(
      version: version,
      signature: signature,
      signatureScheme: scheme,
    );
  }

  @override
  Uint8List serializeBody() {
    final writer = Writer();
    if (version.minor >= TlsProtocolVersion.tls12.minor) {
      final scheme = signatureScheme ?? 0;
      writer.add((scheme >> 8) & 0xff, 1);
      writer.add(scheme & 0xff, 1);
    }
    writer.addVarBytes(signature, 2);
    return writer.bytes;
  }
}

class TlsKeyUpdate extends TlsHandshakeMessage {
  TlsKeyUpdate({this.updateRequested = false})
      : super(TlsHandshakeType.keyUpdate);

  final bool updateRequested;

  static TlsKeyUpdate parseBody(Uint8List body) {
    if (body.length != 1) {
      throw DecodeError('KeyUpdate precisa conter exatamente 1 byte');
    }
    final value = body[0];
    final requested =
        value == tls_constants.KeyUpdateMessageType.update_requested;
    return TlsKeyUpdate(updateRequested: requested);
  }

  @override
  Uint8List serializeBody() {
    return Uint8List.fromList(<int>[
      updateRequested
          ? tls_constants.KeyUpdateMessageType.update_requested
          : tls_constants.KeyUpdateMessageType.update_not_requested,
    ]);
  }
}

class TlsEncryptedExtensions extends TlsHandshakeMessage {
  TlsEncryptedExtensions({TlsExtensionBlock? extensions})
      : this._(extensions ?? TlsExtensionBlock());

  TlsEncryptedExtensions._(TlsExtensionBlock extensions)
      : extensions = extensions,
        serverNames = List<String>.unmodifiable(
          extensions.first<TlsServerNameExtension>()?.hostNames ??
              const <String>[],
        ),
        applicationProtocols = List<String>.unmodifiable(
          extensions.first<TlsAlpnExtension>()?.protocols ??
              const <String>[],
        ),
        super(TlsHandshakeType.encryptedExtensions);

  final TlsExtensionBlock extensions;
  final List<String> serverNames;
  final List<String> applicationProtocols;

  static TlsEncryptedExtensions parseBody(Uint8List body) {
    final parser = Parser(body);
    final extensionsLength = parser.get(2);
    final bytes = parser.getFixBytes(extensionsLength);
    if (!parser.isDone) {
      throw DecodeError('Sobrou payload após EncryptedExtensions');
    }
    final block = TlsExtensionBlock.fromBytes(
      bytes,
      context: TlsExtensionContext.encryptedExtensions,
    );
    return TlsEncryptedExtensions(extensions: block);
  }

  @override
  Uint8List serializeBody() {
    final data = extensions.serialize();
    final writer = Writer();
    writer.add(data.length, 2);
    writer.addBytes(data);
    return writer.bytes;
  }
}

class TlsNewSessionTicket extends TlsHandshakeMessage {
  TlsNewSessionTicket({
    required this.ticketLifetime,
    required this.ticketAgeAdd,
    required Uint8List ticketNonce,
    required Uint8List ticket,
    Uint8List? extensions,
  })  : ticketNonce = Uint8List.fromList(ticketNonce),
        ticket = Uint8List.fromList(ticket),
        extensions = Uint8List.fromList(extensions ?? Uint8List(0)),
        super(TlsHandshakeType.newSessionTicket);

  final int ticketLifetime;
  final int ticketAgeAdd;
  final Uint8List ticketNonce;
  final Uint8List ticket;
  final Uint8List extensions;

  static TlsNewSessionTicket parseBody(Uint8List body) {
    final parser = Parser(body);
    final lifetime = parser.get(4);
    final ageAdd = parser.get(4);
    final nonce = parser.getVarBytes(1);
    final ticket = parser.getVarBytes(2);
    final extensionsLength = parser.get(2);
    final extensions = parser.getFixBytes(extensionsLength);
    if (!parser.isDone) {
      throw DecodeError('Sobrou payload após NewSessionTicket');
    }
    return TlsNewSessionTicket(
      ticketLifetime: lifetime,
      ticketAgeAdd: ageAdd,
      ticketNonce: nonce,
      ticket: ticket,
      extensions: extensions,
    );
  }

  @override
  Uint8List serializeBody() {
    final writer = Writer();
    writer.add(ticketLifetime, 4);
    writer.add(ticketAgeAdd, 4);
    writer.addVarBytes(ticketNonce, 1);
    writer.addVarBytes(ticket, 2);
    writer.add(extensions.length, 2);
    writer.addBytes(extensions);
    return writer.bytes;
  }
}

class TlsChangeCipherSpec extends TlsMessage {
  TlsChangeCipherSpec({this.value = 1})
      : super(TlsContentType.changeCipherSpec) {
    if (value != 1) {
      throw ArgumentError('ChangeCipherSpec.value precisa ser 1');
    }
  }

  final int value;

  static TlsChangeCipherSpec parse(Uint8List fragment) {
    if (fragment.length != 1) {
      throw DecodeError('ChangeCipherSpec deve conter 1 byte');
    }
    return TlsChangeCipherSpec(value: fragment[0]);
  }

  @override
  Uint8List serialize() => Uint8List.fromList(<int>[value]);
}

// ============================================================================
// Additional TLS Handshake Messages
// ============================================================================

/// HelloRequest message (TLS 1.0-1.2)
class TlsHelloRequest extends TlsHandshakeMessage {
  TlsHelloRequest() : super(TlsHandshakeType.helloRequest);

  static TlsHelloRequest parse(Uint8List body) {
    if (body.isNotEmpty) {
      throw DecodeError('HelloRequest deve ter corpo vazio');
    }
    return TlsHelloRequest();
  }

  @override
  Uint8List serializeBody() => Uint8List(0);
}

/// ServerHelloDone message (TLS 1.0-1.2)
class TlsServerHelloDone extends TlsHandshakeMessage {
  TlsServerHelloDone() : super(TlsHandshakeType.serverHelloDone);

  static TlsServerHelloDone parse(Uint8List body) {
    if (body.isNotEmpty) {
      throw DecodeError('ServerHelloDone deve ter corpo vazio');
    }
    return TlsServerHelloDone();
  }

  @override
  Uint8List serializeBody() => Uint8List(0);
}

/// ServerKeyExchange message for DHE/ECDHE/SRP key exchange
class TlsServerKeyExchange extends TlsHandshakeMessage {
  TlsServerKeyExchange({
    this.cipherSuite = 0,
    this.version = const [3, 3],
    BigInt? srpN,
    BigInt? srpG,
    this.srpS = const [],
    BigInt? srpB,
    BigInt? dhP,
    BigInt? dhG,
    BigInt? dhYs,
    this.curveType,
    this.namedCurve,
    this.ecdhYs = const [],
    this.signature = const [],
    this.hashAlg = 0,
    this.signAlg = 0,
  }) : srpN = srpN ?? BigInt.zero,
       srpG = srpG ?? BigInt.zero,
       srpB = srpB ?? BigInt.zero,
       dhP = dhP ?? BigInt.zero,
       dhG = dhG ?? BigInt.zero,
       dhYs = dhYs ?? BigInt.zero,
       super(TlsHandshakeType.serverKeyExchange);

  final int cipherSuite;
  final List<int> version;
  
  // SRP parameters
  final BigInt srpN;
  final BigInt srpG;
  final List<int> srpS;
  final BigInt srpB;
  
  // FFDHE parameters
  final BigInt dhP;
  final BigInt dhG;
  final BigInt dhYs;
  
  // ECDHE parameters
  final int? curveType;
  final int? namedCurve;
  final List<int> ecdhYs;
  
  // Signature
  final List<int> signature;
  final int hashAlg;
  final int signAlg;

  static TlsServerKeyExchange parse(Uint8List body, int cipherSuite, List<int> version) {
    final parser = Parser(body);
    
    BigInt srpN = BigInt.zero;
    BigInt srpG = BigInt.zero;
    List<int> srpS = [];
    BigInt srpB = BigInt.zero;
    BigInt dhP = BigInt.zero;
    BigInt dhG = BigInt.zero;
    BigInt dhYs = BigInt.zero;
    int? curveType;
    int? namedCurve;
    List<int> ecdhYs = [];
    List<int> signature = [];
    int hashAlg = 0;
    int signAlg = 0;

    // Parse based on cipher suite type
    if (tls_constants.CipherSuite.srpAllSuites.contains(cipherSuite)) {
      final srpNLen = parser.get(2);
      srpN = bytesToNumber(Uint8List.fromList(parser.getFixBytes(srpNLen)));
      final srpGLen = parser.get(2);
      srpG = bytesToNumber(Uint8List.fromList(parser.getFixBytes(srpGLen)));
      srpS = parser.getVarBytes(1);
      final srpBLen = parser.get(2);
      srpB = bytesToNumber(Uint8List.fromList(parser.getFixBytes(srpBLen)));
    } else if (tls_constants.CipherSuite.dhAllSuites.contains(cipherSuite)) {
      final dhPLen = parser.get(2);
      dhP = bytesToNumber(Uint8List.fromList(parser.getFixBytes(dhPLen)));
      final dhGLen = parser.get(2);
      dhG = bytesToNumber(Uint8List.fromList(parser.getFixBytes(dhGLen)));
      final dhYsLen = parser.get(2);
      dhYs = bytesToNumber(Uint8List.fromList(parser.getFixBytes(dhYsLen)));
    } else if (tls_constants.CipherSuite.ecdhAllSuites.contains(cipherSuite)) {
      curveType = parser.get(1);
      if (curveType == tls_constants.ECCurveType.named_curve) {
        namedCurve = parser.get(2);
      }
      ecdhYs = parser.getVarBytes(1);
    }

    // Parse signature for authenticated suites
    if (tls_constants.CipherSuite.certAllSuites.contains(cipherSuite) ||
        tls_constants.CipherSuite.ecdheEcdsaSuites.contains(cipherSuite)) {
      if (version[0] == 3 && version[1] >= 3) {
        // TLS 1.2+
        hashAlg = parser.get(1);
        signAlg = parser.get(1);
      }
      signature = parser.getVarBytes(2);
    }

    return TlsServerKeyExchange(
      cipherSuite: cipherSuite,
      version: version,
      srpN: srpN,
      srpG: srpG,
      srpS: srpS,
      srpB: srpB,
      dhP: dhP,
      dhG: dhG,
      dhYs: dhYs,
      curveType: curveType,
      namedCurve: namedCurve,
      ecdhYs: ecdhYs,
      signature: signature,
      hashAlg: hashAlg,
      signAlg: signAlg,
    );
  }

  @override
  Uint8List serializeBody() {
    final writer = Writer();
    
    if (tls_constants.CipherSuite.srpAllSuites.contains(cipherSuite)) {
      final srpNBytes = numberToByteArray(srpN);
      writer.add(srpNBytes.length, 2);
      writer.addBytes(srpNBytes);
      final srpGBytes = numberToByteArray(srpG);
      writer.add(srpGBytes.length, 2);
      writer.addBytes(srpGBytes);
      writer.addVarBytes(Uint8List.fromList(srpS), 1);
      final srpBBytes = numberToByteArray(srpB);
      writer.add(srpBBytes.length, 2);
      writer.addBytes(srpBBytes);
    } else if (tls_constants.CipherSuite.dhAllSuites.contains(cipherSuite)) {
      final dhPBytes = numberToByteArray(dhP);
      writer.add(dhPBytes.length, 2);
      writer.addBytes(dhPBytes);
      final dhGBytes = numberToByteArray(dhG);
      writer.add(dhGBytes.length, 2);
      writer.addBytes(dhGBytes);
      final dhYsBytes = numberToByteArray(dhYs);
      writer.add(dhYsBytes.length, 2);
      writer.addBytes(dhYsBytes);
    } else if (tls_constants.CipherSuite.ecdhAllSuites.contains(cipherSuite)) {
      writer.add(curveType ?? tls_constants.ECCurveType.named_curve, 1);
      if (curveType == tls_constants.ECCurveType.named_curve) {
        writer.add(namedCurve ?? 0, 2);
      }
      writer.addVarBytes(Uint8List.fromList(ecdhYs), 1);
    }

    if (tls_constants.CipherSuite.certAllSuites.contains(cipherSuite) ||
        tls_constants.CipherSuite.ecdheEcdsaSuites.contains(cipherSuite)) {
      if (version[0] == 3 && version[1] >= 3) {
        writer.add(hashAlg, 1);
        writer.add(signAlg, 1);
      }
      writer.addVarBytes(Uint8List.fromList(signature), 2);
    }
    
    return writer.bytes;
  }
}

/// ClientKeyExchange message for various key exchange methods
class TlsClientKeyExchange extends TlsHandshakeMessage {
  TlsClientKeyExchange({
    this.cipherSuite = 0,
    this.version = const [3, 3],
    BigInt? srpA,
    BigInt? dhYc,
    this.ecdhYc = const [],
    this.encryptedPreMasterSecret = const [],
  }) : srpA = srpA ?? BigInt.zero,
       dhYc = dhYc ?? BigInt.zero,
       super(TlsHandshakeType.clientKeyExchange);

  final int cipherSuite;
  final List<int> version;
  final BigInt srpA; // SRP client public value
  final BigInt dhYc; // DH client public value
  final List<int> ecdhYc; // ECDH client public value
  final List<int> encryptedPreMasterSecret; // RSA encrypted premaster

  static TlsClientKeyExchange parse(Uint8List body, int cipherSuite, List<int> version) {
    final parser = Parser(body);
    
    BigInt srpA = BigInt.zero;
    BigInt dhYc = BigInt.zero;
    List<int> ecdhYc = [];
    List<int> encryptedPreMasterSecret = [];

    if (tls_constants.CipherSuite.srpAllSuites.contains(cipherSuite)) {
      final srpALen = parser.get(2);
      srpA = bytesToNumber(Uint8List.fromList(parser.getFixBytes(srpALen)));
    } else if (tls_constants.CipherSuite.dhAllSuites.contains(cipherSuite)) {
      final dhYcLen = parser.get(2);
      dhYc = bytesToNumber(Uint8List.fromList(parser.getFixBytes(dhYcLen)));
    } else if (tls_constants.CipherSuite.ecdhAllSuites.contains(cipherSuite)) {
      ecdhYc = parser.getVarBytes(1);
    } else {
      // RSA key exchange
      if (version[0] == 3 && version[1] >= 1) {
        // TLS 1.0+
        encryptedPreMasterSecret = parser.getVarBytes(2);
      } else {
        // SSL 3.0
        final remaining = parser.getRemainingLength();
        encryptedPreMasterSecret = parser.getFixBytes(remaining);
      }
    }

    return TlsClientKeyExchange(
      cipherSuite: cipherSuite,
      version: version,
      srpA: srpA,
      dhYc: dhYc,
      ecdhYc: ecdhYc,
      encryptedPreMasterSecret: encryptedPreMasterSecret,
    );
  }

  @override
  Uint8List serializeBody() {
    final writer = Writer();
    
    if (tls_constants.CipherSuite.srpAllSuites.contains(cipherSuite)) {
      final srpABytes = numberToByteArray(srpA);
      writer.add(srpABytes.length, 2);
      writer.addBytes(srpABytes);
    } else if (tls_constants.CipherSuite.dhAllSuites.contains(cipherSuite)) {
      final dhYcBytes = numberToByteArray(dhYc);
      writer.add(dhYcBytes.length, 2);
      writer.addBytes(dhYcBytes);
    } else if (tls_constants.CipherSuite.ecdhAllSuites.contains(cipherSuite)) {
      writer.addVarBytes(Uint8List.fromList(ecdhYc), 1);
    } else {
      // RSA
      if (version[0] == 3 && version[1] >= 1) {
        writer.addVarBytes(Uint8List.fromList(encryptedPreMasterSecret), 2);
      } else {
        writer.addBytes(encryptedPreMasterSecret);
      }
    }
    
    return writer.bytes;
  }
}

/// CertificateStatus message (OCSP stapling)
class TlsCertificateStatus extends TlsHandshakeMessage {
  TlsCertificateStatus({
    this.statusType = 1, // ocsp
    this.ocspResponse = const [],
  }) : super(TlsHandshakeType.certificateStatus);

  final int statusType;
  final List<int> ocspResponse;

  static TlsCertificateStatus parse(Uint8List body) {
    final parser = Parser(body);
    final statusType = parser.get(1);
    final ocspResponse = parser.getVarBytes(3);
    
    if (!parser.isDone) {
      throw DecodeError('Sobrou payload após CertificateStatus');
    }
    
    return TlsCertificateStatus(
      statusType: statusType,
      ocspResponse: ocspResponse,
    );
  }

  @override
  Uint8List serializeBody() {
    final writer = Writer();
    writer.add(statusType, 1);
    writer.addVarBytes(Uint8List.fromList(ocspResponse), 3);
    return writer.bytes;
  }
}

/// NextProtocol message (NPN extension)
class TlsNextProtocol extends TlsHandshakeMessage {
  TlsNextProtocol({
    this.nextProto = const [],
  }) : super(TlsHandshakeType.nextProtocol);

  final List<int> nextProto;

  static TlsNextProtocol parse(Uint8List body) {
    final parser = Parser(body);
    final nextProto = parser.getVarBytes(1);
    parser.getVarBytes(1); // padding
    
    if (!parser.isDone) {
      throw DecodeError('Sobrou payload após NextProtocol');
    }
    
    return TlsNextProtocol(nextProto: nextProto);
  }

  @override
  Uint8List serializeBody() {
    final writer = Writer();
    writer.addVarBytes(Uint8List.fromList(nextProto), 1);
    // Add padding to make message at least 32 bytes
    final paddingLen = nextProto.length < 30 ? 32 - nextProto.length - 2 : 0;
    writer.addVarBytes(Uint8List(paddingLen), 1);
    return writer.bytes;
  }
}

/// ApplicationData message
class TlsApplicationData extends TlsMessage {
  TlsApplicationData({required this.data})
      : super(TlsContentType.applicationData);

  final List<int> data;

  static TlsApplicationData parse(Uint8List fragment) {
    return TlsApplicationData(data: fragment);
  }

  @override
  Uint8List serialize() => Uint8List.fromList(data);
}

/// Heartbeat message (RFC 6520)
class TlsHeartbeat extends TlsMessage {
  TlsHeartbeat({
    this.messageType = 1, // request
    this.payload = const [],
    this.padding = const [],
  }) : super(TlsContentType.heartbeat);

  final int messageType;
  final List<int> payload;
  final List<int> padding;

  static TlsHeartbeat parse(Uint8List fragment) {
    final parser = Parser(fragment);
    final messageType = parser.get(1);
    final payload = parser.getVarBytes(2);
    final remaining = parser.getRemainingLength();
    final padding = parser.getFixBytes(remaining);
    
    return TlsHeartbeat(
      messageType: messageType,
      payload: payload,
      padding: padding,
    );
  }

  @override
  Uint8List serialize() {
    final writer = Writer();
    writer.add(messageType, 1);
    writer.addVarBytes(Uint8List.fromList(payload), 2);
    writer.addBytes(padding);
    return writer.bytes;
  }
}
