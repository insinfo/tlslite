import 'dart:convert';
import 'dart:typed_data';

import '../../../constants.dart' as tls_constants;
import '../../../utils/codec.dart';
import '../../../tls_protocol.dart';

enum TlsExtensionContext {
  clientHello,
  serverHello,
  encryptedExtensions,
  certificateRequest,
  helloRetryRequest,
}

abstract class TlsExtension {
  const TlsExtension(this.type);

  final int type;

  Uint8List serializeBody();
}

class TlsRawExtension extends TlsExtension {
  TlsRawExtension({required int type, required Uint8List body})
      : _body = Uint8List.fromList(body),
        super(type);

  final Uint8List _body;

  Uint8List get body => Uint8List.fromList(_body);

  @override
  Uint8List serializeBody() => Uint8List.fromList(_body);
}

typedef _ExtensionParser = TlsExtension Function(
  Uint8List body,
  TlsExtensionContext context,
);

class TlsExtensionRegistry {
  static final Map<int, _ExtensionParser> _parsers =
      <int, _ExtensionParser>{
    tls_constants.ExtensionType.server_name: _parseServerName,
    tls_constants.ExtensionType.alpn: _parseAlpn,
    tls_constants.ExtensionType.supported_versions: _parseSupportedVersions,
    tls_constants.ExtensionType.supported_groups: _parseSupportedGroups,
    tls_constants.ExtensionType.ec_point_formats: _parseEcPointFormats,
    tls_constants.ExtensionType.status_request: _parseStatusRequest,
    tls_constants.ExtensionType.signature_algorithms_cert:
        _parseSignatureAlgorithmsCert,
    tls_constants.ExtensionType.key_share: _parseKeyShare,
  };

  static TlsExtension parse(
    int type,
    Uint8List body,
    TlsExtensionContext context,
  ) {
    final parser = _parsers[type];
    if (parser == null) {
      return TlsRawExtension(type: type, body: body);
    }
    return parser(body, context);
  }

  static TlsExtension _parseServerName(
    Uint8List body,
    TlsExtensionContext context,
  ) {
    final parser = Parser(body);
    final listLength = parser.get(2);
    if (listLength != parser.getRemainingLength()) {
      throw DecodeError('Lista de ServerName com tamanho inconsistente');
    }
    final namesParser = Parser(parser.getFixBytes(listLength));
    final names = <String>[];
    while (!namesParser.isDone) {
      final nameType = namesParser.get(1);
      final nameLength = namesParser.get(2);
      final nameBytes = namesParser.getFixBytes(nameLength);
      if (nameType == tls_constants.NameType.host_name) {
        names.add(utf8.decode(nameBytes));
      }
    }
    return TlsServerNameExtension(hostNames: names);
  }

  static TlsExtension _parseAlpn(
    Uint8List body,
    TlsExtensionContext context,
  ) {
    final parser = Parser(body);
    final listLength = parser.get(2);
    if (listLength != parser.getRemainingLength()) {
      throw DecodeError('ALPN com tamanho inconsistente');
    }
    final listParser = Parser(parser.getFixBytes(listLength));
    final protocols = <String>[];
    while (!listParser.isDone) {
      final protoLength = listParser.get(1);
      final proto = listParser.getFixBytes(protoLength);
      protocols.add(utf8.decode(proto));
    }
    return TlsAlpnExtension(protocols: protocols);
  }

  static TlsExtension _parseSupportedVersions(
    Uint8List body,
    TlsExtensionContext context,
  ) {
    final parser = Parser(body);
    if (context == TlsExtensionContext.clientHello) {
      final vectorLength = parser.get(1);
      if (vectorLength % 2 != 0) {
        throw DecodeError('Lista supported_versions precisa de pares de bytes');
      }
      final bytes = parser.getFixBytes(vectorLength);
      final versions = <TlsProtocolVersion>[];
      for (int i = 0; i < bytes.length; i += 2) {
        versions.add(TlsProtocolVersion(bytes[i], bytes[i + 1]));
      }
      return TlsSupportedVersionsExtension.client(versions);
    }
    if (parser.getRemainingLength() != 2) {
      throw DecodeError('Servidor precisa enviar exatamente 2 bytes');
    }
    final major = parser.get(1);
    final minor = parser.get(1);
    return TlsSupportedVersionsExtension.server(
      TlsProtocolVersion(major, minor),
    );
  }

  static TlsExtension _parseSupportedGroups(
    Uint8List body,
    TlsExtensionContext context,
  ) {
    if (body.isEmpty) {
      return TlsSupportedGroupsExtension(groups: const <int>[]);
    }
    final parser = Parser(body);
    final listLength = parser.get(2);
    if (listLength % 2 != 0 || listLength > parser.getRemainingLength()) {
      throw DecodeError('supported_groups length is invalid');
    }
    final listBytes = parser.getFixBytes(listLength);
    final listParser = Parser(listBytes);
    final groups = <int>[];
    while (!listParser.isDone) {
      groups.add(listParser.get(2));
    }
    if (!parser.isDone) {
      throw DecodeError('Dados extras após supported_groups');
    }
    return TlsSupportedGroupsExtension(groups: groups);
  }

  static TlsExtension _parseEcPointFormats(
    Uint8List body,
    TlsExtensionContext context,
  ) {
    final parser = Parser(body);
    if (parser.isDone) {
      // RFC 4492 requires at least one format, but be lenient and treat empty
      // payloads as "no preference".
      return TlsEcPointFormatsExtension(formats: const <int>[]);
    }
    final listLength = parser.get(1);
    if (listLength > parser.getRemainingLength()) {
      throw DecodeError('ec_point_formats length exceeds payload size');
    }
    final formats = <int>[];
    for (var i = 0; i < listLength; i++) {
      formats.add(parser.get(1));
    }
    if (!parser.isDone) {
      throw DecodeError('Dados extras após ec_point_formats');
    }
    return TlsEcPointFormatsExtension(formats: formats);
  }

  static TlsExtension _parseStatusRequest(
    Uint8List body,
    TlsExtensionContext context,
  ) {
    if (body.isEmpty) {
      return TlsStatusRequestExtension.acknowledgement();
    }
    final parser = Parser(body);
    final statusType = parser.get(1);
    final responderBlockLength = parser.get(2);
    if (responderBlockLength > parser.getRemainingLength()) {
      throw DecodeError('Bloco responder_id_list truncado');
    }
    final responderParser = Parser(parser.getFixBytes(responderBlockLength));
    final responders = <Uint8List>[];
    while (!responderParser.isDone) {
      responders.add(responderParser.getVarBytes(2));
    }
    final requestExtensions = parser.getVarBytes(2);
    if (!parser.isDone) {
      throw DecodeError('Dados extras após status_request');
    }
    return TlsStatusRequestExtension.request(
      statusType: statusType,
      responderIds: responders,
      requestExtensions: requestExtensions,
    );
  }

  static TlsExtension _parseSignatureAlgorithmsCert(
    Uint8List body,
    TlsExtensionContext context,
  ) {
    if (body.isEmpty) {
      return TlsSignatureAlgorithmsCertExtension();
    }
    final parser = Parser(body);
    final listLength = parser.get(2);
    if (listLength % 2 != 0 || listLength > parser.getRemainingLength()) {
      throw DecodeError('Lista signature_algorithms_cert truncada');
    }
    final listParser = Parser(parser.getFixBytes(listLength));
    final schemes = <int>[];
    while (!listParser.isDone) {
      final hash = listParser.get(1);
      final sig = listParser.get(1);
      schemes.add((hash << 8) | sig);
    }
    if (!parser.isDone) {
      throw DecodeError('Dados extras após signature_algorithms_cert');
    }
    return TlsSignatureAlgorithmsCertExtension(signatureSchemes: schemes);
  }

  static TlsExtension _parseKeyShare(
    Uint8List body,
    TlsExtensionContext context,
  ) {
    final parser = Parser(body);
    switch (context) {
      case TlsExtensionContext.clientHello:
        if (parser.isDone) {
          return TlsKeyShareExtension.client(const <TlsKeyShareEntry>[]);
        }
        final vectorLength = parser.get(2);
        if (vectorLength > parser.getRemainingLength()) {
          throw DecodeError('ClientHello key_share truncado');
        }
        final listParser = Parser(parser.getFixBytes(vectorLength));
        final shares = <TlsKeyShareEntry>[];
        while (!listParser.isDone) {
          shares.add(TlsKeyShareEntry.parse(listParser));
        }
        if (!parser.isDone) {
          throw DecodeError('Dados extras após key_share do cliente');
        }
        return TlsKeyShareExtension.client(shares);
      case TlsExtensionContext.serverHello:
        if (parser.isDone) {
          return TlsKeyShareExtension.server(null);
        }
        final share = TlsKeyShareEntry.parse(parser);
        if (!parser.isDone) {
          throw DecodeError('Dados extras após key_share do servidor');
        }
        return TlsKeyShareExtension.server(share);
      case TlsExtensionContext.helloRetryRequest:
        if (parser.getRemainingLength() != 2) {
          throw DecodeError('HelloRetryRequest seleciona exatamente 2 bytes');
        }
        final group = parser.get(2);
        return TlsKeyShareExtension.helloRetry(group);
      default:
        throw DecodeError(
          'Extensão key_share inesperada para o contexto $context',
        );
    }
  }
}

class TlsExtensionBlock {
  TlsExtensionBlock({List<TlsExtension>? extensions})
      : _extensions = List<TlsExtension>.unmodifiable(
          extensions ?? const <TlsExtension>[],
        );

  factory TlsExtensionBlock.fromBytes(
    Uint8List bytes, {
    required TlsExtensionContext context,
  }) {
    final parser = Parser(bytes);
    final parsed = <TlsExtension>[];
    while (!parser.isDone) {
      if (parser.getRemainingLength() < 4) {
        throw DecodeError('Extensão TLS truncada (faltam cabeçalhos)');
      }
      final type = parser.get(2);
      final length = parser.get(2);
      if (parser.getRemainingLength() < length) {
        throw DecodeError('Extensão TLS truncada para o tipo $type');
      }
      final body = parser.getFixBytes(length);
      parsed.add(TlsExtensionRegistry.parse(type, body, context));
    }
    return TlsExtensionBlock(extensions: parsed);
  }

  final List<TlsExtension> _extensions;

  List<TlsExtension> get all => _extensions;

  bool get isEmpty => _extensions.isEmpty;

  TlsExtension? byType(int type) {
    for (final extension in _extensions) {
      if (extension.type == type) {
        return extension;
      }
    }
    return null;
  }

  T? first<T extends TlsExtension>() {
    for (final extension in _extensions) {
      if (extension is T) {
        return extension;
      }
    }
    return null;
  }

  Uint8List serialize() {
    final writer = Writer();
    for (final extension in _extensions) {
      final body = extension.serializeBody();
      writer.add(extension.type, 2);
      writer.add(body.length, 2);
      writer.addBytes(body);
    }
    return writer.bytes;
  }
}

class TlsServerNameExtension extends TlsExtension {
  TlsServerNameExtension({List<String>? hostNames})
      : hostNames = List<String>.unmodifiable(hostNames ?? const <String>[]),
        super(tls_constants.ExtensionType.server_name);

  final List<String> hostNames;

  @override
  Uint8List serializeBody() {
    final listWriter = Writer();
    for (final name in hostNames) {
      final bytes = utf8.encode(name);
      listWriter.add(tls_constants.NameType.host_name, 1);
      listWriter.add(bytes.length, 2);
      listWriter.addBytes(bytes);
    }
    final writer = Writer();
    writer.add(listWriter.length, 2);
    writer.addBytes(listWriter.bytes);
    return writer.bytes;
  }
}

class TlsAlpnExtension extends TlsExtension {
  TlsAlpnExtension({List<String>? protocols})
      : protocols = List<String>.unmodifiable(protocols ?? const <String>[]),
        super(tls_constants.ExtensionType.alpn);

  final List<String> protocols;

  @override
  Uint8List serializeBody() {
    final listWriter = Writer();
    for (final protocol in protocols) {
      final bytes = utf8.encode(protocol);
      listWriter.add(bytes.length, 1);
      listWriter.addBytes(bytes);
    }
    final writer = Writer();
    writer.add(listWriter.length, 2);
    writer.addBytes(listWriter.bytes);
    return writer.bytes;
  }
}

class TlsSupportedVersionsExtension extends TlsExtension {
  TlsSupportedVersionsExtension.client(List<TlsProtocolVersion> versions)
      : supportedVersions = List<TlsProtocolVersion>.unmodifiable(versions),
        selectedVersion = null,
        super(tls_constants.ExtensionType.supported_versions);

  TlsSupportedVersionsExtension.server(TlsProtocolVersion version)
      : supportedVersions = const <TlsProtocolVersion>[],
        selectedVersion = version,
        super(tls_constants.ExtensionType.supported_versions);

  final List<TlsProtocolVersion> supportedVersions;
  final TlsProtocolVersion? selectedVersion;

  bool get isServerResponse => selectedVersion != null;

  @override
  Uint8List serializeBody() {
    if (selectedVersion != null) {
      return Uint8List.fromList(<int>[selectedVersion!.major, selectedVersion!.minor]);
    }
    final listWriter = Writer();
    for (final version in supportedVersions) {
      listWriter.add(version.major, 1);
      listWriter.add(version.minor, 1);
    }
    final writer = Writer();
    writer.add(listWriter.length, 1);
    writer.addBytes(listWriter.bytes);
    return writer.bytes;
  }
}

class TlsSignatureAlgorithmsCertExtension extends TlsExtension {
  TlsSignatureAlgorithmsCertExtension({List<int>? signatureSchemes})
      : signatureSchemes =
            List<int>.unmodifiable(signatureSchemes ?? const <int>[]),
        super(tls_constants.ExtensionType.signature_algorithms_cert);

  final List<int> signatureSchemes;

  @override
  Uint8List serializeBody() {
    final writer = Writer();
    writer.add(signatureSchemes.length * 2, 2);
    for (final scheme in signatureSchemes) {
      writer.add((scheme >> 8) & 0xff, 1);
      writer.add(scheme & 0xff, 1);
    }
    return writer.bytes;
  }
}

class TlsEcPointFormatsExtension extends TlsExtension {
  TlsEcPointFormatsExtension({List<int>? formats})
      : formats = List<int>.unmodifiable(formats ?? const <int>[]),
        super(tls_constants.ExtensionType.ec_point_formats);

  final List<int> formats;

  @override
  Uint8List serializeBody() {
    final writer = Writer();
    writer.add(formats.length, 1);
    for (final format in formats) {
      writer.add(format, 1);
    }
    return writer.bytes;
  }
}

class TlsSupportedGroupsExtension extends TlsExtension {
  TlsSupportedGroupsExtension({List<int>? groups})
      : groups = List<int>.unmodifiable(groups ?? const <int>[]),
        super(tls_constants.ExtensionType.supported_groups);

  final List<int> groups;

  @override
  Uint8List serializeBody() {
    final writer = Writer();
    writer.add(groups.length * 2, 2);
    for (final group in groups) {
      writer.add(group, 2);
    }
    return writer.bytes;
  }
}

class TlsStatusRequestExtension extends TlsExtension {
  TlsStatusRequestExtension.request({
    required this.statusType,
    List<Uint8List>? responderIds,
    Uint8List? requestExtensions,
  })  : responderIds =
            (responderIds ?? const <Uint8List>[])
                .map(Uint8List.fromList)
                .toList(growable: false),
        requestExtensions =
            Uint8List.fromList(requestExtensions ?? Uint8List(0)),
        _isAcknowledgement = false,
        super(tls_constants.ExtensionType.status_request);

  TlsStatusRequestExtension.acknowledgement()
      : statusType = null,
        responderIds = const <Uint8List>[],
        requestExtensions = Uint8List(0),
        _isAcknowledgement = true,
        super(tls_constants.ExtensionType.status_request);

  final int? statusType;
  final List<Uint8List> responderIds;
  final Uint8List requestExtensions;
  final bool _isAcknowledgement;

  bool get isRequest => !_isAcknowledgement;

  @override
  Uint8List serializeBody() {
    if (_isAcknowledgement || statusType == null) {
      return Uint8List(0);
    }
    final responderWriter = Writer();
    for (final id in responderIds) {
      responderWriter.add(id.length, 2);
      responderWriter.addBytes(id);
    }
    final writer = Writer();
    writer.add(statusType!, 1);
    writer.add(responderWriter.length, 2);
    writer.addBytes(responderWriter.bytes);
    writer.add(requestExtensions.length, 2);
    writer.addBytes(requestExtensions);
    return writer.bytes;
  }
}

class TlsKeyShareEntry {
  TlsKeyShareEntry({required this.group, required Uint8List keyExchange})
      : keyExchange = Uint8List.fromList(keyExchange);

  final int group;
  final Uint8List keyExchange;

  static TlsKeyShareEntry parse(Parser parser) {
    final group = parser.get(2);
    final share = parser.getVarBytes(2);
    return TlsKeyShareEntry(group: group, keyExchange: share);
  }

  Uint8List serialize() {
    final writer = Writer();
    writer.add(group, 2);
    writer.add(keyExchange.length, 2);
    writer.addBytes(keyExchange);
    return writer.bytes;
  }
}

enum TlsKeyShareVariant {
  client,
  server,
  helloRetry,
}

class TlsKeyShareExtension extends TlsExtension {
  TlsKeyShareExtension.client(List<TlsKeyShareEntry> shares)
      : variant = TlsKeyShareVariant.client,
        clientShares = List<TlsKeyShareEntry>.unmodifiable(shares),
        serverShare = null,
        selectedGroup = null,
        super(tls_constants.ExtensionType.key_share);

  TlsKeyShareExtension.server(TlsKeyShareEntry? share)
      : variant = TlsKeyShareVariant.server,
        clientShares = const <TlsKeyShareEntry>[],
        serverShare = share,
        selectedGroup = null,
        super(tls_constants.ExtensionType.key_share);

  TlsKeyShareExtension.helloRetry(int group)
      : variant = TlsKeyShareVariant.helloRetry,
        clientShares = const <TlsKeyShareEntry>[],
        serverShare = null,
        selectedGroup = group,
        super(tls_constants.ExtensionType.key_share);

  final TlsKeyShareVariant variant;
  final List<TlsKeyShareEntry> clientShares;
  final TlsKeyShareEntry? serverShare;
  final int? selectedGroup;

  bool get hasShares => clientShares.isNotEmpty || serverShare != null;

  @override
  Uint8List serializeBody() {
    switch (variant) {
      case TlsKeyShareVariant.client:
        final listWriter = Writer();
        for (final share in clientShares) {
          listWriter.addBytes(share.serialize());
        }
        final writer = Writer();
        writer.add(listWriter.length, 2);
        writer.addBytes(listWriter.bytes);
        return writer.bytes;
      case TlsKeyShareVariant.server:
        if (serverShare == null) {
          return Uint8List(0);
        }
        return serverShare!.serialize();
      case TlsKeyShareVariant.helloRetry:
        final writer = Writer();
        writer.add(selectedGroup ?? 0, 2);
        return writer.bytes;
    }
  }
}
