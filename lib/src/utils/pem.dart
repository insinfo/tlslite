import 'dart:convert';
import 'dart:typed_data';

/// Decode a PEM block for [name] from [text].
/// Throws [FormatException] when delimiters are missing or the payload is
/// not valid Base64.
Uint8List dePem(String text, String name) {
  final prefix = '-----BEGIN $name-----';
  final postfix = '-----END $name-----';
  final start = text.indexOf(prefix);
  if (start == -1) {
    throw const FormatException('Missing PEM prefix');
  }
  final end = text.indexOf(postfix, start + prefix.length);
  if (end == -1) {
    throw const FormatException('Missing PEM postfix');
  }
  final body = text.substring(start + prefix.length, end);
  return _decodeBody(body);
}

/// Decode all PEM blocks for [name] from [text].
List<Uint8List> dePemList(String text, String name) {
  final blocks = <Uint8List>[];
  final prefix = '-----BEGIN $name-----';
  final postfix = '-----END $name-----';
  String remaining = text;
  while (true) {
    final start = remaining.indexOf(prefix);
    if (start == -1) {
      break;
    }
    final end = remaining.indexOf(postfix, start + prefix.length);
    if (end == -1) {
      throw const FormatException('Missing PEM postfix');
    }
    final body = remaining.substring(start + prefix.length, end);
    blocks.add(_decodeBody(body));
    remaining = remaining.substring(end + postfix.length);
  }
  return blocks;
}

Uint8List _decodeBody(String body) {
  final sanitized = body.replaceAll(RegExp(r'\s+'), '');
  final normalized = base64.normalize(sanitized);
  try {
    return Uint8List.fromList(base64.decode(normalized));
  } on FormatException catch (error) {
    throw FormatException('Invalid PEM payload: ${error.message}');
  }
}

/// Encode [data] into a PEM block labelled [name].
String pem(Uint8List data, String name) {
  final encoded = base64.encode(data);
  final buffer = StringBuffer('-----BEGIN $name-----\n');
  for (var i = 0; i < encoded.length; i += 64) {
    final end = (i + 64 < encoded.length) ? i + 64 : encoded.length;
    buffer.writeln(encoded.substring(i, end));
  }
  buffer.write('-----END $name-----\n');
  return buffer.toString();
}

/// Returns true when [text] seems to contain a PEM block for [name].
bool pemSniff(String text, String name) {
  return text.contains('-----BEGIN $name-----');
}
