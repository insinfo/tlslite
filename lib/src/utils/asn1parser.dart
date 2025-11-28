import 'dart:typed_data';

import 'codec.dart';

/// Metadata describing an ASN.1 tag (class/primitive/id).
class ASN1Type {
  const ASN1Type(this.tagClass, this.isPrimitive, this.tagId);

  final int tagClass;
  final int isPrimitive;
  final int tagId;
}

/// Parser for DER-encoded ASN.1 objects.
class ASN1Parser {
  ASN1Parser(Uint8List bytes) : _bytes = Uint8List.fromList(bytes) {
    final parser = Parser(_bytes);
    type = _parseType(parser);
    length = _getAsn1Length(parser);
    value = parser.getFixBytes(length);
  }

  /// Raw DER payload backing this node (tag+len+value).
  final Uint8List _bytes;

  /// ASN.1 tag metadata for this node.
  late final ASN1Type type;

  /// Length in bytes of the value portion.
  late final int length;

  /// Raw value bytes of this node.
  late final Uint8List value;

  /// Returns the nth child assuming this is a constructed sequence/set.
  ASN1Parser getChild(int index) {
    return ASN1Parser(getChildBytes(index));
  }

  /// Returns the DER bytes for the nth child.
  Uint8List getChildBytes(int index) {
    final parser = Parser(value);
    for (var i = 0; i <= index; i++) {
      final start = parser.index;
      parser.skipBytes(1); // type octet
      final len = _getAsn1Length(parser);
      parser.skipBytes(len);
      if (i == index) {
        return value.sublist(start, parser.index);
      }
    }
    throw RangeError.index(index, null, 'index');
  }

  /// Returns number of children contained within this constructed value.
  int getChildCount() {
    final parser = Parser(value);
    var count = 0;
    while (parser.getRemainingLength() > 0) {
      parser.skipBytes(1);
      final len = _getAsn1Length(parser);
      parser.skipBytes(len);
      count += 1;
    }
    return count;
  }

  static int _getAsn1Length(Parser parser) {
    final first = parser.get(1);
    if (first <= 0x7f) {
      return first;
    }
    final lengthLength = first & 0x7f;
    return parser.get(lengthLength);
  }

  static ASN1Type _parseType(Parser parser) {
    final header = parser.get(1);
    final tagClass = (header & 0xc0) >> 6;
    final isPrimitive = (header & 0x20) >> 5;
    var tagId = header & 0x1f;
    if (tagId == 0x1f) {
      tagId = 0;
      while (true) {
        final value = parser.get(1);
        tagId = (tagId << 7) | (value & 0x7f);
        if ((value & 0x80) == 0) {
          break;
        }
      }
    }
    return ASN1Type(tagClass, isPrimitive, tagId);
  }
}
