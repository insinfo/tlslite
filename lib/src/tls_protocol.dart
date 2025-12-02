import 'dart:typed_data';

import 'utils/codec.dart';

/// Representa uma versão TLS (major/minor).
class TlsProtocolVersion {
  const TlsProtocolVersion(this.major, this.minor);

  final int major;
  final int minor;

  static const TlsProtocolVersion tls10 = TlsProtocolVersion(3, 1);
  static const TlsProtocolVersion tls11 = TlsProtocolVersion(3, 2);
  static const TlsProtocolVersion tls12 = TlsProtocolVersion(3, 3);
  static const TlsProtocolVersion tls13 = TlsProtocolVersion(3, 4);

  Uint8List serialize() => Uint8List.fromList(<int>[major, minor]);

  static TlsProtocolVersion parse(Parser parser) {
    final versionMajor = parser.get(1);
    final versionMinor = parser.get(1);
    return TlsProtocolVersion(versionMajor, versionMinor);
  }

  @override
  String toString() => '$major.$minor';

  @override
  bool operator ==(Object other) {
    return other is TlsProtocolVersion &&
        other.major == major &&
        other.minor == minor;
  }

  @override
  int get hashCode => (major << 8) ^ minor;
}
