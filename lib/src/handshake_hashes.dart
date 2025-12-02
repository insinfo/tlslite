

/// Handling cryptographic hashes for handshake protocol.

import 'dart:typed_data';
import 'package:crypto/crypto.dart' as crypto;

/// Store and calculate necessary hashes for handshake protocol.
///
/// Calculates message digests of messages exchanged in handshake protocol
/// of SSLv3 and TLS.
class HandshakeHashes {
  late _HashWrapper _handshakeMD5;
  late _HashWrapper _handshakeSHA;
  late _HashWrapper _handshakeSHA224;
  late _HashWrapper _handshakeSHA256;
  late _HashWrapper _handshakeSHA384;
  late _HashWrapper _handshakeSHA512;
  final _handshakeBuffer = <int>[];

  /// Create instance.
  HandshakeHashes() {
    _handshakeMD5 = _HashWrapper(() => crypto.md5);
    _handshakeSHA = _HashWrapper(() => crypto.sha1);
    _handshakeSHA224 = _HashWrapper(() => crypto.sha224);
    _handshakeSHA256 = _HashWrapper(() => crypto.sha256);
    _handshakeSHA384 = _HashWrapper(() => crypto.sha384);
    _handshakeSHA512 = _HashWrapper(() => crypto.sha512);
  }

  /// Add [data] to hash input.
  ///
  /// [data] - serialized TLS handshake message
  void update(Uint8List data) {
    _handshakeMD5.update(data);
    _handshakeSHA.update(data);
    _handshakeSHA224.update(data);
    _handshakeSHA256.update(data);
    _handshakeSHA384.update(data);
    _handshakeSHA512.update(data);
    _handshakeBuffer.addAll(data);
  }

  /// Calculate and return digest for the already consumed data.
  ///
  /// Used for Finished and CertificateVerify messages.
  ///
  /// [digest] - name of digest to return (md5, sha1, sha224, sha256, sha384,
  /// sha512, intrinsic). If null, returns MD5+SHA1 concatenation (for SSLv3/TLS1.0).
  Uint8List digest([String? digest]) {
    if (digest == null) {
      // SSLv3/TLS 1.0/1.1 use MD5+SHA1
      final md5Bytes = _handshakeMD5.digest();
      final sha1Bytes = _handshakeSHA.digest();
      return Uint8List.fromList([...md5Bytes, ...sha1Bytes]);
    }

    switch (digest) {
      case 'md5':
        return _handshakeMD5.digest();
      case 'sha1':
        return _handshakeSHA.digest();
      case 'sha224':
        return _handshakeSHA224.digest();
      case 'sha256':
        return _handshakeSHA256.digest();
      case 'sha384':
        return _handshakeSHA384.digest();
      case 'sha512':
        return _handshakeSHA512.digest();
      case 'intrinsic':
        return Uint8List.fromList(_handshakeBuffer);
      default:
        throw ArgumentError('Unknown digest name: $digest');
    }
  }

  /// Calculate and return digest for already consumed data (SSLv3 version).
  ///
  /// Used for Finished and CertificateVerify messages.
  ///
  /// [masterSecret] - value of the master secret
  /// [label] - label to include in the calculation
  Uint8List digestSSL(Uint8List masterSecret, Uint8List label) {
    final imacMD5 = _handshakeMD5.copy();
    final imacSHA = _handshakeSHA.copy();

    // The below difference in input for MD5 and SHA-1 is why we can't reuse
    // digest() method
    imacMD5.update(Uint8List.fromList([
      ...label,
      ...masterSecret,
      ...List.filled(48, 0x36),
    ]));
    imacSHA.update(Uint8List.fromList([
      ...label,
      ...masterSecret,
      ...List.filled(40, 0x36),
    ]));

    final md5Bytes = Uint8List.fromList(crypto.md5.convert([
      ...masterSecret,
      ...List.filled(48, 0x5c),
      ...imacMD5.digest(),
    ]).bytes);

    final shaBytes = Uint8List.fromList(crypto.sha1.convert([
      ...masterSecret,
      ...List.filled(40, 0x5c),
      ...imacSHA.digest(),
    ]).bytes);

    return Uint8List.fromList([...md5Bytes, ...shaBytes]);
  }

  /// Copy object.
  ///
  /// Return a copy of the object with all the hashes in the same state
  /// as the source object.
  HandshakeHashes copy() {
    final other = HandshakeHashes();
    other._handshakeMD5 = _handshakeMD5.copy();
    other._handshakeSHA = _handshakeSHA.copy();
    other._handshakeSHA224 = _handshakeSHA224.copy();
    other._handshakeSHA256 = _handshakeSHA256.copy();
    other._handshakeSHA384 = _handshakeSHA384.copy();
    other._handshakeSHA512 = _handshakeSHA512.copy();
    other._handshakeBuffer.addAll(_handshakeBuffer);
    return other;
  }
}

/// Wrapper for hash functions that maintains incremental state.
class _HashWrapper {
  final crypto.Hash Function() _hashFactory;
  final List<int> _buffer = [];
  
  _HashWrapper(this._hashFactory);

  void update(Uint8List data) {
    _buffer.addAll(data);
  }

  Uint8List digest() {
    final hash = _hashFactory();
    return Uint8List.fromList(hash.convert(_buffer).bytes);
  }

  _HashWrapper copy() {
    final other = _HashWrapper(_hashFactory);
    other._buffer.addAll(_buffer);
    return other;
  }
}
