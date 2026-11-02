// Ported to Dart from tlslite-ng tlslite/handshakehashes.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

/// Handling cryptographic hashes for handshake protocol.

import 'dart:typed_data';
import 'utils/digest/digest.dart';

/// Store and calculate necessary hashes for handshake protocol.
///
/// Calculates message digests of messages exchanged in handshake protocol
/// of SSLv3 and TLS.
class HandshakeHashes {
  MessageDigest _handshakeMD5 = Md5();
  MessageDigest _handshakeSHA = Sha1();
  MessageDigest _handshakeSHA224 = Sha224();
  MessageDigest _handshakeSHA256 = Sha256();
  MessageDigest _handshakeSHA384 = Sha384();
  MessageDigest _handshakeSHA512 = Sha512();
  final _handshakeBuffer = <int>[];

  /// Create instance.
  HandshakeHashes();

  /// Reset all hashes and replace with the state from another HandshakeHashes.
  /// Used for HelloRetryRequest transcript replacement (RFC 8446 Section 4.4.1).
  void replaceWith(HandshakeHashes other) {
    _handshakeMD5 = other._handshakeMD5.clone();
    _handshakeSHA = other._handshakeSHA.clone();
    _handshakeSHA224 = other._handshakeSHA224.clone();
    _handshakeSHA256 = other._handshakeSHA256.clone();
    _handshakeSHA384 = other._handshakeSHA384.clone();
    _handshakeSHA512 = other._handshakeSHA512.clone();
    _handshakeBuffer.clear();
    _handshakeBuffer.addAll(other._handshakeBuffer);
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
  /// Used for Finished and CertificateVerify messages. The running hashes are
  /// not finalized, so more messages can be added afterwards.
  ///
  /// [digest] - name of digest to return (md5, sha1, sha224, sha256, sha384,
  /// sha512, intrinsic). If null, returns MD5+SHA1 concatenation (for SSLv3/TLS1.0).
  Uint8List digest([String? digest]) {
    if (digest == null) {
      // SSLv3/TLS 1.0/1.1 use MD5+SHA1
      final md5Bytes = _handshakeMD5.digest();
      final sha1Bytes = _handshakeSHA.digest();
      return Uint8List(md5Bytes.length + sha1Bytes.length)
        ..setAll(0, md5Bytes)
        ..setAll(md5Bytes.length, sha1Bytes);
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
    final imacMD5 = _handshakeMD5.clone();
    final imacSHA = _handshakeSHA.clone();

    // The below difference in input for MD5 and SHA-1 is why we can't reuse
    // digest() method
    imacMD5
      ..update(label)
      ..update(masterSecret)
      ..update(Uint8List(48)..fillRange(0, 48, 0x36));
    imacSHA
      ..update(label)
      ..update(masterSecret)
      ..update(Uint8List(40)..fillRange(0, 40, 0x36));

    final md5Bytes = (Md5()
          ..update(masterSecret)
          ..update(Uint8List(48)..fillRange(0, 48, 0x5c))
          ..update(imacMD5.finish()))
        .finish();

    final shaBytes = (Sha1()
          ..update(masterSecret)
          ..update(Uint8List(40)..fillRange(0, 40, 0x5c))
          ..update(imacSHA.finish()))
        .finish();

    return Uint8List(md5Bytes.length + shaBytes.length)
      ..setAll(0, md5Bytes)
      ..setAll(md5Bytes.length, shaBytes);
  }

  /// Copy object.
  ///
  /// Return a copy of the object with all the hashes in the same state
  /// as the source object.
  HandshakeHashes copy() {
    final other = HandshakeHashes();
    other._handshakeMD5 = _handshakeMD5.clone();
    other._handshakeSHA = _handshakeSHA.clone();
    other._handshakeSHA224 = _handshakeSHA224.clone();
    other._handshakeSHA256 = _handshakeSHA256.clone();
    other._handshakeSHA384 = _handshakeSHA384.clone();
    other._handshakeSHA512 = _handshakeSHA512.clone();
    other._handshakeBuffer.addAll(_handshakeBuffer);
    return other;
  }
}
