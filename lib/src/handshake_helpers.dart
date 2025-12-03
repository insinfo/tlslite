

/// Class with various handshake helpers

import 'dart:typed_data';

import 'constants.dart';
import 'errors.dart';
import 'utils/codec.dart';
import 'utils/constanttime.dart';
import 'utils/cryptomath.dart';

/// Helper functions to be used with a TLS handshake
class HandshakeHelpers {
  /// Align ClientHello using the Padding extension to 512 bytes at least
  ///
  /// Check clientHello size if padding extension should be added.
  /// We want to add the extension even when using just SSLv3.
  /// Cut-off 4 bytes with the Hello header (ClientHello type + Length)
  static void alignClientHelloPadding(dynamic clientHello) {
    // Calculate current size (minus 4-byte header)
    var clientHelloLength = clientHello.write().length - 4;

    if (256 <= clientHelloLength && clientHelloLength <= 511) {
      if (clientHello.extensions == null) {
        clientHello.extensions = [];
        // Recalculate size after extension list addition (adds 2 bytes)
        clientHelloLength += 2;
      }

      // We want to get 512 bytes total, including padding extension header (4B)
      final paddingSize = (512 - clientHelloLength - 4).clamp(0, double.infinity).toInt();
      final paddingExtension = _PaddingExtension().create(paddingSize);
      clientHello.extensions.add(paddingExtension);
    }
  }

  /// Calculate the binder value for a given HandshakeHash
  ///
  /// The HandshakeHash should include a truncated client hello already.
  static Uint8List calcBinder(
    String prf,
    Uint8List psk,
    dynamic handshakeHash, {
    bool external = true,
  }) {
    assert(prf == 'sha256' || prf == 'sha384');
    final keyLen = prf == 'sha256' ? 32 : 48;

    // HKDF-Extract(0, PSK)
    final earlySecret = secureHMAC(Uint8List(keyLen), psk, prf);

    final binderKey = derive_secret(
      earlySecret,
      external ? Uint8List.fromList('ext binder'.codeUnits) : Uint8List.fromList('res binder'.codeUnits),
      null,
      prf,
    );

    final finishedKey = HKDF_expand_label(
      binderKey,
      Uint8List.fromList('finished'.codeUnits),
      Uint8List(0),
      keyLen,
      prf,
    );

    final binder = secureHMAC(finishedKey, handshakeHash.digest(prf), prf);
    return binder;
  }

  /// Calculate PSK associated with provided ticket identity
  static Uint8List calcResBinderPsk(
    dynamic iden,
    Uint8List resMasterSecret,
    List<dynamic> tickets,
  ) {
    final ticket = tickets.firstWhere((i) => i.ticket == iden.identity);

    final ticketHash = resMasterSecret.length == 32 ? 'sha256' : 'sha384';

    final psk = HKDF_expand_label(
      resMasterSecret,
      Uint8List.fromList('resumption'.codeUnits),
      ticket.ticket_nonce,
      resMasterSecret.length,
      ticketHash,
    );

    return psk;
  }

  /// Sign the Client Hello using TLS 1.3 PSK binders
  ///
  /// Note: the psk_configs should be in the same order as the ones in the
  /// PreSharedKeyExtension extension (extra ones are ok)
  static void updateBinders(
    dynamic clientHello,
    dynamic handshakeHashes,
    List<dynamic> pskConfigs, {
    List<dynamic>? tickets,
    Uint8List? resMasterSecret,
  }) {
    final ext = clientHello.extensions.last;
    if (ext.runtimeType.toString() != 'PreSharedKeyExtension') {
      throw ArgumentError(
        'Last extension in client_hello must be PreSharedKeyExtension',
      );
    }

    if (tickets != null && resMasterSecret == null) {
      throw ArgumentError('Tickets require setting res_master_secret');
    }

    final hh = handshakeHashes.copy();
    hh.update(clientHello.psk_truncate());

    final configsIter = pskConfigs.iterator;
    final ticketIdens = tickets?.map((i) => i.ticket).toList() ?? [];

    for (var i = 0; i < ext.identities.length; i++) {
      final iden = ext.identities[i];

      Uint8List psk;
      String binderHash;
      bool external;

      // Identities that are tickets don't carry PSK directly
      if (ticketIdens.contains(iden.identity)) {
        binderHash = resMasterSecret!.length == 32 ? 'sha256' : 'sha384';
        psk = calcResBinderPsk(iden, resMasterSecret, tickets!);
        external = false;
      } else {
        // Find matching config
        dynamic config;
        while (configsIter.moveNext()) {
          config = configsIter.current;
          if (config[0] == iden.identity) break;
        }

        if (config == null) {
          throw ArgumentError(
            "psk_configs don't match the PreSharedKeyExtension",
          );
        }

        binderHash = config.length > 2 ? config[2] : 'sha256';
        psk = config[1];
        external = true;
      }

      final binder = calcBinder(binderHash, psk, hh, external: external);

      // Replace the fake value with calculated one
      ext.binders[i] = binder;
    }
  }

  /// Verify the PSK binder value in client hello
  static bool verifyBinder(
    dynamic clientHello,
    dynamic handshakeHashes,
    int position,
    Uint8List secret,
    String prf, {
    bool external = true,
  }) {
    final ext = clientHello.extensions.last;
    if (ext.runtimeType.toString() != 'PreSharedKeyExtension') {
      throw TLSIllegalParameterException(
        'Last extension in client_hello must be PreSharedKeyExtension',
      );
    }

    final hh = handshakeHashes.copy();
    hh.update(clientHello.psk_truncate());

    final binder = calcBinder(prf, secret, hh, external: external);

    if (!ctCompareDigest(binder, ext.binders[position])) {
      throw TLSIllegalParameterException('Binder does not verify');
    }

    return true;
  }
}

// Temporary stub for PaddingExtension
class _PaddingExtension {
  _PaddingExtension() : extType = ExtensionType.client_hello_padding;

  final int extType;
  Uint8List _paddingData = Uint8List(0);

  Uint8List get extData => _paddingData;

  _PaddingExtension create(int size) {
    if (size < 0 || size > 0xffff) {
      throw ArgumentError('Padding size must be in the range 0..65535');
    }
    _paddingData = Uint8List(size);
    return this;
  }

  Uint8List write() {
    final writer = Writer();
    writer.addTwo(extType);
    writer.addTwo(_paddingData.length);
    writer.addBytes(_paddingData);
    return writer.bytes;
  }
}
