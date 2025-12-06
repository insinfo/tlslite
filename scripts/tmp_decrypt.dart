import 'dart:typed_data';

import 'package:tlslite/src/mathtls.dart';
import 'package:tlslite/src/messages.dart';
import 'package:tlslite/src/tls_protocol.dart';
import 'package:tlslite/src/utils/chacha20_poly1305.dart';

Uint8List hexToBytes(String hex) {
  hex = hex.replaceAll(RegExp(r'[^0-9a-fA-F]'), '');
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String toHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

Uint8List buildNonce(Uint8List fixedNonce, Uint8List seqnum) {
  final padded = Uint8List(fixedNonce.length);
  // seqnum is 8 bytes; left-pad with zeros to 12.
  padded.setRange(fixedNonce.length - seqnum.length, fixedNonce.length, seqnum);
  final out = Uint8List(fixedNonce.length);
  for (var i = 0; i < out.length; i++) {
    out[i] = padded[i] ^ fixedNonce[i];
  }
  return out;
}

void tryDecrypt({
  required String label,
  required Uint8List clientRandom,
  required Uint8List serverRandom,
  required Uint8List masterSecret,
  required Uint8List ciphertextWithTag,
}) {
  final keyBlock = calcKey(
    const [3, 3],
    masterSecret,
    0xcca8,
    Uint8List.fromList('key expansion'.codeUnits),
    clientRandom: clientRandom,
    serverRandom: serverRandom,
    outputLength: 88,
  );

  final clientKey = keyBlock.sublist(0, 32);
  final serverKey = keyBlock.sublist(32, 64);
  final clientIV = keyBlock.sublist(64, 76);
  final serverIV = keyBlock.sublist(76, 88);

  final seqnum = Uint8List(8); // first encrypted record
  final aad = Uint8List.fromList([
    ...seqnum,
    22, // handshake
    3,
    3,
    (ciphertextWithTag.length - 16) >> 8,
    (ciphertextWithTag.length - 16) & 0xff,
  ]);

  final nonce = buildNonce(serverIV, seqnum);
  final cipher = Chacha20Poly1305(serverKey, 'python');
  final opened = cipher.open(nonce, ciphertextWithTag, aad);

  print('--- $label ---');
  print('clientKey=${toHex(clientKey)}');
  print('serverKey=${toHex(serverKey)}');
  print('clientIV=${toHex(clientIV)}');
  print('serverIV=${toHex(serverIV)}');
  print('nonce=${toHex(nonce)}');
  print('opened len=${opened?.length}');
  if (opened != null) {
    print('opened=${toHex(opened)}');
  }
}

void main() {
  final masterSecret = hexToBytes(
    '9f9ac33d9a02bb79600e6523ba08b7d2aa1a3fc3a9d25d7b44301ba17d872883514a02e4a6cedf9e98be97268525b26c',
  );
  final clientRandom = hexToBytes(
    '0b0161e4bcf33ba237b0d48846662b66e6be4a88f20baddcac6993cdc2027e4a',
  );
  final serverRandom = hexToBytes(
    '63b31c25ee223ded0364789d83bfaa5054bcb74e2cc992012ea3a38b5b3fc556',
  );
  final ciphertext = hexToBytes(
    '040000a600001c2000a04e306c06f308f04ad259b40470b300f31df39273c3ae76aae6a14e07a326f945938387b0c1ab3f83654e96f1ba677642f82337833209726a2795b5b52f5038951c2e876e65be6e39d27ea07cad608abecdf124a7639f88d26236383744373c2db25f76a5a467853a3d87b6c7ff2b888b94efdebee79fbe2f6a6cd1f75282742bb9cbbb02982a962a944501ef541fb69b960fb5eb724fda71d244b6749599f4e3',
  );

  tryDecrypt(
    label: 'server+client seed',
    clientRandom: clientRandom,
    serverRandom: serverRandom,
    masterSecret: masterSecret,
    ciphertextWithTag: ciphertext,
  );

  tryDecrypt(
    label: 'client+server seed',
    clientRandom: serverRandom,
    serverRandom: clientRandom,
    masterSecret: masterSecret,
    ciphertextWithTag: ciphertext,
  );

  try {
    final messages = TlsHandshakeMessage.parseFragment(
      ciphertext,
      recordVersion: const TlsProtocolVersion(3, 3),
    );
    print('parsed ${messages.length} handshake messages: '
        '${messages.map((m) => m.handshakeType.name).join(', ')}');
  } catch (e, st) {
    print('parse error: $e');
    print(st);
  }
}
