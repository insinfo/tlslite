import 'dart:typed_data';
import 'utils/asn1parser.dart';
import 'utils/pem.dart';
import 'utils/cryptomath.dart';

/// Parse DH parameters from ASN.1 DER encoded binary string.
///
/// Returns a tuple of (generator, prime).
(BigInt, BigInt) parseBinary(Uint8List data) {
  final parser = ASN1Parser(data);
  
  //  code:
  // prime = parser.getChild(0)
  // gen = parser.getChild(1)
  // return (bytesToNumber(gen.value), bytesToNumber(prime.value))
  
  final primeObj = parser.getChild(0);
  final genObj = parser.getChild(1);
  
  return (bytesToNumber(genObj.value), bytesToNumber(primeObj.value));
}

/// Parses DH parameters from a binary string.
///
/// The string can either by PEM or DER encoded.
/// Returns (generator, prime).
(BigInt, BigInt) parse(Uint8List data) {
  try {
    return parseBinary(data);
  } catch (_) {
    // Try PEM
    try {
        // dePem expects String usually, but let's see if we can convert
        // Or if dePem handles bytes.
        // In Dart port, pem.dart usually handles String.
        String s = String.fromCharCodes(data);
        final binData = dePem(s, "DH PARAMETERS");
        return parseBinary(binData);
    } catch (e) {
        throw FormatException('Could not parse DH parameters');
    }
  }
}
