import 'dart:typed_data';

import 'constants.dart';
import 'utils/asn1parser.dart';
import 'utils/compat.dart';
import 'utils/cryptomath.dart';
import 'utils/keyfactory.dart';
import 'utils/pem.dart';
import 'utils/rsakey.dart';

/// Representation of an X.509 certificate (DER or PEM).
class X509 {
  X509();

  /// DER-encoded certificate bytes.
  Uint8List bytes = Uint8List(0);

  /// Certificate serial number.
  BigInt? serialNumber;

  /// Raw SubjectPublicKey (BIT STRING payload).
  Uint8List? subjectPublicKey;

  /// Parsed subject public key instance (RSA/DSA/ECDSA/EdDSA).
  Object? publicKey;

  /// DER-encoded subject distinguished name.
  Uint8List? subject;

  /// Algorithm of the subject key (rsa, rsa-pss, ecdsa, dsa, Ed25519, Ed448).
  String? certAlg;

  /// Parsed signature algorithm identifier (SignatureScheme or legacy tuple).
  dynamic signatureAlgorithm;

  /// DER-encoded issuer distinguished name.
  Uint8List? issuer;

  /// Start of validity period.
  DateTime? notBefore;

  /// End of validity period.
  DateTime? notAfter;

  /// Parse a PEM certificate and populate this instance.
  X509 parse(String pem) {
    final der = dePem(pem, 'CERTIFICATE');
    return parseBinary(der);
  }

  /// Parse DER certificate bytes and populate this instance.
  X509 parseBinary(Uint8List certBytes) {
    bytes = Uint8List.fromList(certBytes);
    final parser = ASN1Parser(bytes);
    final signatureAlgorithmIdentifier = parser.getChild(1);
    signatureAlgorithm =
        _resolveSignatureAlgorithm(signatureAlgorithmIdentifier);

    final tbsCertificate = parser.getChild(0);
    final hasVersionField =
        tbsCertificate.value.isNotEmpty && tbsCertificate.value.first == 0xa0;
    final serialIndex = hasVersionField ? 1 : 0;
    final subjectPublicKeyInfoIndex = hasVersionField ? 6 : 5;

    serialNumber = bytesToNumber(tbsCertificate.getChild(serialIndex).value);
    issuer = Uint8List.fromList(
      tbsCertificate.getChildBytes(subjectPublicKeyInfoIndex - 3),
    );
    
    final validity = tbsCertificate.getChild(subjectPublicKeyInfoIndex - 2);
    notBefore = _parseAsn1Time(validity.getChild(0));
    notAfter = _parseAsn1Time(validity.getChild(1));

    subject = Uint8List.fromList(
      tbsCertificate.getChildBytes(subjectPublicKeyInfoIndex - 1),
    );

    final subjectPublicKeyInfo =
        tbsCertificate.getChild(subjectPublicKeyInfoIndex);
    final publicKeyBytes =
        _extractBitString(subjectPublicKeyInfo.getChild(1).value);
    subjectPublicKey = Uint8List.fromList(publicKeyBytes);
    _parsePublicKey(subjectPublicKeyInfo, publicKeyBytes);
    return this;
  }

  /// Hex fingerprint of the certificate (SHA-1 as in tlslite-ng).
  String getFingerprint() {
    final digestBytes = Uint8List.fromList(SHA1(bytes));
    return hexEncode(digestBytes);
  }

  // TODO(port): Missing methods from Python x509.py:
  // - getTackExt(): Extract TACK extension (requires utils/tackwrapper.dart)
  // - checkTack(tack): Validate TACK (requires utils/tackwrapper.dart)
  // - Full extension parsing (currently only basic cert fields are extracted)

  /// Return the raw DER certificate bytes.
  Uint8List writeBytes() => bytes;

  @override
  int get hashCode => Object.hashAll(bytes);

  @override
  bool operator ==(Object other) {
    return other is X509 && _bytesEqual(bytes, other.bytes);
  }

  DateTime _parseAsn1Time(ASN1Parser node) {
    final text = String.fromCharCodes(node.value);
    if (node.type.tagId == 0x17) {
      // UTCTime: YYMMDDHHMMSSZ
      // We need to handle the 2-digit year window.
      // RFC 5280 says:
      // Where YY is greater than or equal to 50, the year SHALL be 
      // interpreted as 19YY; and
      // Where YY is less than 50, the year SHALL be interpreted as 20YY.
      
      // However, datefuncs.dart might have helpers or we parse manually.
      // Let's check datefuncs.dart content again or just implement here.
      // I'll implement a simple parser here or use datefuncs if applicable.
      // parseDateClass in datefuncs expects YYYY-MM-DD...
      
      // Let's implement manual parsing for UTCTime/GeneralizedTime to DateTime
      
      var year = int.parse(text.substring(0, 2));
      if (year >= 50) {
        year += 1900;
      } else {
        year += 2000;
      }
      final month = int.parse(text.substring(2, 4));
      final day = int.parse(text.substring(4, 6));
      final hour = int.parse(text.substring(6, 8));
      final minute = int.parse(text.substring(8, 10));
      final second = int.parse(text.substring(10, 12));
      // Ignore timezone for now, assume Z
      return DateTime.utc(year, month, day, hour, minute, second);
    } else if (node.type.tagId == 0x18) {
      // GeneralizedTime: YYYYMMDDHHMMSSZ
      final year = int.parse(text.substring(0, 4));
      final month = int.parse(text.substring(4, 6));
      final day = int.parse(text.substring(6, 8));
      final hour = int.parse(text.substring(8, 10));
      final minute = int.parse(text.substring(10, 12));
      final second = int.parse(text.substring(12, 14));
      return DateTime.utc(year, month, day, hour, minute, second);
    }
    throw FormatException('Unknown time format tag: ${node.type.tagId}');
  }

  void _parsePublicKey(ASN1Parser spki, Uint8List publicKeyBytes) {
    final algIdentifier = spki.getChild(0);
    final algOid = algIdentifier.getChild(0).value.toList();
    certAlg = _classifyKeyAlgorithm(algOid);
    switch (certAlg) {
      case 'rsa':
      case 'rsa-pss':
        _parseRsaPublicKey(publicKeyBytes);
        break;
      case 'ecdsa':
        _parseEcdsaPublicKey(spki, publicKeyBytes);
        break;
      case 'dsa':
        _parseDsaPublicKey(spki, publicKeyBytes);
        break;
      case 'Ed25519':
      case 'Ed448':
        _parseEdDsaPublicKey(publicKeyBytes, certAlg!);
        break;
      default:
        throw const FormatException('Unrecognized AlgorithmIdentifier');
    }
  }

  void _parseRsaPublicKey(Uint8List publicKeyBytes) {
    final parser = ASN1Parser(publicKeyBytes);
    final modulus = bytesToNumber(parser.getChild(0).value);
    final exponent = bytesToNumber(parser.getChild(1).value);
    publicKey = PythonRSAKey(
      n: modulus,
      e: exponent,
      keyType: certAlg ?? 'rsa',
    );
  }

  void _parseEcdsaPublicKey(ASN1Parser spki, Uint8List publicKeyBytes) {
    final algIdentifier = spki.getChild(0);
    if (algIdentifier.getChildCount() != 2) {
      throw const FormatException('Missing EC parameters');
    }
    final curveOid =
      _decodeObjectIdentifier(algIdentifier.getChild(1).value);
    final curveName = curveNameFromOid(curveOid);
    if (curveName == null) {
      throw const FormatException('Unknown EC curve OID');
    }
    if (publicKeyBytes.isEmpty || publicKeyBytes.first != 0x04) {
      throw const FormatException('Unsupported EC point encoding');
    }
    final coords = publicKeyBytes.sublist(1);
    if (coords.length.isOdd) {
      throw const FormatException('Malformed EC point');
    }
    final coordLen = coords.length ~/ 2;
    final xBytes = Uint8List.fromList(coords.sublist(0, coordLen));
    final yBytes = Uint8List.fromList(coords.sublist(coordLen));
    final pointX = bytesToNumber(xBytes);
    final pointY = bytesToNumber(yBytes);
    publicKey = createPublicECDSAKey(pointX, pointY, curveName);
  }

  void _parseDsaPublicKey(ASN1Parser spki, Uint8List publicKeyBytes) {
    final algIdentifier = spki.getChild(0);
    if (algIdentifier.getChildCount() < 2) {
      throw const FormatException('Missing DSA parameters');
    }
    final params = algIdentifier.getChild(1);
    final p = bytesToNumber(params.getChild(0).value);
    final q = bytesToNumber(params.getChild(1).value);
    final g = bytesToNumber(params.getChild(2).value);
    final yParser = ASN1Parser(publicKeyBytes);
    final y = bytesToNumber(yParser.value);
    publicKey = createPublicDSAKey(p: p, q: q, g: g, y: y);
  }

  void _parseEdDsaPublicKey(Uint8List publicKeyBytes, String curveName) {
    publicKey = createPublicEdDSAKey(publicKeyBytes, curve: curveName);
  }

  dynamic _resolveSignatureAlgorithm(ASN1Parser algIdentifier) {
    final oidBytes = Uint8List.fromList(algIdentifier.getChildBytes(0));
    if (_bytesEqual(oidBytes, RSA_PSS_OID)) {
      if (algIdentifier.getChildCount() < 2) {
        throw const FormatException('RSASSA-PSS parameters missing');
      }
      final params = algIdentifier.getChild(1);
      if (params.getChildCount() == 0) {
        return AlgorithmOID.findSignatureSchemeForOid(oidBytes);
      }
      final hashAlgorithmTagged = params.getChild(0);
      final hashAlgorithm = ASN1Parser(hashAlgorithmTagged.value);
      final hashOidBytes =
          Uint8List.fromList(hashAlgorithm.getChildBytes(0));
      return AlgorithmOID.findSignatureSchemeForOid(hashOidBytes) ??
          (throw const FormatException('Unknown signature algorithm OID'));
    }
    return AlgorithmOID.findSignatureSchemeForOid(oidBytes) ??
        (throw const FormatException('Unknown signature algorithm OID'));
  }

  String _classifyKeyAlgorithm(List<int> oid) {
    if (_oidEquals(oid, _oidRsaEncryption)) {
      return 'rsa';
    }
    if (_oidEquals(oid, _oidRsaPss)) {
      return 'rsa-pss';
    }
    if (_oidEquals(oid, _oidDsa)) {
      return 'dsa';
    }
    if (_oidEquals(oid, _oidEcdsa)) {
      return 'ecdsa';
    }
    if (_oidEquals(oid, _oidEd25519)) {
      return 'Ed25519';
    }
    if (_oidEquals(oid, _oidEd448)) {
      return 'Ed448';
    }
    throw const FormatException('Unrecognized AlgorithmIdentifier');
  }

  Uint8List _extractBitString(Uint8List bitStringValue) {
    if (bitStringValue.isEmpty) {
      throw const FormatException('Invalid BIT STRING encoding');
    }
    if (bitStringValue.first != 0) {
      throw const FormatException('Unsupported BIT STRING padding');
    }
    return Uint8List.fromList(bitStringValue.sublist(1));
  }

  bool _bytesEqual(List<int> a, List<int> b) {
    if (a.length != b.length) {
      return false;
    }
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  List<int> _decodeObjectIdentifier(Uint8List oidValue) {
    if (oidValue.isEmpty) {
      throw const FormatException('OID encoding is empty');
    }
    final arcs = <int>[];
    final first = oidValue.first;
    arcs.add(first ~/ 40);
    arcs.add(first % 40);
    var value = 0;
    for (var i = 1; i < oidValue.length; i++) {
      final byte = oidValue[i];
      value = (value << 7) | (byte & 0x7f);
      if ((byte & 0x80) == 0) {
        arcs.add(value);
        value = 0;
      }
    }
    if (value != 0) {
      arcs.add(value);
    }
    return arcs;
  }

  bool _oidEquals(List<int> actual, List<int> expected) {
    if (actual.length != expected.length) {
      return false;
    }
    for (var i = 0; i < actual.length; i++) {
      if (actual[i] != expected[i]) {
        return false;
      }
    }
    return true;
  }
}

const List<int> _oidRsaEncryption = [42, 134, 72, 134, 247, 13, 1, 1, 1];
const List<int> _oidRsaPss = [42, 134, 72, 134, 247, 13, 1, 1, 10];
const List<int> _oidDsa = [42, 134, 72, 206, 56, 4, 1];
const List<int> _oidEcdsa = [42, 134, 72, 206, 61, 2, 1];
const List<int> _oidEd25519 = [43, 101, 112];
const List<int> _oidEd448 = [43, 101, 113];
