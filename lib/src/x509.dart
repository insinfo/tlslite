import 'dart:typed_data';

import 'constants.dart';
import 'utils/asn1parser.dart';
import 'utils/compat.dart';
import 'utils/cryptomath.dart';
import 'utils/keyfactory.dart';
import 'utils/pem.dart';
import 'utils/rsakey.dart';
import 'utils/ecdsakey.dart';
import 'utils/eddsakey.dart';
import 'utils/dsakey.dart';

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

  // Extensions
  List<String>? subjectAltName;
  bool? isCA;
  int? pathLenConstraint;
  Set<String>? keyUsage;
  List<String>? extendedKeyUsage;

  /// Raw signature bytes.
  Uint8List? signatureValue;

  /// Raw TBSCertificate bytes (signed data).
  Uint8List? tbsCertificateBytes;

  /// Parse a PEM certificate and populate this instance.
  X509 parse(String pem) {
    final der = dePem(pem, 'CERTIFICATE');
    return parseBinary(der);
  }

  /// Parse DER certificate bytes and populate this instance.
  X509 parseBinary(Uint8List certBytes) {
    bytes = Uint8List.fromList(certBytes);
    final parser = ASN1Parser(bytes);
    
    tbsCertificateBytes = Uint8List.fromList(parser.getChildBytes(0));
    final tbsCertificate = parser.getChild(0);
    
    final signatureAlgorithmIdentifier = parser.getChild(1);
    signatureAlgorithm =
        _resolveSignatureAlgorithm(signatureAlgorithmIdentifier);
        
    final signatureValueBitString = parser.getChild(2);
    signatureValue = Uint8List.fromList(_extractBitString(signatureValueBitString.value));

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

    // Parse optional fields (IssuerUniqueID, SubjectUniqueID, Extensions)
    final totalChildren = tbsCertificate.getChildCount();
    for (var i = subjectPublicKeyInfoIndex + 1; i < totalChildren; i++) {
      final child = tbsCertificate.getChild(i);
      // Extensions is [3] EXPLICIT
      if (child.type.tagClass == 2 && child.type.tagId == 3) {
        final extensionsSeq = ASN1Parser(child.value);
        _parseExtensions(extensionsSeq);
      }
    }

    return this;
  }

  /// Verify the certificate signature against the issuer's public key.
  bool verify(Object issuerPublicKey) {
    if (tbsCertificateBytes == null || signatureValue == null || signatureAlgorithm == null) {
      throw StateError('Certificate not parsed or incomplete');
    }

    String? hashName;
    String? padding;
    
    if (signatureAlgorithm is int) {
        final schemeName = SignatureScheme.toRepr(signatureAlgorithm);
        if (schemeName == null) throw FormatException('Unknown signature scheme');
        
        hashName = SignatureScheme.getHash(schemeName);
        padding = SignatureScheme.getPadding(schemeName);
        if (padding.isEmpty) padding = null;
        
        // Handle EdDSA special case (intrinsic hash)
        if (schemeName == 'ed25519' || schemeName == 'ed448') {
            hashName = 'intrinsic';
            padding = null;
        }
    } else if (signatureAlgorithm is List) {
        // Legacy tuple [hashAlg, sigAlg]
        final hashAlg = signatureAlgorithm[0];
        final sigAlg = signatureAlgorithm[1];
        hashName = HashAlgorithm.toRepr(hashAlg);
        if (sigAlg == SignatureAlgorithm.rsa) {
            padding = 'pkcs1';
        } else if (sigAlg == SignatureAlgorithm.dsa) {
            padding = null;
        }
    } else {
        throw FormatException('Unknown signature algorithm format');
    }

    if (hashName == null) throw FormatException('Unknown hash algorithm');

    // Calculate digest or use raw bytes
    Uint8List dataToVerify;
    if (hashName == 'intrinsic') {
        dataToVerify = tbsCertificateBytes!;
    } else {
        dataToVerify = secureHash(tbsCertificateBytes!, hashName);
    }

    // Verify
    if (issuerPublicKey is RSAKey) {
        return issuerPublicKey.verify(signatureValue!, dataToVerify, padding: padding ?? 'pkcs1', hashAlg: hashName);
    } else if (issuerPublicKey is ECDSAKey) {
        return issuerPublicKey.verify(signatureValue!, dataToVerify);
    } else if (issuerPublicKey is EdDSAKey) {
        return issuerPublicKey.hashAndVerify(signatureValue!, dataToVerify);
    } else if (issuerPublicKey is DSAKey) {
        return issuerPublicKey.verify(signatureValue!, dataToVerify);
    } else {
        throw UnimplementedError('Unsupported issuer key type: ${issuerPublicKey.runtimeType}');
    }
  }

  void _parseExtensions(ASN1Parser extensionsSeq) {
    final count = extensionsSeq.getChildCount();
    for (var i = 0; i < count; i++) {
      final extension = extensionsSeq.getChild(i);
      final oid = _decodeObjectIdentifier(extension.getChild(0).value);
      
      var valueIndex = 1;
      if (extension.getChild(1).type.tagId == 1) { // BOOLEAN (critical)
         valueIndex = 2;
      }
      
      final extValueOctet = extension.getChild(valueIndex);
      // The extension value is an OCTET STRING containing the DER encoding of the extension value.
      final extValue = extValueOctet.value;
      
      if (_oidEquals(oid, _oidSubjectAltName)) {
        _parseSubjectAltName(extValue);
      } else if (_oidEquals(oid, _oidBasicConstraints)) {
        _parseBasicConstraints(extValue);
      } else if (_oidEquals(oid, _oidKeyUsage)) {
        _parseKeyUsage(extValue);
      } else if (_oidEquals(oid, _oidExtendedKeyUsage)) {
        _parseExtendedKeyUsage(extValue);
      }
    }
  }

  void _parseSubjectAltName(Uint8List data) {
    final parser = ASN1Parser(data);
    final count = parser.getChildCount();
    subjectAltName = [];
    for (var i = 0; i < count; i++) {
      final item = parser.getChild(i);
      // dNSName [2] IA5String
      if (item.type.tagClass == 2 && item.type.tagId == 2) {
        subjectAltName!.add(String.fromCharCodes(item.value));
      }
      // iPAddress [7] OCTET STRING
      else if (item.type.tagClass == 2 && item.type.tagId == 7) {
        // Convert IP bytes to string representation
        final ipBytes = item.value;
        if (ipBytes.length == 4) {
          // IPv4 address
          subjectAltName!.add(ipBytes.join('.'));
        } else if (ipBytes.length == 16) {
          // IPv6 address - convert to standard notation
          final parts = <String>[];
          for (var j = 0; j < 16; j += 2) {
            parts.add(((ipBytes[j] << 8) | ipBytes[j + 1]).toRadixString(16));
          }
          subjectAltName!.add(parts.join(':'));
        }
        // Skip malformed IP addresses silently
      }
    }
  }

  void _parseBasicConstraints(Uint8List data) {
    final parser = ASN1Parser(data);
    isCA = false;
    if (parser.getChildCount() > 0) {
      final first = parser.getChild(0);
      if (first.type.tagId == 1) { // BOOLEAN
        isCA = first.value.isNotEmpty && first.value[0] != 0;
        if (parser.getChildCount() > 1) {
          final second = parser.getChild(1);
          if (second.type.tagId == 2) { // INTEGER
            pathLenConstraint = bytesToNumber(second.value).toInt();
          }
        }
      }
    }
  }

  void _parseKeyUsage(Uint8List data) {
    // KeyUsage ::= BIT STRING
    // We need to parse the BIT STRING (skip unused bits byte)
    if (data.length < 2) return; // Invalid
    // First byte is number of unused bits, we ignore for now as we check specific bits
    final bits = data.sublist(1);
    keyUsage = {};
    
    bool isBitSet(int byteIndex, int bitIndex) {
      if (byteIndex >= bits.length) return false;
      return (bits[byteIndex] & (1 << (7 - bitIndex))) != 0;
    }

    if (isBitSet(0, 0)) keyUsage!.add('digitalSignature');
    if (isBitSet(0, 1)) keyUsage!.add('nonRepudiation');
    if (isBitSet(0, 2)) keyUsage!.add('keyEncipherment');
    if (isBitSet(0, 3)) keyUsage!.add('dataEncipherment');
    if (isBitSet(0, 4)) keyUsage!.add('keyAgreement');
    if (isBitSet(0, 5)) keyUsage!.add('keyCertSign');
    if (isBitSet(0, 6)) keyUsage!.add('cRLSign');
    if (isBitSet(0, 7)) keyUsage!.add('encipherOnly');
    if (isBitSet(1, 0)) keyUsage!.add('decipherOnly');
  }

  void _parseExtendedKeyUsage(Uint8List data) {
    final parser = ASN1Parser(data);
    final count = parser.getChildCount();
    extendedKeyUsage = [];
    for (var i = 0; i < count; i++) {
      final item = parser.getChild(i);
      final oid = _decodeObjectIdentifier(item.value);
      extendedKeyUsage!.add(oid.map((e) => e.toString()).join('.'));
    }
  }

  /// Hex fingerprint of the certificate (SHA-1 ).
  String getFingerprint() {
    final digestBytes = Uint8List.fromList(SHA1(bytes));
    return hexEncode(digestBytes);
  }

  // NOTE: TACK extension methods (getTackExt, checkTack) require utils/tackwrapper.dart
  // TACK is a rarely-used feature and not required for standard TLS operation.

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
    publicKey = DartRSAKey(
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

const List<int> _oidSubjectAltName = [85, 29, 17];
const List<int> _oidBasicConstraints = [85, 29, 19];
const List<int> _oidKeyUsage = [85, 29, 15];
const List<int> _oidExtendedKeyUsage = [85, 29, 37];
