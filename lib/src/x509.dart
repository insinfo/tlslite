// Ported to Dart from tlslite-ng tlslite/x509.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

import 'dart:convert';
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

  /// Textual subjectAltName entries (dNSName values and iPAddress values in
  /// dotted / colon notation, mixed). Kept for compatibility; prefer
  /// [dnsNames] and [ipAddresses], which keep the two name types apart.
  List<String>? subjectAltName;

  /// subjectAltName dNSName entries, exactly as encoded in the certificate.
  /// `null` when the certificate has no subjectAltName extension.
  List<String>? dnsNames;

  /// subjectAltName iPAddress entries as raw network-order bytes (4 bytes
  /// for IPv4, 16 for IPv6). `null` when there is no subjectAltName.
  List<Uint8List>? ipAddresses;

  /// basicConstraints cA flag; `null` when the extension is absent.
  bool? isCA;

  /// basicConstraints pathLenConstraint; `null` when absent.
  int? pathLenConstraint;

  /// keyUsage bits by name (e.g. `keyCertSign`); `null` when absent.
  Set<String>? keyUsage;

  /// extendedKeyUsage purpose OIDs in dotted notation; `null` when absent.
  List<String>? extendedKeyUsage;

  /// nameConstraints permitted dNSName subtrees (`null` when not present).
  List<String>? permittedDnsNames;

  /// nameConstraints excluded dNSName subtrees (`null` when not present).
  List<String>? excludedDnsNames;

  /// nameConstraints permitted iPAddress subtrees, each address||mask
  /// (8 bytes for IPv4, 32 for IPv6). `null` when not present.
  List<Uint8List>? permittedIpRanges;

  /// nameConstraints excluded iPAddress subtrees, each address||mask.
  List<Uint8List>? excludedIpRanges;

  /// Dotted OIDs of every extension marked critical.
  final Set<String> criticalExtensions = <String>{};

  /// Signature family of the certificate signature: `rsa-pkcs1`,
  /// `rsa-pss`, `ecdsa`, `dsa`, `Ed25519` or `Ed448`; `null` if the
  /// algorithm is not recognised (then [verify] returns false).
  String? signatureKind;

  /// Hash used by the certificate signature (`sha1`, `sha256`, ...), or
  /// `intrinsic` for EdDSA.
  String? signatureHashName;

  /// RSASSA-PSS salt length (RFC 4055 default 20); only for `rsa-pss`.
  int? signaturePssSaltLength;

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
    try {
      signatureAlgorithm =
          _resolveSignatureAlgorithm(signatureAlgorithmIdentifier);
    } on FormatException {
      signatureAlgorithm = null;
    }
    _resolveSignatureParameters(signatureAlgorithmIdentifier);
        
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
  ///
  /// Supports RSA PKCS#1 v1.5 and RSASSA-PSS (SHA-1/224/256/384/512),
  /// ECDSA (SHA-1/224/256/384/512 on any supported curve), DSA and
  /// Ed25519/Ed448. Returns `false` when the signature does not verify, when
  /// the key type does not match the signature algorithm, or when the
  /// signature algorithm is not recognised.
  bool verify(Object issuerPublicKey) {
    final tbs = tbsCertificateBytes;
    final sig = signatureValue;
    if (tbs == null || sig == null) {
      throw StateError('Certificate not parsed or incomplete');
    }
    final kind = signatureKind;
    final hashName = signatureHashName;
    if (kind == null || hashName == null) {
      return false;
    }
    try {
      switch (kind) {
        case 'rsa-pkcs1':
          if (issuerPublicKey is! RSAKey) return false;
          return issuerPublicKey.verify(sig, secureHash(tbs, hashName),
              padding: 'pkcs1', hashAlg: hashName);
        case 'rsa-pss':
          if (issuerPublicKey is! RSAKey) return false;
          return issuerPublicKey.verify(sig, secureHash(tbs, hashName),
              padding: 'pss',
              hashAlg: hashName,
              saltLen: signaturePssSaltLength ?? 20);
        case 'ecdsa':
          if (issuerPublicKey is! ECDSAKey) return false;
          return issuerPublicKey.verify(sig, secureHash(tbs, hashName));
        case 'dsa':
          if (issuerPublicKey is! DSAKey) return false;
          return issuerPublicKey.verify(sig, secureHash(tbs, hashName));
        case 'Ed25519':
        case 'Ed448':
          if (issuerPublicKey is! EdDSAKey) return false;
          return issuerPublicKey.hashAndVerify(sig, tbs);
      }
    } on ArgumentError {
      return false;
    } on FormatException {
      return false;
    } on StateError {
      return false;
    }
    return false;
  }

  /// Common name (CN) attribute values of the subject, in encoding order.
  List<String> get subjectCommonNames {
    final der = subject;
    if (der == null) return const [];
    return [
      for (final attr in x509NameAttributes(der))
        if (attr.key == '2.5.4.3') attr.value
    ];
  }

  /// Human readable subject DN, e.g. `CN=example.com, O=Example`.
  String get subjectString =>
      subject == null ? '' : formatX509Name(subject!);

  /// Human readable issuer DN.
  String get issuerString => issuer == null ? '' : formatX509Name(issuer!);

  void _resolveSignatureParameters(ASN1Parser algIdentifier) {
    signatureKind = null;
    signatureHashName = null;
    signaturePssSaltLength = null;
    final List<int> oid;
    try {
      oid = _decodeObjectIdentifier(algIdentifier.getChild(0).value);
    } on Object {
      return;
    }
    final dotted = oid.join('.');
    final known = _signatureOids[dotted];
    if (known != null) {
      signatureKind = known.$1;
      signatureHashName = known.$2;
      return;
    }
    if (dotted == '1.2.840.113549.1.1.10') {
      // RSASSA-PSS-params ::= SEQUENCE {
      //   hashAlgorithm [0] HashAlgorithm DEFAULT sha1,
      //   maskGenAlgorithm [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
      //   saltLength [2] INTEGER DEFAULT 20,
      //   trailerField [3] TrailerField DEFAULT trailerFieldBC }
      var hash = 'sha1';
      var mgfHash = 'sha1';
      var salt = 20;
      try {
        if (algIdentifier.getChildCount() > 1) {
          final params = algIdentifier.getChild(1);
          final count = params.getChildCount();
          for (var i = 0; i < count; i++) {
            final field = params.getChild(i);
            if (field.type.tagClass != 2) continue;
            final inner = ASN1Parser(field.value);
            switch (field.type.tagId) {
              case 0:
                final h = _hashOids[
                    _decodeObjectIdentifier(inner.getChild(0).value).join('.')];
                if (h == null) return;
                hash = h;
                break;
              case 1:
                // MGF1 with a hash AlgorithmIdentifier parameter.
                final mgfOid =
                    _decodeObjectIdentifier(inner.getChild(0).value).join('.');
                if (mgfOid != '1.2.840.113549.1.1.8') return;
                final mgfParams = inner.getChild(1);
                final h = _hashOids[
                    _decodeObjectIdentifier(mgfParams.getChild(0).value)
                        .join('.')];
                if (h == null) return;
                mgfHash = h;
                break;
              case 2:
                salt = bytesToNumber(inner.value).toInt();
                break;
              case 3:
                if (bytesToNumber(inner.value) != BigInt.one) return;
                break;
            }
          }
        }
      } on Object {
        return;
      }
      // The RSA backend uses the same hash for MGF1 as for the message.
      if (mgfHash != hash) return;
      signatureKind = 'rsa-pss';
      signatureHashName = hash;
      signaturePssSaltLength = salt;
    }
  }

  void _parseExtensions(ASN1Parser extensionsSeq) {
    final count = extensionsSeq.getChildCount();
    for (var i = 0; i < count; i++) {
      final extension = extensionsSeq.getChild(i);
      final oid = _decodeObjectIdentifier(extension.getChild(0).value);

      var valueIndex = 1;
      final second = extension.getChild(1);
      if (second.type.tagClass == 0 && second.type.tagId == 1) {
        // BOOLEAN (critical)
        valueIndex = 2;
        if (second.value.isNotEmpty && second.value[0] != 0) {
          criticalExtensions.add(oid.join('.'));
        }
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
      } else if (_oidEquals(oid, _oidNameConstraints)) {
        _parseNameConstraints(extValue);
      }
    }
  }

  void _parseSubjectAltName(Uint8List data) {
    final parser = ASN1Parser(data);
    final count = parser.getChildCount();
    subjectAltName = [];
    dnsNames = [];
    ipAddresses = [];
    for (var i = 0; i < count; i++) {
      final item = parser.getChild(i);
      // dNSName [2] IA5String
      if (item.type.tagClass == 2 && item.type.tagId == 2) {
        final name = String.fromCharCodes(item.value);
        subjectAltName!.add(name);
        dnsNames!.add(name);
      }
      // iPAddress [7] OCTET STRING
      else if (item.type.tagClass == 2 && item.type.tagId == 7) {
        // Convert IP bytes to string representation
        final ipBytes = item.value;
        if (ipBytes.length == 4 || ipBytes.length == 16) {
          ipAddresses!.add(Uint8List.fromList(ipBytes));
        }
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
      } else if (first.type.tagId == 2) {
        // cA omitted (DEFAULT FALSE) but pathLenConstraint present.
        pathLenConstraint = bytesToNumber(first.value).toInt();
      }
    }
  }

  void _parseKeyUsage(Uint8List data) {
    // KeyUsage ::= BIT STRING. The extension value is the full DER
    // encoding (tag, length, unused-bits octet, bits).
    final bitString = ASN1Parser(data);
    if (bitString.type.tagId != 3 || bitString.value.isEmpty) return;
    // First value octet is the number of unused bits; we test named bits.
    final bits = bitString.value.sublist(1);
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

  void _parseNameConstraints(Uint8List data) {
    // NameConstraints ::= SEQUENCE {
    //   permittedSubtrees [0] GeneralSubtrees OPTIONAL,
    //   excludedSubtrees  [1] GeneralSubtrees OPTIONAL }
    final parser = ASN1Parser(data);
    final count = parser.getChildCount();
    for (var i = 0; i < count; i++) {
      final subtrees = parser.getChild(i);
      if (subtrees.type.tagClass != 2) continue;
      final permitted = subtrees.type.tagId == 0;
      final dns = <String>[];
      final ips = <Uint8List>[];
      // [n] IMPLICIT SEQUENCE OF GeneralSubtree: the value holds the items.
      final n = subtrees.getChildCount();
      for (var j = 0; j < n; j++) {
        final subtree = subtrees.getChild(j);
        final base = subtree.getChild(0);
        if (base.type.tagClass == 2 && base.type.tagId == 2) {
          dns.add(String.fromCharCodes(base.value));
        } else if (base.type.tagClass == 2 && base.type.tagId == 7) {
          ips.add(Uint8List.fromList(base.value));
        }
      }
      if (permitted) {
        permittedDnsNames = dns;
        permittedIpRanges = ips;
      } else {
        excludedDnsNames = dns;
        excludedIpRanges = ips;
      }
    }
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
    final digestBytes = Uint8List.fromList(sha1(bytes));
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
    if (_bytesEqual(oidBytes, rsaPssOid)) {
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

  List<int> _decodeObjectIdentifier(Uint8List oidValue) =>
      _decodeOidArcs(oidValue);

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

// Extension OIDs are compared against decoded arcs.
const List<int> _oidSubjectAltName = [2, 5, 29, 17];
const List<int> _oidBasicConstraints = [2, 5, 29, 19];
const List<int> _oidKeyUsage = [2, 5, 29, 15];
const List<int> _oidExtendedKeyUsage = [2, 5, 29, 37];
const List<int> _oidNameConstraints = [2, 5, 29, 30];

/// Certificate signature algorithm OIDs -> (signature kind, hash).
const Map<String, (String, String)> _signatureOids = {
  '1.2.840.113549.1.1.4': ('rsa-pkcs1', 'md5'),
  '1.2.840.113549.1.1.5': ('rsa-pkcs1', 'sha1'),
  '1.2.840.113549.1.1.14': ('rsa-pkcs1', 'sha224'),
  '1.2.840.113549.1.1.11': ('rsa-pkcs1', 'sha256'),
  '1.2.840.113549.1.1.12': ('rsa-pkcs1', 'sha384'),
  '1.2.840.113549.1.1.13': ('rsa-pkcs1', 'sha512'),
  '1.2.840.10045.4.1': ('ecdsa', 'sha1'),
  '1.2.840.10045.4.3.1': ('ecdsa', 'sha224'),
  '1.2.840.10045.4.3.2': ('ecdsa', 'sha256'),
  '1.2.840.10045.4.3.3': ('ecdsa', 'sha384'),
  '1.2.840.10045.4.3.4': ('ecdsa', 'sha512'),
  '1.2.840.10040.4.3': ('dsa', 'sha1'),
  '2.16.840.1.101.3.4.3.1': ('dsa', 'sha224'),
  '2.16.840.1.101.3.4.3.2': ('dsa', 'sha256'),
  '1.3.101.112': ('Ed25519', 'intrinsic'),
  '1.3.101.113': ('Ed448', 'intrinsic'),
};

/// Hash algorithm OIDs used inside RSASSA-PSS parameters.
const Map<String, String> _hashOids = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.4': 'sha224',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};

const Map<String, String> _nameAttributeShortNames = {
  '2.5.4.3': 'CN',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.5': 'serialNumber',
  '0.9.2342.19200300.100.1.25': 'DC',
  '1.2.840.113549.1.9.1': 'emailAddress',
};

/// Decodes a DER X.501 `Name` into (dotted attribute OID, string value)
/// pairs, in encoding order. Values that are not strings are rendered as
/// `#hex`.
List<MapEntry<String, String>> x509NameAttributes(Uint8List nameDer) {
  final result = <MapEntry<String, String>>[];
  final name = ASN1Parser(nameDer);
  final rdnCount = name.getChildCount();
  for (var i = 0; i < rdnCount; i++) {
    final rdn = name.getChild(i);
    final attrCount = rdn.getChildCount();
    for (var j = 0; j < attrCount; j++) {
      final attr = rdn.getChild(j);
      final oid = _decodeOidArcs(attr.getChild(0).value).join('.');
      final value = attr.getChild(1);
      result.add(MapEntry(oid, _decodeDirectoryString(value)));
    }
  }
  return result;
}

/// Formats a DER X.501 `Name` as `CN=..., O=...` (encoding order).
String formatX509Name(Uint8List nameDer) {
  try {
    return x509NameAttributes(nameDer)
        .map((e) => '${_nameAttributeShortNames[e.key] ?? e.key}=${e.value}')
        .join(', ');
  } on Object {
    return '<unparseable name>';
  }
}

String _decodeDirectoryString(ASN1Parser value) {
  final bytes = value.value;
  if (value.type.tagClass != 0) return '#${hexEncode(bytes)}';
  switch (value.type.tagId) {
    case 12: // UTF8String
      return utf8.decode(bytes, allowMalformed: true);
    case 19: // PrintableString
    case 22: // IA5String
    case 20: // TeletexString (treated as Latin-1)
    case 26: // VisibleString
      return String.fromCharCodes(bytes);
    case 30: // BMPString (UTF-16BE)
      final units = <int>[];
      for (var i = 0; i + 1 < bytes.length; i += 2) {
        units.add((bytes[i] << 8) | bytes[i + 1]);
      }
      return String.fromCharCodes(units);
    case 28: // UniversalString (UTF-32BE)
      final runes = <int>[];
      for (var i = 0; i + 3 < bytes.length; i += 4) {
        runes.add((bytes[i] << 24) |
            (bytes[i + 1] << 16) |
            (bytes[i + 2] << 8) |
            bytes[i + 3]);
      }
      return String.fromCharCodes(runes);
    default:
      return '#${hexEncode(bytes)}';
  }
}

List<int> _decodeOidArcs(Uint8List oidValue) {
  if (oidValue.isEmpty) {
    throw const FormatException('OID encoding is empty');
  }
  final arcs = <int>[];
  var value = 0;
  var first = true;
  for (final byte in oidValue) {
    value = (value << 7) | (byte & 0x7f);
    if ((byte & 0x80) == 0) {
      if (first) {
        if (value < 80) {
          arcs..add(value ~/ 40)..add(value % 40);
        } else {
          arcs..add(2)..add(value - 80);
        }
        first = false;
      } else {
        arcs.add(value);
      }
      value = 0;
    }
  }
  return arcs;
}
