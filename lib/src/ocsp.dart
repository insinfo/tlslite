import 'dart:typed_data';

import 'errors.dart';
import 'signed.dart';
import 'x509.dart';
import 'utils/asn1parser.dart';
import 'utils/cryptomath.dart';
import 'utils/rsakey.dart';

class OCSPRespStatus {
  static const int successful = 0;
  static const int malformedRequest = 1;
  static const int internalError = 2;
  static const int tryLater = 3;
  static const int sigRequired = 5;
  static const int unauthorized = 6;
}

class CertStatus {
  static const int good = 0;
  static const int revoked = 1;
  static const int unknown = 2;
}

class SingleResponse {
  SingleResponse(ASN1Parser node) {
    _parse(node);
  }

  late final Uint8List certHashAlgorithm;
  late final Uint8List certIssuerNameHash;
  late final Uint8List certIssuerKeyHash;
  late final BigInt certSerialNumber;
  late final Uint8List certStatus;
  late final Uint8List thisUpdate;
  Uint8List? nextUpdate;

  static final Map<String, String> _hashAlgsOids = {
    _oidKey([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05]): 'md5',
    _oidKey([0x2b, 0x0e, 0x03, 0x02, 0x1a]): 'sha1',
    _oidKey([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04]): 'sha224',
    _oidKey([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]): 'sha256',
    _oidKey([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02]): 'sha384',
    _oidKey([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03]): 'sha512',
  };

  void _parse(ASN1Parser value) {
    final certId = value.getChild(0);
    certHashAlgorithm = Uint8List.fromList(
      certId.getChild(0).getChild(0).value,
    );
    certIssuerNameHash = Uint8List.fromList(certId.getChild(1).value);
    certIssuerKeyHash = Uint8List.fromList(certId.getChild(2).value);
    certSerialNumber = bytesToNumber(certId.getChild(3).value);
    certStatus = Uint8List.fromList(value.getChild(1).value);
    thisUpdate = Uint8List.fromList(value.getChild(2).value);
    nextUpdate = null;
    if (value.getChildCount() > 3) {
      final field = value.getChild(3);
      if (field.type.tagId == 0) {
        nextUpdate = Uint8List.fromList(field.value);
      }
    }
  }

  bool verifyCertMatch(X509 serverCert, X509 issuerCert) {
    final issuerKey = issuerCert.subjectPublicKey;
    final issuerName = issuerCert.subject;
    final serial = serverCert.serialNumber;
    if (issuerKey == null) {
      throw ArgumentError('Issuer certificate missing subject public key');
    }
    if (issuerName == null) {
      throw ArgumentError('Issuer certificate missing subject name');
    }
    if (serial == null) {
      throw ArgumentError('Server certificate missing serial number');
    }
    final alg = _hashAlgsOids[_oidKey(certHashAlgorithm)];
    if (alg == null) {
      throw TLSIllegalParameterException(
        'Unknown hash algorithm: ${certHashAlgorithm.toList()}',
      );
    }
    final hashedKey = secureHash(issuerKey, alg);
    if (!_bytesEqual(hashedKey, certIssuerKeyHash)) {
      throw StateError('Could not verify certificate public key');
    }
    final hashedName = secureHash(issuerName, alg);
    if (!_bytesEqual(hashedName, certIssuerNameHash)) {
      throw StateError('Could not verify certificate DN');
    }
    if (certSerialNumber != serial) {
      throw StateError('Could not verify certificate serial number');
    }
    return true;
  }
}

// TODO(port): OCSP integration pending:
// - Integration with tlsconnection.py for stapling
// - Certificate validation logic from x509.py (chain verification)
// - Full extension parsing in responses

class OCSPResponse extends SignedObject {
  OCSPResponse(List<int> value) {
    parse(value);
  }

  Uint8List bytes = Uint8List(0);
  int respStatus = OCSPRespStatus.internalError;
  Uint8List? respType;
  int version = 1;
  Uint8List? respId;
  Uint8List? producedAt;
  final List<SingleResponse> responses = [];
  final List<X509> certs = [];

  void parse(List<int> value) {
    bytes = Uint8List.fromList(value);
    final parser = ASN1Parser(bytes);
    final respStatusNode = parser.getChild(0);
    respStatus = respStatusNode.value.isEmpty ? 0 : respStatusNode.value.first;
    responses.clear();
    certs.clear();
    if (respStatus != OCSPRespStatus.successful) {
      return;
    }
    final respBytes = parser.getChild(1).getChild(0);
    respType = Uint8List.fromList(respBytes.getChild(0).value);
    final response = respBytes.getChild(1);
    if (!_bytesEqual(respType!, _idPkixOcspBasic)) {
      throw const FormatException('Unsupported OCSP response type');
    }
    final basicResp = response.getChild(0);
    _parseTbsData(basicResp.getChild(0));
    tbsData = basicResp.getChildBytes(0);
    signatureAlgorithm = Uint8List.fromList(
      basicResp.getChild(1).getChild(0).value,
    );
    signature = Uint8List.fromList(basicResp.getChild(2).value);
    if (basicResp.getChildCount() > 3) {
      final certSeq = basicResp.getChild(3);
      final count = certSeq.getChildCount();
      for (var i = 0; i < count; i++) {
        final certificate = X509();
        certificate.parseBinary(certSeq.getChild(i).value);
        certs.add(certificate);
      }
    }
  }

  void _parseTbsData(ASN1Parser value) {
    final firstField = value.getChild(0);
    var offset = 0;
    if (firstField.type.tagId == 0) {
      version = bytesToNumber(firstField.value).toInt();
      offset = 1;
    } else {
      version = 1;
    }
    respId = Uint8List.fromList(value.getChild(offset).value);
    producedAt = Uint8List.fromList(value.getChild(offset + 1).value);
    final responsesNode = value.getChild(offset + 2);
    final count = responsesNode.getChildCount();
    for (var i = 0; i < count; i++) {
      responses.add(SingleResponse(responsesNode.getChild(i)));
    }
  }

  bool verifySignature(RSAKey publicKey, {SignatureSettings? settings}) {
    return super.verifySignature(publicKey, settings: settings);
  }
}

const List<int> _idPkixOcspBasic = [43, 6, 1, 5, 5, 7, 48, 1, 1];

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

String _oidKey(List<int> oid) => oid.join(',');
