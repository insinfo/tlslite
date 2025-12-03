import 'dart:typed_data';

import 'constants.dart';
import 'messages.dart' show TlsNewSessionTicket;
import 'x509certchain.dart';

/// Representation of a TLS session and related metadata.
class Session {
  Session();

  Uint8List masterSecret = Uint8List(0);
  Uint8List sessionID = Uint8List(0);
  int cipherSuite = 0;
  String srpUsername = '';
  X509CertChain? clientCertChain;
  X509CertChain? serverCertChain;
  dynamic tackExt;
  bool tackInHelloExt = false;
  String serverName = '';
  bool resumable = false;
  bool encryptThenMAC = false;
  bool extendedMasterSecret = false;
  Uint8List appProto = Uint8List(0);
  Uint8List clAppSecret = Uint8List(0);
  Uint8List srAppSecret = Uint8List(0);
  Uint8List clHandshakeSecret = Uint8List(0);
  Uint8List srHandshakeSecret = Uint8List(0);
  Uint8List exporterMasterSecret = Uint8List(0);
  Uint8List resumptionMasterSecret = Uint8List(0);
  List<Ticket>? tickets;
  List<Ticket>? tls10Tickets;
  int ecPointFormat = 0;
  List<TlsNewSessionTicket> tls13Tickets = <TlsNewSessionTicket>[];

  /// Populate the session with negotiated handshake data.
  void create({
    required List<int> masterSecret,
    required List<int> sessionID,
    required int cipherSuite,
    required String srpUsername,
    X509CertChain? clientCertChain,
    X509CertChain? serverCertChain,
    dynamic tackExt,
    required bool tackInHelloExt,
    required String serverName,
    bool resumable = true,
    bool encryptThenMAC = false,
    bool extendedMasterSecret = false,
    List<int>? appProto,
    List<int>? clAppSecret,
    List<int>? srAppSecret,
    List<int>? clHandshakeSecret,
    List<int>? srHandshakeSecret,
    List<int>? exporterMasterSecret,
    List<int>? resumptionMasterSecret,
    List<Ticket>? tickets,
    List<Ticket>? tls10Tickets,
    int? ecPointFormat,
    List<TlsNewSessionTicket>? tls13SessionTickets,
  }) {
    this.masterSecret = _bytes(masterSecret);
    this.sessionID = _bytes(sessionID);
    this.cipherSuite = cipherSuite;
    this.srpUsername = srpUsername;
    this.clientCertChain = clientCertChain;
    this.serverCertChain = serverCertChain;
    this.tackExt = tackExt;
    this.tackInHelloExt = tackInHelloExt;
    this.serverName = serverName;
    this.resumable = resumable;
    this.encryptThenMAC = encryptThenMAC;
    this.extendedMasterSecret = extendedMasterSecret;
    this.appProto = _bytes(appProto);
    this.clAppSecret = _bytes(clAppSecret);
    this.srAppSecret = _bytes(srAppSecret);
    this.clHandshakeSecret = _bytes(clHandshakeSecret);
    this.srHandshakeSecret = _bytes(srHandshakeSecret);
    this.exporterMasterSecret = _bytes(exporterMasterSecret);
    this.resumptionMasterSecret = _bytes(resumptionMasterSecret);
    this.tickets = tickets;
    this.tls10Tickets = tls10Tickets;
    if (ecPointFormat != null) {
      this.ecPointFormat = ecPointFormat;
    }
    if (tls13SessionTickets != null) {
      tls13Tickets = List<TlsNewSessionTicket>.from(tls13SessionTickets,
          growable: false);
    }
  }

  /// Shallow clone of this session (original semantics reuse lists/objects).
  Session clone() {
    final other = Session();
    other.masterSecret = masterSecret;
    other.sessionID = sessionID;
    other.cipherSuite = cipherSuite;
    other.srpUsername = srpUsername;
    other.clientCertChain = clientCertChain;
    other.serverCertChain = serverCertChain;
    other.tackExt = tackExt;
    other.tackInHelloExt = tackInHelloExt;
    other.serverName = serverName;
    other.resumable = resumable;
    other.encryptThenMAC = encryptThenMAC;
    other.extendedMasterSecret = extendedMasterSecret;
    other.appProto = appProto;
    other.clAppSecret = clAppSecret;
    other.srAppSecret = srAppSecret;
    other.clHandshakeSecret = clHandshakeSecret;
    other.srHandshakeSecret = srHandshakeSecret;
    other.exporterMasterSecret = exporterMasterSecret;
    other.resumptionMasterSecret = resumptionMasterSecret;
    other.tickets = tickets;
    other.tls10Tickets = tls10Tickets;
    other.ecPointFormat = ecPointFormat;
    other.tls13Tickets = List<TlsNewSessionTicket>.from(tls13Tickets);
    return other;
  }

  /// Whether this session can be used for resumption attempts.
  bool valid() {
    final hasId = sessionID.isNotEmpty;
    final hasTickets =
      (tickets?.isNotEmpty ?? false) ||
      (tls10Tickets?.isNotEmpty ?? false) ||
      tls13Tickets.isNotEmpty;
    final hasTls13ResSecret = resumptionMasterSecret.isNotEmpty;
    return resumable && (hasId || hasTickets || hasTls13ResSecret);
  }

  /// Update resumable flag; disallow true when there is no session ID.
  void setResumable(bool value) {
    if (!value || (value && sessionID.isNotEmpty)) {
      resumable = value;
    }
  }

  /// Returns the tack id if a TackExtension is attached.
  String? getTackId() {
    final ext = tackExt;
    if (ext == null) {
      return null;
    }
    try {
      final tack = ext.tack;
      if (tack == null) {
        return null;
      }
      return tack.getTackId();
    } catch (_) {
      return null;
    }
  }

  /// Returns the configured break signatures if present.
  dynamic getBreakSigs() {
    final ext = tackExt;
    if (ext == null) {
      return null;
    }
    try {
      return ext.break_sigs;
    } catch (_) {
      return null;
    }
  }

  /// Canonical cipher name derived from the negotiated cipher suite.
  String? getCipherName() {
    return CipherSuite.canonicalCipherName(cipherSuite);
  }

  /// Canonical MAC name derived from the negotiated cipher suite.
  String? getMacName() {
    return CipherSuite.canonicalMacName(cipherSuite);
  }

  static Uint8List _bytes(List<int>? value) {
    if (value == null) {
      return Uint8List(0);
    }
    if (value is Uint8List) {
      return value;
    }
    return Uint8List.fromList(value);
  }
}

// TODO(port): Session integration pending:
// - Integration with tlsconnection.py/tlsrecordlayer.py for actual resumption
// - TACK extension support (getTackId/getBreakSigs need utils/tackwrapper.dart)

/// Session ticket metadata for TLS 1.2 and earlier resumptions.
class Ticket {
  Ticket({
    required List<int> ticket,
    required this.ticketLifetime,
    required List<int> masterSecret,
    required this.cipherSuite,
  })  : this.ticket = Session._bytes(ticket),
        masterSecret = Session._bytes(masterSecret),
        _timeReceived = DateTime.now().millisecondsSinceEpoch ~/ 1000;

  final Uint8List ticket;
  final int ticketLifetime;
  final Uint8List masterSecret;
  final int cipherSuite;
  final int _timeReceived;

  bool valid() {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    return now < _timeReceived + ticketLifetime;
  }
}
