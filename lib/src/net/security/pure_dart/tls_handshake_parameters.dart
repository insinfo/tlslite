import '../../../constants.dart' as tls_constants;
import 'pure_dart_tls_types.dart';
import 'tls_extensions.dart';

/// Coordinates the key_share negotiation while the full TLS 1.3 key schedule
/// is still being ported from tlslite-ng.
class PureDartKeyShareCoordinator {
  PureDartKeyShareCoordinator({required this.mode});

  final PureDartTlsMode mode;

  List<TlsKeyShareEntry> _clientShares = const <TlsKeyShareEntry>[];
  TlsKeyShareEntry? _serverShare;
  int? _negotiatedGroup;

  static const List<int> _groupPreference = <int>[
    tls_constants.GroupName.x25519,
    tls_constants.GroupName.secp256r1,
    tls_constants.GroupName.secp384r1,
    tls_constants.GroupName.secp521r1,
    tls_constants.GroupName.ffdhe2048,
    tls_constants.GroupName.ffdhe3072,
    tls_constants.GroupName.ffdhe4096,
  ];

  /// Records the client's offered key shares (either parsed ClientHello or
  /// the one we are about to send) and computes the preferred group.
  void registerClientShares(List<TlsKeyShareEntry> shares) {
    _clientShares = List<TlsKeyShareEntry>.unmodifiable(shares);
    if (_clientShares.isEmpty) {
      _negotiatedGroup = null;
      return;
    }
    _negotiatedGroup ??= _selectPreferredShare(_clientShares)?.group;
  }

  /// Validates and stores the key share picked by the peer in ServerHello.
  void registerServerHelloShare(TlsKeyShareEntry share) {
    if (_clientShares.isNotEmpty &&
        !_clientShares.any((entry) => entry.group == share.group)) {
      throw StateError(
        'ServerHello key_share usa grupo ${share.group} não anunciado',
      );
    }
    _serverShare = share;
    _negotiatedGroup = share.group;
  }

  /// Returns the group that should be used by the server when generating its
  /// own KeyShare entry. Null means we still need to trigger HelloRetryRequest
  /// (no overlaps).
  int? planServerSelectedGroup({List<int>? preferenceOverride}) {
    if (_clientShares.isEmpty) {
      return null;
    }
    final preferred = preferenceOverride ?? _groupPreference;
    final selected = _selectPreferredShare(
      _clientShares,
      preference: preferred,
    );
    _negotiatedGroup = selected?.group ?? _clientShares.first.group;
    return _negotiatedGroup;
  }

  bool get needsHelloRetryRequest =>
      mode == PureDartTlsMode.server && _clientShares.isEmpty;

  int? get negotiatedGroup => _negotiatedGroup;

  TlsKeyShareEntry? get clientSelectedShare {
    if (_negotiatedGroup == null) {
      return null;
    }
    return _firstWhereOrNull(
      _clientShares,
      (entry) => entry.group == _negotiatedGroup,
    );
  }

  TlsKeyShareEntry? get serverShare => _serverShare;

  List<TlsKeyShareEntry> get clientShares => _clientShares;

  TlsKeyShareEntry? _selectPreferredShare(
    List<TlsKeyShareEntry> shares, {
    List<int>? preference,
  }) {
    if (shares.isEmpty) {
      return null;
    }
    final ordered = preference ?? _groupPreference;
    for (final group in ordered) {
      final match = _firstWhereOrNull(shares, (entry) => entry.group == group);
      if (match != null) {
        return match;
      }
    }
    return shares.first;
  }
}

/// Simple helper for negotiating a signature scheme once both peers presented
/// their supported lists.
class SignatureSchemeNegotiator {
  const SignatureSchemeNegotiator();

  int selectScheme({
    required List<int> peerPreferred,
    required List<int> localSupported,
  }) {
    if (localSupported.isEmpty) {
      throw StateError('Nenhum algoritmo de assinatura disponível localmente');
    }
    if (peerPreferred.isEmpty) {
      return localSupported.first;
    }
    for (final scheme in localSupported) {
      if (peerPreferred.contains(scheme)) {
        return scheme;
      }
    }
    throw StateError(
      'Nenhum algoritmo de assinatura em comum com o peer',
    );
  }
}

T? _firstWhereOrNull<T>(Iterable<T> iterable, bool Function(T) test) {
  for (final value in iterable) {
    if (test(value)) {
      return value;
    }
  }
  return null;
}
