import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/constants.dart' as tls_constants;
import 'package:tlslite/src/errors.dart';
import 'package:tlslite/src/ffdhe_groups.dart';
import 'package:tlslite/src/handshake_settings.dart';
import 'package:tlslite/src/keyexchange.dart';
import 'package:tlslite/src/mathtls.dart';
import 'package:tlslite/src/messages.dart';

void main() {
  group('RFC 7919 selection', () {
    test('prefers first mutual group from client preference order', () {
      final clientHello = _FakeHello(
        version: const [3, 3],
        randomSeed: 1,
        supportedGroups: <int>[
          tls_constants.GroupName.ffdhe4096,
          tls_constants.GroupName.ffdhe3072,
        ],
      );
      final serverHello = _FakeHello(
        version: const [3, 3],
        randomSeed: 2,
      );

      final kex = ADHKeyExchange(
        tls_constants.CipherSuite.TLS_DH_ANON_WITH_AES_128_CBC_SHA,
        clientHello,
        serverHello,
        null,
        dhGroups: <int>[
          tls_constants.GroupName.ffdhe8192,
          tls_constants.GroupName.ffdhe3072,
        ],
      );

      final ske = kex.makeServerKeyExchange();
      final params = rfc7919GroupMap[tls_constants.GroupName.ffdhe3072]!;

      expect(ske.dhP, equals(params.prime));
      expect(ske.dhG, equals(params.generator));
    });

    test('throws when client and server share no RFC 7919 groups', () {
      final clientHello = _FakeHello(
        version: const [3, 3],
        randomSeed: 3,
        supportedGroups: <int>[
          tls_constants.GroupName.ffdhe8192,
        ],
      );
      final serverHello = _FakeHello(
        version: const [3, 3],
        randomSeed: 4,
      );

      final kex = ADHKeyExchange(
        tls_constants.CipherSuite.TLS_DH_ANON_WITH_AES_128_CBC_SHA,
        clientHello,
        serverHello,
        null,
        dhGroups: <int>[
          tls_constants.GroupName.ffdhe2048,
        ],
      );

      expect(
        () => kex.makeServerKeyExchange(),
        throwsA(isA<TLSInternalError>()),
      );
    });

    test('uses supportedGroups property even without extension', () {
      final clientHello = _FakeHello(
        version: const [3, 3],
        randomSeed: 5,
        supportedGroups: const [
          tls_constants.GroupName.ffdhe4096,
          tls_constants.GroupName.ffdhe3072,
        ],
        advertiseSupportedGroupsExtension: false,
      );
      final serverHello = _FakeHello(
        version: const [3, 3],
        randomSeed: 6,
      );

      final kex = ADHKeyExchange(
        tls_constants.CipherSuite.TLS_DH_ANON_WITH_AES_128_CBC_SHA,
        clientHello,
        serverHello,
        null,
        dhGroups: const [
          tls_constants.GroupName.ffdhe8192,
          tls_constants.GroupName.ffdhe3072,
        ],
      );

      final ske = kex.makeServerKeyExchange();
      final params = rfc7919GroupMap[tls_constants.GroupName.ffdhe3072]!;

      expect(ske.dhP, equals(params.prime));
      expect(ske.dhG, equals(params.generator));
    });
  });

  group('ECDH classic curves', () {
    test('secp256r1 shared secret matches between peers', () {
      const version = (3, 4);
      final clientKex = ECDHKeyExchange(
        tls_constants.GroupName.secp256r1,
        version,
      );
      final serverKex = ECDHKeyExchange(
        tls_constants.GroupName.secp256r1,
        version,
      );

      final clientPriv = clientKex.getRandomPrivateKey();
      final serverPriv = serverKex.getRandomPrivateKey();
      final clientPub = clientKex.calcPublicValue(clientPriv);
      final serverPub = serverKex.calcPublicValue(serverPriv);

      final clientSecret = clientKex.calcSharedKey(clientPriv, serverPub);
      final serverSecret = serverKex.calcSharedKey(serverPriv, clientPub);

      expect(clientSecret, equals(serverSecret));
      expect(clientSecret.length, greaterThan(0));
    });
  });

  group('EC point format negotiation', () {
    test('throws when client and server advertise disjoint formats', () {
      final clientHello = _FakeHello(
        version: const [3, 3],
        randomSeed: 11,
        supportedGroups: const [tls_constants.GroupName.secp256r1],
        ecPointFormats: const [
          tls_constants.ECPointFormat.ansiX962_compressed_prime,
        ],
      );
      final serverHello = _FakeHello(
        version: const [3, 3],
        randomSeed: 22,
        ecPointFormats: const [
          tls_constants.ECPointFormat.ansiX962_compressed_char2,
        ],
      );

      final kex = AECDHKeyExchange(
        tls_constants.CipherSuite.TLS_ECDH_ANON_WITH_AES_128_CBC_SHA,
        clientHello,
        serverHello,
        null,
        acceptedCurves: const [tls_constants.GroupName.secp256r1],
      );

      expect(
        () => kex.makeServerKeyExchange(),
        throwsA(isA<TLSIllegalParameterException>()),
      );
    });

    test('uses uncompressed format when peers advertise it', () {
      final clientHello = _FakeHello(
        version: const [3, 4],
        randomSeed: 33,
        supportedGroups: const [tls_constants.GroupName.secp256r1],
        ecPointFormats: const [
          tls_constants.ECPointFormat.ansiX962_compressed_prime,
          tls_constants.ECPointFormat.uncompressed,
        ],
      );
      final serverHello = _FakeHello(
        version: const [3, 4],
        randomSeed: 44,
        ecPointFormats: const [
          tls_constants.ECPointFormat.uncompressed,
          tls_constants.ECPointFormat.ansiX962_compressed_prime,
        ],
      );

      final serverKex = AECDHKeyExchange(
        tls_constants.CipherSuite.TLS_ECDH_ANON_WITH_AES_128_CBC_SHA,
        clientHello,
        serverHello,
        null,
        acceptedCurves: const [tls_constants.GroupName.secp256r1],
      );

      final ske = serverKex.makeServerKeyExchange();
      expect(ske.ecdhYs, isNotEmpty);

      final peerKex = ECDHKeyExchange(
        serverKex.groupId!,
        const (3, 4),
      );
      final peerPriv = peerKex.getRandomPrivateKey();
      final peerShare = peerKex.calcPublicValue(peerPriv);
      final cke = _FakeClientKeyExchange(peerShare);

      final shared = serverKex.processClientKeyExchange(cke);
      expect(shared, isNotEmpty);
    });
  });

  group('SRP validation', () {
    test('rejects unknown parameter sets', () {
      final settings = HandshakeSettings();
      final kex = _buildSrpKeyExchange(settings: settings);
      final ske = _buildSrpServerKeyExchange(
        prime: BigInt.from(23),
        generator: BigInt.from(5),
      );

      expect(
        () => kex.processServerKeyExchange(null, ske),
        throwsA(isA<TLSInsufficientSecurity>()),
      );
    });

    test('enforces minimum key size from settings', () {
      final params = goodGroupParameters.first;
      final settings = HandshakeSettings(minKeySize: 4096);
      final kex = _buildSrpKeyExchange(settings: settings);
      final ske = _buildSrpServerKeyExchange(
        prime: params.prime,
        generator: params.generator,
      );

      expect(
        () => kex.processServerKeyExchange(null, ske),
        throwsA(isA<TLSInsufficientSecurity>()),
      );
    });

    test('enforces maximum key size from settings', () {
      final params = goodGroupParameters.last;
      final settings = HandshakeSettings(maxKeySize: 2048);
      final kex = _buildSrpKeyExchange(settings: settings);
      final ske = _buildSrpServerKeyExchange(
        prime: params.prime,
        generator: params.generator,
      );

      expect(
        () => kex.processServerKeyExchange(null, ske),
        throwsA(isA<TLSInsufficientSecurity>()),
      );
    });
  });

  group('DH key size policy', () {
    test('rejects DH primes smaller than configured minimum', () {
      final params = rfc7919GroupMap[tls_constants.GroupName.ffdhe2048]!;
      final kex = _buildAdhKeyExchange(
        settings: HandshakeSettings(minKeySize: 4096),
      );
      final ske = _buildDhServerKeyExchange(
        prime: params.prime,
        generator: params.generator,
      );

      expect(
        () => kex.processServerKeyExchange(null, ske),
        throwsA(isA<TLSInsufficientSecurity>()),
      );
    });

    test('rejects DH primes larger than configured maximum', () {
      final params = rfc7919GroupMap[tls_constants.GroupName.ffdhe8192]!;
      final kex = _buildAdhKeyExchange(
        settings: HandshakeSettings(maxKeySize: 3072),
      );
      final ske = _buildDhServerKeyExchange(
        prime: params.prime,
        generator: params.generator,
      );

      expect(
        () => kex.processServerKeyExchange(null, ske),
        throwsA(isA<TLSInsufficientSecurity>()),
      );
    });
  });
}

class _FakeHello {
  _FakeHello({
    required List<int> version,
    required int randomSeed,
    this.supportedGroups,
    this.ecPointFormats,
    this.advertiseSupportedGroupsExtension = true,
  })  : _version = List<int>.from(version, growable: false),
        random = Uint8List.fromList(List<int>.filled(32, randomSeed));

  final List<int> _version;
  final Uint8List random;
  final List<int>? supportedGroups;
  final List<int>? ecPointFormats;
  final bool advertiseSupportedGroupsExtension;

  List<int> get client_version => _version;
  List<int> get clientVersion => _version;
  List<int> get server_version => _version;
  List<int> get serverVersion => _version;

  dynamic getExtension(int type) {
    if (type == tls_constants.ExtensionType.supported_groups &&
        supportedGroups != null &&
        advertiseSupportedGroupsExtension) {
      return _FakeSupportedGroups(supportedGroups!);
    }
    if (type == tls_constants.ExtensionType.ec_point_formats &&
        ecPointFormats != null) {
      return _FakeEcPointFormats(ecPointFormats!);
    }
    return null;
  }
}

class _FakeSupportedGroups {
  _FakeSupportedGroups(this.groups);

  final List<int> groups;
}

class _FakeEcPointFormats {
  _FakeEcPointFormats(this.formats);

  final List<int> formats;
}

class _FakeClientKeyExchange {
  _FakeClientKeyExchange(this.ecdhYc);

  final List<int> ecdhYc;
}

SRPKeyExchange _buildSrpKeyExchange({HandshakeSettings? settings}) {
  final hello = _FakeHello(version: const [3, 3], randomSeed: 55);
  return SRPKeyExchange(
    tls_constants.CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
    hello,
    hello,
    null,
    verifierDB: <Uint8List, dynamic>{},
    srpUsername: Uint8List.fromList('user'.codeUnits),
    password: Uint8List.fromList('pass'.codeUnits),
    settings: settings,
  );
}

ADHKeyExchange _buildAdhKeyExchange({HandshakeSettings? settings}) {
  final hello = _FakeHello(version: const [3, 3], randomSeed: 77);
  return ADHKeyExchange(
    tls_constants.CipherSuite.TLS_DH_ANON_WITH_AES_128_CBC_SHA,
    hello,
    hello,
    null,
    settings: settings,
  );
}

TlsServerKeyExchange _buildDhServerKeyExchange({
  required BigInt prime,
  required BigInt generator,
}) {
  return TlsServerKeyExchange(
    cipherSuite: tls_constants.CipherSuite.TLS_DH_ANON_WITH_AES_128_CBC_SHA,
    version: const [3, 3],
    dhP: prime,
    dhG: generator,
    dhYs: generator + BigInt.one,
  );
}

TlsServerKeyExchange _buildSrpServerKeyExchange({
  required BigInt prime,
  required BigInt generator,
}) {
  return TlsServerKeyExchange(
    cipherSuite: tls_constants.CipherSuite.TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
    version: const [3, 3],
    srpN: prime,
    srpG: generator,
    srpS: const [0xAA, 0xBB, 0xCC],
    srpB: generator + BigInt.one,
  );
}
