import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/constants.dart' as tls_constants;
import 'package:tlslite/src/net/security/pure_dart/pure_dart_tls_types.dart';
import 'package:tlslite/src/net/security/pure_dart/tls_extensions.dart';
import 'package:tlslite/src/handshake_parameters.dart';

void main() {
  group('PureDartKeyShareCoordinator', () {
    test('selects preferred group order', () {
      final coordinator =
          PureDartKeyShareCoordinator(mode: PureDartTlsMode.server);
      coordinator.registerClientShares(<TlsKeyShareEntry>[
        TlsKeyShareEntry(
          group: tls_constants.GroupName.ffdhe2048,
          keyExchange: Uint8List.fromList(<int>[1, 2, 3]),
        ),
        TlsKeyShareEntry(
          group: tls_constants.GroupName.x25519,
          keyExchange: Uint8List.fromList(List<int>.filled(32, 0xAA)),
        ),
      ]);

      expect(
        coordinator.planServerSelectedGroup(),
        equals(tls_constants.GroupName.x25519),
      );
    });

    test('validates server share against announced groups', () {
      final coordinator =
          PureDartKeyShareCoordinator(mode: PureDartTlsMode.server);
      coordinator.registerClientShares(<TlsKeyShareEntry>[
        TlsKeyShareEntry(
          group: tls_constants.GroupName.x25519,
          keyExchange: Uint8List.fromList(List<int>.filled(32, 0x01)),
        ),
      ]);

      expect(
        () => coordinator.registerServerHelloShare(
          TlsKeyShareEntry(
            group: tls_constants.GroupName.secp256r1,
            keyExchange: Uint8List.fromList(List<int>.filled(65, 0x02)),
          ),
        ),
        throwsStateError,
      );
    });
  });

  group('SignatureSchemeNegotiator', () {
    const negotiator = SignatureSchemeNegotiator();

    test('picks first overlap', () {
      final scheme = negotiator.selectScheme(
        peerPreferred: <int>[
          tls_constants.SignatureScheme.ecdsa_secp256r1_sha256.value,
          tls_constants.SignatureScheme.rsa_pss_rsae_sha256.value,
        ],
        localSupported: <int>[
          tls_constants.SignatureScheme.ed25519.value,
          tls_constants.SignatureScheme.ecdsa_secp256r1_sha256.value,
        ],
      );

      expect(
        scheme,
        equals(tls_constants.SignatureScheme.ecdsa_secp256r1_sha256.value),
      );
    });

    test('falls back to local list when peer list empty', () {
      final scheme = negotiator.selectScheme(
        peerPreferred: const <int>[],
        localSupported: <int>[
          tls_constants.SignatureScheme.ed25519.value,
          tls_constants.SignatureScheme.rsa_pss_rsae_sha256.value,
        ],
      );

      expect(
        scheme,
        equals(tls_constants.SignatureScheme.ed25519.value),
      );
    });

    test('throws when no common algorithms', () {
      expect(
        () => negotiator.selectScheme(
          peerPreferred: <int>[
            tls_constants.SignatureScheme.ecdsa_secp256r1_sha256.value,
          ],
          localSupported: <int>[
            tls_constants.SignatureScheme.rsa_pss_rsae_sha256.value,
          ],
        ),
        throwsStateError,
      );
    });
  });
}
