import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/src/ml_kem/ml_kem.dart';

void main() {
  group('ML-KEM Tests', () {
    test('ML-KEM-512 Roundtrip', () {
      final kem = mlKem512Instance;
      
      // 1. Key Generation
      final (ek, dk) = kem.keygen();
      expect(ek.length, equals(kem.params.ekSize));
      expect(dk.length, equals(kem.params.dkSize));

      // 2. Encapsulation
      final (ss, ct) = kem.encaps(ek);
      expect(ss.length, equals(32)); // Shared secret is always 32 bytes
      expect(ct.length, equals(kem.params.ciphertextSize));

      // 3. Decapsulation
      final ssDecaps = kem.decaps(dk, ct);
      expect(ssDecaps, equals(ss));
    });

    test('ML-KEM-768 Roundtrip', () {
      final kem = mlKem768Instance;
      
      // 1. Key Generation
      final (ek, dk) = kem.keygen();
      expect(ek.length, equals(kem.params.ekSize));
      expect(dk.length, equals(kem.params.dkSize));

      // 2. Encapsulation
      final (ss, ct) = kem.encaps(ek);
      expect(ss.length, equals(32));
      expect(ct.length, equals(kem.params.ciphertextSize));

      // 3. Decapsulation
      final ssDecaps = kem.decaps(dk, ct);
      expect(ssDecaps, equals(ss));
    });

    test('ML-KEM-1024 Roundtrip', () {
      final kem = mlKem1024Instance;
      
      // 1. Key Generation
      final (ek, dk) = kem.keygen();
      expect(ek.length, equals(kem.params.ekSize));
      expect(dk.length, equals(kem.params.dkSize));

      // 2. Encapsulation
      final (ss, ct) = kem.encaps(ek);
      expect(ss.length, equals(32));
      expect(ct.length, equals(kem.params.ciphertextSize));

      // 3. Decapsulation
      final ssDecaps = kem.decaps(dk, ct);
      expect(ssDecaps, equals(ss));
    });

    test('ML-KEM Implicit Rejection', () {
      final kem = mlKem768Instance;
      final (ek, dk) = kem.keygen();
      final (ss, ct) = kem.encaps(ek);

      // Modify ciphertext
      final badCt = Uint8List.fromList(ct);
      badCt[0] ^= 0xFF; // Flip bits in first byte

      final ssBad = kem.decaps(dk, badCt);
      
      // Should not match original shared secret
      expect(ssBad, isNot(equals(ss)));
      // Should still be 32 bytes
      expect(ssBad.length, equals(32));
    });

    test('ML-KEM Key Derivation (Deterministic Keygen)', () {
      final kem = mlKem768Instance;
      final seed = Uint8List(64); // All zeros for testing
      
      final (ek1, dk1) = kem.keyDerive(seed);
      final (ek2, dk2) = kem.keyDerive(seed);

      expect(ek1, equals(ek2));
      expect(dk1, equals(dk2));
    });
    
    test('Convenience Functions', () {
      // 768
      final (ek768, dk768) = mlKem768Keygen();
      final (ss768, ct768) = mlKem768Encaps(ek768);
      final ssDecaps768 = mlKem768Decaps(dk768, ct768);
      expect(ssDecaps768, equals(ss768));

      // 1024
      final (ek1024, dk1024) = mlKem1024Keygen();
      final (ss1024, ct1024) = mlKem1024Encaps(ek1024);
      final ssDecaps1024 = mlKem1024Decaps(dk1024, ct1024);
      expect(ssDecaps1024, equals(ss1024));
    });
  });
}
