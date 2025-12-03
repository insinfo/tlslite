/// ML-KEM Parameters as defined in FIPS 203.
library;

/// Parameters for ML-KEM variants.
class MlKemParameters {
  /// Security level identifier
  final String name;
  
  /// Module rank (k)
  final int k;
  
  /// CBD parameter for secret/error generation in keygen
  final int eta1;
  
  /// CBD parameter for error generation in encryption
  final int eta2;
  
  /// Compression parameter for ciphertext u
  final int du;
  
  /// Compression parameter for ciphertext v
  final int dv;
  
  /// OID for this parameter set
  final List<int> oid;

  const MlKemParameters({
    required this.name,
    required this.k,
    required this.eta1,
    required this.eta2,
    required this.du,
    required this.dv,
    required this.oid,
  });

  /// Size of encapsulation key in bytes: 384*k + 32
  int get ekSize => 384 * k + 32;

  /// Size of decapsulation key in bytes: 768*k + 96
  int get dkSize => 768 * k + 96;

  /// Size of ciphertext in bytes: 32*(du*k + dv)
  int get ciphertextSize => 32 * (du * k + dv);

  /// Shared secret size (always 32 bytes)
  static const int sharedSecretSize = 32;
}

/// ML-KEM-512 parameters (128-bit security)
const mlKem512 = MlKemParameters(
  name: 'ML-KEM-512',
  k: 2,
  eta1: 3,
  eta2: 2,
  du: 10,
  dv: 4,
  oid: [2, 16, 840, 1, 101, 3, 4, 4, 1],
);

/// ML-KEM-768 parameters (192-bit security)
const mlKem768 = MlKemParameters(
  name: 'ML-KEM-768',
  k: 3,
  eta1: 2,
  eta2: 2,
  du: 10,
  dv: 4,
  oid: [2, 16, 840, 1, 101, 3, 4, 4, 2],
);

/// ML-KEM-1024 parameters (256-bit security)
const mlKem1024 = MlKemParameters(
  name: 'ML-KEM-1024',
  k: 4,
  eta1: 2,
  eta2: 2,
  du: 11,
  dv: 5,
  oid: [2, 16, 840, 1, 101, 3, 4, 4, 3],
);
