/// Ed448-Goldilocks implementation for Dart.
/// 
/// This implements the Ed448 signature algorithm as specified in RFC 8032.
/// Ed448 uses the Edwards curve with equation x² + y² = 1 - 39081x²y²
/// over the field GF(p) where p = 2^448 - 2^224 - 1 (Goldilocks prime).
library ed448;

export 'src/ed448_impl.dart';
