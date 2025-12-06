/// Vector and Matrix operations over polynomial ring for ML-KEM.
library;

import 'dart:typed_data';
import 'polynomial.dart';

/// A vector of polynomials
class PolyVector {
  final List<Polynomial> elements;
  final int k;

  PolyVector(this.elements) : k = elements.length;

  /// Create zero vector
  factory PolyVector.zero(int k, {bool isNtt = false}) {
    return PolyVector([
      for (var i = 0; i < k; i++) Polynomial.zero(isNtt: isNtt)
    ]);
  }

  /// Whether all elements are in NTT domain
  bool get isNtt => elements.isNotEmpty && elements.first.isNtt;

  /// Convert to NTT domain
  PolyVector toNtt() {
    return PolyVector([for (final e in elements) e.toNtt()]);
  }

  /// Convert from NTT domain
  PolyVector fromNtt() {
    return PolyVector([for (final e in elements) e.fromNtt()]);
  }

  /// Convert all elements into Montgomery domain
  PolyVector toMontgomery() {
    return PolyVector([for (final e in elements) e.toMontgomery()]);
  }

  /// Add two vectors
  PolyVector operator +(PolyVector other) {
    assert(k == other.k);
    return PolyVector([
      for (var i = 0; i < k; i++) elements[i] + other.elements[i]
    ]);
  }

  /// Subtract two vectors  
  PolyVector operator -(PolyVector other) {
    assert(k == other.k);
    return PolyVector([
      for (var i = 0; i < k; i++) elements[i] - other.elements[i]
    ]);
  }

  /// Dot product (inner product) with another vector
  Polynomial dot(PolyVector other) {
    assert(k == other.k);
    assert(isNtt && other.isNtt);
    
    var result = elements[0] * other.elements[0];
    for (var i = 1; i < k; i++) {
      result = result + (elements[i] * other.elements[i]);
    }
    return result;
  }

  /// Encode vector to bytes
  Uint8List encode(int d) {
    final result = <int>[];
    for (final e in elements) {
      result.addAll(e.encode(d));
    }
    return Uint8List.fromList(result);
  }

  /// Decode bytes to vector
  factory PolyVector.decode(Uint8List bytes, int k, int d, {bool isNtt = false}) {
    final polySize = 32 * d;
    assert(bytes.length == k * polySize);
    
    return PolyVector([
      for (var i = 0; i < k; i++)
        Polynomial.decode(
          Uint8List.sublistView(bytes, i * polySize, (i + 1) * polySize),
          d,
          isNtt: isNtt,
        )
    ]);
  }

  /// Compress all elements
  PolyVector compress(int d) {
    return PolyVector([for (final e in elements) e.compress(d)]);
  }

  /// Decompress all elements
  PolyVector decompress(int d) {
    return PolyVector([for (final e in elements) e.decompress(d)]);
  }
}

/// A matrix of polynomials (k x k)
class PolyMatrix {
  final List<List<Polynomial>> rows;
  final int k;

  PolyMatrix(this.rows) : k = rows.length;

  /// Multiply matrix by vector: A * v
  PolyVector operator *(PolyVector v) {
    assert(k == v.k);
    final result = <Polynomial>[];
    
    for (var i = 0; i < k; i++) {
      var sum = rows[i][0] * v.elements[0];
      for (var j = 1; j < k; j++) {
        sum = sum + (rows[i][j] * v.elements[j]);
      }
      result.add(sum);
    }
    
    return PolyVector(result);
  }

  /// Get transpose of matrix
  PolyMatrix transpose() {
    final transposed = <List<Polynomial>>[];
    for (var j = 0; j < k; j++) {
      final row = <Polynomial>[];
      for (var i = 0; i < k; i++) {
        row.add(rows[i][j]);
      }
      transposed.add(row);
    }
    return PolyMatrix(transposed);
  }
}
