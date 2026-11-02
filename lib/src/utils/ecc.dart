// Ported to Dart from tlslite-ng tlslite/utils/ecc.py
// (https://github.com/tlsfuzzer/tlslite-ng); see LICENSE for the terms.
// Modified in 2025-2026 by Isaque Neves.

/// Elliptic-curve helpers (pure Dart).
///
/// The curve arithmetic lives in `ec/ec_curve.dart`; the named curves in
/// `ec/ec_curves.dart`. This file keeps the historical helper names used by
/// the rest of the library.
library;

import 'ec/ec_curve.dart';
import 'ec/ec_curves.dart';

export 'ec/ec_curve.dart' show EcCurve, EcPoint;
export 'ec/ec_curves.dart'
    show allEcCurves, ecCurveNames, ecCurveByName, ecCurveByOid;

/// Returns the domain parameters of the curve called [curveName]
/// (case-insensitive; aliases such as `prime256v1`, `nistp256` or
/// `brainpoolP256r1tls13` are accepted).
///
/// Throws [ArgumentError] if the curve is unknown or not supported.
EcCurve getCurveByName(String curveName) {
  final curve = ecCurveByName(curveName);
  if (curve == null) {
    throw ArgumentError(
        "Curve named '$curveName' (normalized: '${curveName.toLowerCase()}') "
        "is unknown or not supported by this mapping.");
  }
  return curve;
}

/// Returns the size in bytes of one coordinate of a point on the curve.
///
/// Accepts an [EcPoint] or an [EcCurve].
int getPointByteSize(dynamic pointOrCurve) {
  if (pointOrCurve is EcPoint) {
    return pointOrCurve.curve.fieldBytes;
  }
  if (pointOrCurve is EcCurve) {
    return pointOrCurve.fieldBytes;
  }
  throw ArgumentError('The input must be an EcPoint or an EcCurve.');
}
