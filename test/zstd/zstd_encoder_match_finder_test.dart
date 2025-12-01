import 'dart:typed_data';

import 'package:test/test.dart';
import 'package:tlslite/src/zstd/encoder_match_finder.dart';

void main() {
  test('finds single obvious match', () {
    final input = Uint8List.fromList('abcabcabc'.codeUnits);
    final plan = planMatches(input);
    expect(plan.sequences, isNotEmpty);
    final first = plan.sequences.first;
    expect(first.literalLength, equals(3));
    expect(first.matchLength, greaterThanOrEqualTo(3));
    expect(first.offset, equals(3));
    expect(plan.literalBytes, equals(Uint8List.fromList('abc'.codeUnits)));
  });

  test('falls back to literals when no repeats exist', () {
    final input = Uint8List.fromList('abcdef'.codeUnits);
    final plan = planMatches(input);
    expect(plan.sequences, isEmpty);
    expect(plan.literalBytes, equals(input));
  });
}
