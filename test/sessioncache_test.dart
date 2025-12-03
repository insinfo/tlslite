import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:tlslite/src/session.dart';
import 'package:tlslite/src/sessioncache.dart';

void main() {
  group('SessionCache', () {
    test('removes expired entries before returning them', () async {
      final cache = SessionCache(maxEntries: 4, maxAgeSeconds: 0);
      final sessionId = Uint8List.fromList('hello'.codeUnits);
      final session = _session(sessionId);
      cache[sessionId] = session;

      await Future<void>.delayed(const Duration(milliseconds: 5));

      expect(() => cache[sessionId], throwsStateError);
    });

    test('evicts oldest entries when capacity exceeded', () {
      final cache = SessionCache(maxEntries: 3, maxAgeSeconds: 3600);
      final ids = List.generate(5, (i) => Uint8List.fromList([i]));
      final sessions = ids.map(_session).toList();
      for (var i = 0; i < ids.length; i++) {
        cache[ids[i]] = sessions[i];
      }

      expect(() => cache[ids.first], throwsStateError);
      expect(cache[ids.last], same(sessions.last));
    });
  });
}

Session _session(Uint8List sessionId) {
  final session = Session();
  session.sessionID = Uint8List.fromList(sessionId);
  session.resumable = true;
  return session;
}
