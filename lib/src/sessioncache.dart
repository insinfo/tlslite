import 'dart:collection';
import 'dart:convert';
import 'dart:typed_data';

import 'session.dart';

/// Cache for reusable TLS sessions, mirroring tlslite-ng's SessionCache.
class SessionCache {
  SessionCache({int maxEntries = 10000, int maxAgeSeconds = 14400})
      : assert(maxEntries > 0, 'maxEntries must be positive'),
        assert(maxAgeSeconds >= 0, 'maxAgeSeconds cannot be negative'),
        _maxEntries = maxEntries,
        _maxAgeMillis = maxAgeSeconds * 1000,
        _order = Queue<_SessionEntry>();

  final int _maxEntries;
  final int _maxAgeMillis;
  final Map<String, Session> _entries = <String, Session>{};
  final Queue<_SessionEntry> _order;

  /// Returns an existing, still valid session for [sessionId] or throws.
  Session operator [](List<int> sessionId) {
    _purgeExpired();
    final key = _keyFor(sessionId);
    final session = _entries[key];
    if (session == null || !session.valid()) {
      throw StateError('Session not found or not resumable');
    }
    return session;
  }

  /// Stores [session] under [sessionId], evicting old entries as needed.
  void operator []=(List<int> sessionId, Session session) {
    final key = _keyFor(sessionId);
    _purgeExpired();
    _entries[key] = session;
    _order.addLast(_SessionEntry(key, _nowMillis()));
    _trimCapacity();
  }

  /// Best-effort lookup that returns null instead of throwing.
  Session? getOrNull(List<int> sessionId) {
    try {
      return this[sessionId];
    } catch (_) {
      return null;
    }
  }

  /// Removes all cached sessions.
  void clear() {
    _entries.clear();
    _order.clear();
  }

  void _trimCapacity() {
    while (_entries.length > _maxEntries && _order.isNotEmpty) {
      final oldest = _order.removeFirst();
      _entries.remove(oldest.key);
    }
  }

  void _purgeExpired() {
    if (_maxAgeMillis == 0) {
      // Age zero means entries expire immediately after insertion.
      while (_order.isNotEmpty) {
        final entry = _order.removeFirst();
        _entries.remove(entry.key);
      }
      return;
    }

    final now = _nowMillis();
    while (_order.isNotEmpty) {
      final entry = _order.first;
      final remaining = _entries.containsKey(entry.key);
      if (!remaining) {
        _order.removeFirst();
        continue;
      }
      final expired = now - entry.timestampMillis > _maxAgeMillis;
      if (expired) {
        _entries.remove(entry.key);
        _order.removeFirst();
        continue;
      }
      break;
    }
  }

  static String _keyFor(List<int> sessionId) {
    final bytes = sessionId is Uint8List
        ? sessionId
        : Uint8List.fromList(List<int>.from(sessionId));
    return base64Encode(bytes);
  }

  static int _nowMillis() => DateTime.now().millisecondsSinceEpoch;
}

class _SessionEntry {
  _SessionEntry(this.key, this.timestampMillis);

  final String key;
  final int timestampMillis;
}
