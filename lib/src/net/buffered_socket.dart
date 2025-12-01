import 'dart:collection';
import 'dart:math' as math;
import 'dart:typed_data';

/// Lightweight port of tlslite-ng's bufferedsocket.py.
///
/// This class mirrors the "buffered socket" helper used by the Python
/// implementation but intentionally targets an abstract [socket] that only needs
/// to expose the handful of methods invoked here. Once the Dart TLS transport
/// layer solidifies, replace the `dynamic` type with a strongly-typed adapter
/// over `Socket`/`RawSocket` or a future FFI-backed implementation.
class BufferedSocket {
  BufferedSocket(this.socket);

  /// Underlying transport. Must expose `send`, `sendall`, `recv`, `getsockname`,
  /// `getpeername`, `settimeout`, `gettimeout`, `setsockopt`, `shutdown`, and
  /// `close` with Python-like semantics.
  ///
  /// // TODO: Replace [dynamic] with a Dart interface when the socket layer is
  /// // finalized (e.g., RawSocket wrapper or platform channel/FFI adapter).
  final dynamic socket;

  final Queue<Uint8List> _writeQueue = Queue<Uint8List>();
  bool bufferWrites = false;
  final List<int> _readBuffer = <int>[];

  Future<int> send(List<int> data) async {
    final bytes = Uint8List.fromList(data);
    if (bufferWrites) {
      _writeQueue.add(bytes);
      return bytes.length;
    }
    final result = await socket.send(bytes);
    if (result is int) {
      return result;
    }
    return bytes.length;
  }

  Future<void> sendall(List<int> data) async {
    final bytes = Uint8List.fromList(data);
    if (bufferWrites) {
      _writeQueue.add(bytes);
      return;
    }
    await socket.sendall(bytes);
  }

  Future<void> flush() async {
    if (_writeQueue.isEmpty) {
      return;
    }
    final builder = BytesBuilder(copy: false);
    while (_writeQueue.isNotEmpty) {
      builder.add(_writeQueue.removeFirst());
    }
    if (builder.length > 0) {
      await socket.sendall(builder.takeBytes());
    }
  }

  Future<Uint8List> recv(int bufsize) async {
    if (_readBuffer.isEmpty) {
      final chunk = await socket.recv(math.max(4096, bufsize));
      if (chunk is List<int>) {
        _readBuffer.addAll(chunk);
      }
    }
    if (_readBuffer.isEmpty) {
      return Uint8List(0);
    }
    final take = math.min(bufsize, _readBuffer.length);
    final result = Uint8List.fromList(_readBuffer.sublist(0, take));
    _readBuffer.removeRange(0, take);
    return result;
  }

  dynamic getsockname() => socket.getsockname();

  dynamic getpeername() => socket.getpeername();

  Future<dynamic> settimeout(dynamic value) async => socket.settimeout(value);

  dynamic gettimeout() => socket.gettimeout();

  Future<dynamic> setsockopt(dynamic level, dynamic optname, dynamic value) async =>
      socket.setsockopt(level, optname, value);

  Future<dynamic> shutdown(dynamic how) async {
    await flush();
    return socket.shutdown(how);
  }

  Future<dynamic> close() async {
    await flush();
    return socket.close();
  }
}
