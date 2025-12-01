import 'dart:typed_data';

import '../socket/socket_native_ffi.dart';

abstract interface class SecureTransport implements RawTransport {
  RawTransport get innerTransport;
  bool get isHandshakeComplete;
  void ensureHandshakeCompleted();
}

mixin SecureTransportDelegates implements SecureTransport {
  @override
  RawTransport get innerTransport;

  @override
  bool get isHandshakeComplete;

  @override
  void ensureHandshakeCompleted();

  RawTransport get _delegate => innerTransport;

  @override
  SocketBlockingMode get blockingMode => _delegate.blockingMode;

  @override
  bool get isClosed => _delegate.isClosed;

  @override
  (String, int) get address => _delegate.address;

  @override
  int get port => _delegate.port;

  @override
  int? get nativeHandle => _delegate.nativeHandle;

  @override
  Duration? get timeoutDuration => _delegate.timeoutDuration;

  @override
  void setBlockingMode(SocketBlockingMode mode) =>
    _delegate.setBlockingMode(mode);

  @override
  void settimeout(double? timeout) => _delegate.settimeout(timeout);

  @override
  void setTimeout(Duration? duration) => _delegate.setTimeout(duration);

  @override
  void bind(String host, int port) => _delegate.bind(host, port);

  @override
  void connect(String host, int port) => _delegate.connect(host, port);

  @override
  void listen(int backlog) => _delegate.listen(backlog);

  @override
  RawTransport accept() => _delegate.accept();

  @override
  int send(Uint8List data) => _delegate.send(data);

  @override
  void sendall(Uint8List data) => _delegate.sendall(data);

  @override
  Uint8List recv(int bufferSize) => _delegate.recv(bufferSize);

  @override
  (Uint8List, String, int) recvfrom(int bufferSize) =>
    _delegate.recvfrom(bufferSize);

  @override
  int sendto(Uint8List data, String host, int port) =>
    _delegate.sendto(data, host, port);

  @override
  bool waitForRead({Duration? timeout}) =>
    _delegate.waitForRead(timeout: timeout);

  @override
  bool waitForWrite({Duration? timeout}) =>
    _delegate.waitForWrite(timeout: timeout);

  @override
  void setReuseAddress(bool enabled) =>
    _delegate.setReuseAddress(enabled);

  @override
  void setReusePort(bool enabled) => _delegate.setReusePort(enabled);

  @override
  void setNoDelay(bool enabled) => _delegate.setNoDelay(enabled);

  @override
  void shutdown([SocketShutdown how = SocketShutdown.both]) =>
    _delegate.shutdown(how);

  @override
  void close() => _delegate.close();
}
