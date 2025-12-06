import 'dart:typed_data';

enum SocketBlockingMode { blocking, nonBlocking }

enum SocketShutdown { receive, send, both }

enum TransportEvent { read, write }

abstract interface class RawTransport {
  SocketBlockingMode get blockingMode;
  bool get isClosed;
  (String, int) get address;
  int get port;
  Duration? get timeoutDuration;
  int? get nativeHandle;

  void setBlockingMode(SocketBlockingMode mode);
  void settimeout(double? timeout);
  void setTimeout(Duration? duration);

  void bind(String host, int port);
  void connect(String host, int port);
  void listen(int backlog);
  RawTransport accept();

  int send(Uint8List data);
  void sendall(Uint8List data);
  Uint8List recv(int bufferSize);
  (Uint8List, String, int) recvfrom(int bufferSize);
  int sendto(Uint8List data, String host, int port);

  bool waitForRead({Duration? timeout});
  bool waitForWrite({Duration? timeout});

  void setReuseAddress(bool enabled);
  void setReusePort(bool enabled);
  void setNoDelay(bool enabled);

  void shutdown([SocketShutdown how = SocketShutdown.both]);
  void close();
}
