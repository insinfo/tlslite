/// A state machine for using TLS Lite with asynchronous I/O.
///
/// In the implementation, this class bridges TLS Lite with asyncore and Twisted.
/// In Dart, asynchronous I/O is handled natively by the runtime (Futures, Streams, Isolates).
///
/// This class is provided primarily for porting reference and is not used by the
/// core [TlsConnection] implementation in Dart, which uses [Socket] and `await`.
abstract class AsyncStateMachine {
  bool? wantsReadEvent() {
    return null;
  }

  bool? wantsWriteEvent() {
    return null;
  }

  void outConnectEvent() {}
  void outReadEvent(List<int> data) {}
  void outWriteEvent() {}
  void outCloseEvent() {}
}
