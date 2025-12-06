part of tlslite_socket_native_ffi;

class SocketRuntimeHelper {
  const SocketRuntimeHelper._();

  static Duration secondsToDuration(double seconds) {
    final millis = (seconds * 1000).round();
    return Duration(milliseconds: millis < 0 ? 0 : millis);
  }

  static int lastErrorCode() {
    if (Platform.isWindows) {
      return _WSAGetLastError();
    }
    final getter = _posixErrnoPointer;
    if (getter != null) {
      return getter().value;
    }
    return 0;
  }

  static bool isRetryable(int code) =>
      Platform.isWindows ? code == _WSAEINTR : code == _POSIX_EINTR;

  static bool isWouldBlock(int code) {
    if (Platform.isWindows) {
      return code == _WSAEWOULDBLOCK;
    }
    return Platform.isMacOS ? code == _POSIX_EAGAIN_MAC : code == _POSIX_EAGAIN_LINUX;
  }

  static Never throwWithOsError(String operation) {
    final code = lastErrorCode();
    throw SocketException('$operation failed (os error $code)');
  }
}
