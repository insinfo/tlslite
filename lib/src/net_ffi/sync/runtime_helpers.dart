part of tlslite_socket_native_ffi;

class SocketRuntimeHelper {
  const SocketRuntimeHelper._();

  static Duration secondsToDuration(double seconds) {
    final millis = (seconds * 1000).round();
    return Duration(milliseconds: millis < 0 ? 0 : millis);
  }

  static int lastErrorCode() {
    if (Platform.isWindows) {
      return _wsaGetLastError();
    }
    final getter = _posixErrnoPointer;
    if (getter != null) {
      return getter().value;
    }
    return 0;
  }

  static bool isRetryable(int code) =>
      Platform.isWindows ? code == _wsaeIntr : code == _posixEIntr;

  static bool isWouldBlock(int code) {
    if (Platform.isWindows) {
      return code == _wsaeWouldBlock;
    }
    return Platform.isMacOS
        ? code == _posixEAgainMac
        : code == _posixEAgainLinux;
  }

  static bool isConnectionClosed(int code) {
    if (Platform.isWindows) {
      return code == _wsaeConnAborted || code == _wsaeConnReset;
    }
    return Platform.isMacOS
        ? code == _posixEConnResetMac
        : code == _posixEConnReset;
  }

  static Never throwWithOsError(String operation, {int? code}) {
    final errorCode = code ?? lastErrorCode();
    throw SocketException('$operation failed (os error $errorCode)');
  }
}
