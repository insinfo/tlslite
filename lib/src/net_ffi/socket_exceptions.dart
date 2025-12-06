class SocketException implements Exception {
  final String message;
  SocketException(this.message);
  @override
  String toString() => 'SocketException: $message';
}
class SocketTimeoutException extends SocketException {
  SocketTimeoutException(String message) : super(message);
}

class SocketWouldBlockException extends SocketException {
  SocketWouldBlockException(String message) : super(message);
}