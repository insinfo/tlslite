/**
 * Unchecked exception used internally.
 */
class BrotliRuntimeException implements Exception {
  final String message;
  final Object? cause;

  BrotliRuntimeException(this.message, [this.cause]);

  @override
  String toString() {
    if (cause != null) {
      return "BrotliRuntimeException: $message (Cause: $cause)";
    }
    return "BrotliRuntimeException: $message";
  }
}