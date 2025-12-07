import 'dart:async';
import 'dart:typed_data';

typedef CiphertextWriterAsync = Future<void> Function(Uint8List chunk);
typedef CiphertextReaderAsync = Future<Uint8List?> Function(int preferredLength);

typedef CiphertextWriterSync = void Function(Uint8List chunk);
typedef CiphertextReaderSync = Uint8List? Function(int preferredLength);
