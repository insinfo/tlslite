

import "dart:ffi";

import 'package:tlslite/src/ffi/native_memory.dart';

/// Size of the global buffer used for interacting with OpenSSL.
const bufferSize = 1 << 16;

/// Global buffer used for interacting with OpenSSL.
final Pointer<Uint8> buffer = malloc.call<Uint8>(bufferSize);
