/// Native memory helpers used by the FFI code, replacing `package:ffi`.
///
/// [malloc] and [calloc] allocate with the C runtime on POSIX systems and with
/// `CoTaskMemAlloc` on Windows; memory must be released with the same
/// allocator's `free`.
library;

import 'dart:convert' show utf8;
import 'dart:ffi';
import 'dart:io' show Platform;

typedef _AllocNative = Pointer<Void> Function(IntPtr size);
typedef _Alloc = Pointer<Void> Function(int size);
typedef _CallocNative = Pointer<Void> Function(IntPtr count, IntPtr size);
typedef _Calloc = Pointer<Void> Function(int count, int size);
typedef _FreeNative = Void Function(Pointer<Void> pointer);
typedef _Free = void Function(Pointer<Void> pointer);

final DynamicLibrary _runtime = Platform.isWindows
    ? DynamicLibrary.open('ole32.dll')
    : DynamicLibrary.process();

final _Alloc _alloc = _runtime.lookupFunction<_AllocNative, _Alloc>(
    Platform.isWindows ? 'CoTaskMemAlloc' : 'malloc');

final _Free _free = _runtime.lookupFunction<_FreeNative, _Free>(
    Platform.isWindows ? 'CoTaskMemFree' : 'free');

final _Calloc? _calloc = Platform.isWindows
    ? null
    : _runtime.lookupFunction<_CallocNative, _Calloc>('calloc');

/// Allocator backed by the C runtime `malloc` (`CoTaskMemAlloc` on Windows).
/// Memory is not initialized.
const Allocator malloc = _MallocAllocator();

/// Like [malloc], but the memory is zero-initialized.
const Allocator calloc = _CallocAllocator();

Pointer<Void> _checked(Pointer<Void> pointer, int byteCount) {
  if (pointer.address == 0) {
    throw ArgumentError('Could not allocate $byteCount bytes.');
  }
  return pointer;
}

final class _MallocAllocator implements Allocator {
  const _MallocAllocator();

  @override
  Pointer<T> allocate<T extends NativeType>(int byteCount, {int? alignment}) =>
      _checked(_alloc(byteCount), byteCount).cast();

  @override
  void free(Pointer pointer) => _free(pointer.cast());
}

final class _CallocAllocator implements Allocator {
  const _CallocAllocator();

  @override
  Pointer<T> allocate<T extends NativeType>(int byteCount, {int? alignment}) {
    final calloc = _calloc;
    if (calloc != null) {
      return _checked(calloc(byteCount, 1), byteCount).cast();
    }
    final pointer = _checked(_alloc(byteCount), byteCount);
    pointer.cast<Uint8>().asTypedList(byteCount).fillRange(0, byteCount, 0);
    return pointer.cast();
  }

  @override
  void free(Pointer pointer) => _free(pointer.cast());
}

/// A NUL-terminated UTF-8 C string.
final class Utf8 extends Opaque {}

extension Utf8Pointer on Pointer<Utf8> {
  /// Number of bytes before the terminating NUL.
  int get length {
    final bytes = cast<Uint8>();
    var length = 0;
    while (bytes[length] != 0) {
      length++;
    }
    return length;
  }

  /// Decodes the string; [length] (in bytes) skips the NUL scan.
  String toDartString({int? length}) {
    if (address == 0) {
      throw ArgumentError.notNull('pointer');
    }
    return utf8.decode(cast<Uint8>().asTypedList(length ?? this.length));
  }
}

extension StringUtf8Pointer on String {
  /// Copies the string as NUL-terminated UTF-8 into memory from [allocator].
  Pointer<Utf8> toNativeUtf8({Allocator allocator = malloc}) {
    final units = utf8.encode(this);
    final pointer = allocator<Uint8>(units.length + 1);
    pointer.asTypedList(units.length + 1)
      ..setAll(0, units)
      ..[units.length] = 0;
    return pointer.cast();
  }
}
