import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

class NativeUint8Buffer {
  final ffi.Pointer<ffi.Uint8> pointer;
  final int length;
  final NativeUint8BufferPool? _pool;
  bool _released = false;

  NativeUint8Buffer._(this.pointer, this.length, [this._pool]);

  factory NativeUint8Buffer.allocate(int length) {
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'must be non-negative');
    }
    return NativeUint8Buffer._(calloc<ffi.Uint8>(length), length);
  }

  factory NativeUint8Buffer.pooled(int length,
      {NativeUint8BufferPool? pool}) {
    final selectedPool = pool ?? NativeUint8BufferPool.global;
    return selectedPool.acquire(length);
  }

  factory NativeUint8Buffer.fromBytes(Uint8List data,
      {NativeUint8BufferPool? pool}) {
    final buffer = pool == null
        ? NativeUint8Buffer.allocate(data.length)
        : pool.acquire(data.length);
    buffer.asTypedList().setAll(0, data);
    return buffer;
  }

  Uint8List copyToDart(int bytes) {
    if (bytes < 0 || bytes > length) {
      throw ArgumentError.value(bytes, 'bytes', 'must be within buffer length');
    }
    if (bytes == 0) {
      return Uint8List(0);
    }
    final view = pointer.asTypedList(bytes);
    return Uint8List.fromList(view);
  }

  ffi.Pointer<ffi.Uint8> slice(int offset) {
    if (offset < 0 || offset > length) {
      throw ArgumentError.value(offset, 'offset', 'must be within buffer length');
    }
    return pointer + offset;
  }

  Uint8List asTypedList() => pointer.asTypedList(length);

  void release() {
    if (_released) {
      return;
    }
    _released = true;
    final pool = _pool;
    if (pool != null) {
      pool.release(this);
      return;
    }
    calloc.free(pointer);
  }

  void free() => release();

  void _markInUse() {
    _released = false;
  }
}

class NativeUint8BufferPool {
  NativeUint8BufferPool({this.maxBuffers = 32});

  static final NativeUint8BufferPool global = NativeUint8BufferPool();

  final int maxBuffers;
  final List<NativeUint8Buffer> _pool = <NativeUint8Buffer>[];

  NativeUint8Buffer acquire(int length) {
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'must be non-negative');
    }
    for (int i = 0; i < _pool.length; i++) {
      final buffer = _pool[i];
      if (buffer.length >= length) {
        _pool.removeAt(i);
        buffer._markInUse();
        return buffer;
      }
    }
    final buffer = NativeUint8Buffer._(calloc<ffi.Uint8>(length), length, this);
    buffer._markInUse();
    return buffer;
  }

  void release(NativeUint8Buffer buffer) {
    if (_pool.length >= maxBuffers) {
      calloc.free(buffer.pointer);
      return;
    }
    _pool.add(buffer);
  }
}
