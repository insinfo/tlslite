part of tlslite_socket_native_ffi;

DynamicLibrary? _unixLib;

DynamicLibrary _posixLib() {
  if (Platform.isWindows) {
    throw UnsupportedError('POSIX socket APIs are unavailable on Windows');
  }
  if (_unixLib != null) {
    return _unixLib!;
  }
  final candidates = <String>[
    if (Platform.isMacOS) 'libSystem.dylib' else 'libc.so.6',
    'libc.so'
  ];
  for (final name in candidates) {
    try {
      return _unixLib ??= DynamicLibrary.open(name);
    } catch (_) {
      continue;
    }
  }
  // Fallback to process handle if specific library names are missing.
  return _unixLib ??= DynamicLibrary.process();
}

final Pointer<Int32> Function()? _posixErrnoPointer =
    Platform.isWindows ? null : _loadErrnoPointer();

Pointer<Int32> Function()? _loadErrnoPointer() {
  if (Platform.isWindows) {
    return null;
  }
  final symbols = ['__errno_location', '__error', '___error'];
  for (final symbol in symbols) {
    try {
      return _posixLib()
          .lookupFunction<Pointer<Int32> Function(), Pointer<Int32> Function()>(
              symbol);
    } catch (_) {
      continue;
    }
  }
  return null;
}

int Function(int, int, int)? _socketUnixPtr;
int Function(int, Pointer, int)? _bindUnixPtr;
int Function(int, int)? _listenUnixPtr;
int Function(int, Pointer, Pointer<Int32>)? _acceptUnixPtr;
int Function(int, Pointer, int)? _connectUnixPtr;
int Function(int, Pointer<Uint8>, int, int)? _sendUnixPtr;
int Function(int, Pointer<Uint8>, int, int)? _recvUnixPtr;
int Function(int, Pointer<Uint8>, int, int, Pointer, Pointer<Int32>)?
    _recvfromUnixPtr;
int Function(int, Pointer<Uint8>, int, int, Pointer, int)? _sendtoUnixPtr;
int Function(int)? _closeUnixPtr;
int Function(int, int, int)? _fcntlPtr;
int Function(Pointer<PollFd>, int, int)? _pollUnixPtr;
int Function(int, int, int, Pointer<Uint8>, int)? _setsockoptUnixPtr;
int Function(int, int)? _shutdownUnixPtr;
int Function(int, Pointer<Utf8>, Pointer)? _inetPtonUnixPtr;
Pointer<Utf8> Function(int, Pointer, Pointer<Utf8>, int)? _inetNtopUnixPtr;
int Function(Pointer<Uint8>, int)? _gethostnameUnixPtr;
int Function(int, Pointer, Pointer<Int32>)? _getsocknameUnixPtr;
int Function(int)? _htonsPosixPtr;
int Function(int)? _ntohsPosixPtr;

int Function(int, int, int) get _socketUnix =>
    _socketUnixPtr ??= _posixLib().lookupFunction<
        Int32 Function(Int32, Int32, Int32),
        int Function(int, int, int)>('socket');

int Function(int, Pointer, int) get _bindUnix =>
    _bindUnixPtr ??= _posixLib().lookupFunction<
        Int32 Function(Int32, Pointer, Int32),
        int Function(int, Pointer, int)>('bind');

int Function(int, int) get _listenUnix => _listenUnixPtr ??= _posixLib()
    .lookupFunction<Int32 Function(Int32, Int32), int Function(int, int)>(
        'listen');

int Function(int, Pointer, Pointer<Int32>) get _acceptUnix =>
    _acceptUnixPtr ??= _posixLib().lookupFunction<
        Int32 Function(Int32, Pointer, Pointer<Int32>),
        int Function(int, Pointer, Pointer<Int32>)>('accept');

int Function(int, Pointer, int) get _connectUnix =>
    _connectUnixPtr ??= _posixLib().lookupFunction<
        Int32 Function(Int32, Pointer, Int32),
        int Function(int, Pointer, int)>('connect');

int Function(int, Pointer<Uint8>, int, int) get _sendUnix =>
    _sendUnixPtr ??= _posixLib().lookupFunction<
        IntPtr Function(Int32, Pointer<Uint8>, IntPtr, Int32),
        int Function(int, Pointer<Uint8>, int, int)>('send');

int Function(int, Pointer<Uint8>, int, int) get _recvUnix =>
    _recvUnixPtr ??= _posixLib().lookupFunction<
        IntPtr Function(Int32, Pointer<Uint8>, IntPtr, Int32),
        int Function(int, Pointer<Uint8>, int, int)>('recv');

int Function(int, Pointer<Uint8>, int, int, Pointer, Pointer<Int32>)
    get _recvfromUnix => _recvfromUnixPtr ??= _posixLib().lookupFunction<
        IntPtr Function(
            Int32, Pointer<Uint8>, IntPtr, Int32, Pointer, Pointer<Int32>),
        int Function(int, Pointer<Uint8>, int, int, Pointer,
            Pointer<Int32>)>('recvfrom');

int Function(int, Pointer<Uint8>, int, int, Pointer, int) get _sendtoUnix =>
    _sendtoUnixPtr ??= _posixLib().lookupFunction<
        IntPtr Function(Int32, Pointer<Uint8>, IntPtr, Int32, Pointer, Int32),
        int Function(int, Pointer<Uint8>, int, int, Pointer, int)>('sendto');

int Function(int) get _closeUnix => _closeUnixPtr ??= _posixLib()
    .lookupFunction<Int32 Function(Int32), int Function(int)>('close');

int Function(int, int, int) get _fcntl =>
    _fcntlPtr ??= _posixLib().lookupFunction<
        Int32 Function(Int32, Int32, Int32),
        int Function(int, int, int)>('fcntl');

int Function(Pointer<PollFd>, int, int) get _pollUnix =>
    _pollUnixPtr ??= _posixLib().lookupFunction<
        Int32 Function(Pointer<PollFd>, Uint32, Int32),
        int Function(Pointer<PollFd>, int, int)>('poll');

int Function(int, int, int, Pointer<Uint8>, int) get _setsockoptUnix =>
    _setsockoptUnixPtr ??= _posixLib().lookupFunction<
        Int32 Function(Int32, Int32, Int32, Pointer<Uint8>, Int32),
        int Function(int, int, int, Pointer<Uint8>, int)>('setsockopt');

int Function(int, int) get _shutdownUnix => _shutdownUnixPtr ??= _posixLib()
    .lookupFunction<Int32 Function(Int32, Int32), int Function(int, int)>(
        'shutdown');

int Function(int, Pointer<Utf8>, Pointer) get _inetPtonUnix =>
    _inetPtonUnixPtr ??= _posixLib().lookupFunction<
        Int32 Function(Int32, Pointer<Utf8>, Pointer),
        int Function(int, Pointer<Utf8>, Pointer)>('inet_pton');

Pointer<Utf8> Function(int, Pointer, Pointer<Utf8>, int) get _inetNtopUnix =>
    _inetNtopUnixPtr ??= _posixLib().lookupFunction<
        Pointer<Utf8> Function(Int32, Pointer, Pointer<Utf8>, Int32),
        Pointer<Utf8> Function(int, Pointer, Pointer<Utf8>, int)>('inet_ntop');

int Function(Pointer<Uint8>, int) get _gethostnameUnix =>
    _gethostnameUnixPtr ??= _posixLib().lookupFunction<
        Int32 Function(Pointer<Uint8>, Int32),
        int Function(Pointer<Uint8>, int)>('gethostname');

int Function(int, Pointer, Pointer<Int32>) get _getsocknameUnix =>
    _getsocknameUnixPtr ??= _posixLib().lookupFunction<
        Int32 Function(Int32, Pointer, Pointer<Int32>),
        int Function(int, Pointer, Pointer<Int32>)>('getsockname');

int Function(int) get _htonsPosix => _htonsPosixPtr ??= _posixLib()
    .lookupFunction<Uint16 Function(Uint16), int Function(int)>('htons');

int Function(int) get _ntohsPosix => _ntohsPosixPtr ??= _posixLib()
    .lookupFunction<Uint16 Function(Uint16), int Function(int)>('ntohs');
