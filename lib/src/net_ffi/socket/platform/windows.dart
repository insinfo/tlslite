part of tlslite_socket_native_ffi;

const int _INVALID_SOCKET = -1;

DynamicLibrary? _windowsLib;

DynamicLibrary _winLib() {
  if (!Platform.isWindows) {
    throw UnsupportedError('Windows socket APIs are unavailable on this platform');
  }
  return _windowsLib ??= DynamicLibrary.open('ws2_32.dll');
}

int Function(int, Pointer<WSADATA>)? _wsaStartupPtr;
int Function()? _wsaCleanupPtr;
SocketHandle Function(int, int, int)? _socketWinPtr;
int Function(SocketHandle, Pointer, int)? _bindWinPtr;
int Function(SocketHandle, int)? _listenWinPtr;
SocketHandle Function(SocketHandle, Pointer, Pointer<Int32>)? _acceptWinPtr;
int Function(SocketHandle, Pointer, int)? _connectWinPtr;
int Function(SocketHandle, Pointer<Uint8>, int, int)? _sendWinPtr;
int Function(SocketHandle, Pointer<Uint8>, int, int)? _recvWinPtr;
int Function(SocketHandle)? _closesocketWinPtr;
int Function(SocketHandle, int, Pointer<Uint32>)? _ioctlsocketPtr;
int Function(Pointer<PollFd>, int, int)? _wsaPollPtr;
int Function(SocketHandle, Pointer<Uint8>, int, int, Pointer, Pointer<Int32>)?
    _recvfromWinPtr;
int Function(SocketHandle, Pointer<Uint8>, int, int, Pointer, int)? _sendtoWinPtr;
int Function(SocketHandle, Pointer, Pointer<Int32>)? _getsocknameWinPtr;
int Function()? _wsaGetLastErrorPtr;
int Function(SocketHandle, int, int, Pointer<Uint8>, int)? _setsockoptWinPtr;
int Function(SocketHandle, int)? _shutdownWinPtr;
int Function(int)? _htonsWinPtr;
int Function(int)? _ntohsWinPtr;
int Function(int, Pointer<Utf8>, Pointer)? _inetPtonWinPtr;
Pointer<Utf8> Function(int, Pointer, Pointer<Utf8>, int)? _inetNtopWinPtr;
int Function(Pointer<Uint8>, int)? _gethostnameWinPtr;

int Function(int, Pointer<WSADATA>) get _WSAStartup =>
    _wsaStartupPtr ??= _winLib().lookupFunction<
        Int32 Function(Uint16, Pointer<WSADATA>),
        int Function(int, Pointer<WSADATA>)>('WSAStartup');

int Function() get _WSACleanup => _wsaCleanupPtr ??=
    _winLib().lookupFunction<Int32 Function(), int Function()>('WSACleanup');

SocketHandle Function(int, int, int) get _socketWin => _socketWinPtr ??=
    _winLib().lookupFunction<
        IntPtr Function(Int32, Int32, Int32),
        int Function(int, int, int)>('socket');

int Function(SocketHandle, Pointer, int) get _bindWin => _bindWinPtr ??=
    _winLib().lookupFunction<
        Int32 Function(IntPtr, Pointer, Int32),
        int Function(int, Pointer, int)>('bind');

int Function(SocketHandle, int) get _listenWin => _listenWinPtr ??=
    _winLib().lookupFunction<
        Int32 Function(IntPtr, Int32), int Function(int, int)>('listen');

SocketHandle Function(SocketHandle, Pointer, Pointer<Int32>) get _acceptWin =>
    _acceptWinPtr ??= _winLib().lookupFunction<
        IntPtr Function(IntPtr, Pointer, Pointer<Int32>),
        int Function(int, Pointer, Pointer<Int32>)>('accept');

int Function(SocketHandle, Pointer, int) get _connectWin => _connectWinPtr ??=
    _winLib().lookupFunction<
        Int32 Function(IntPtr, Pointer, Int32),
        int Function(int, Pointer, int)>('connect');

int Function(SocketHandle, Pointer<Uint8>, int, int) get _sendWin =>
    _sendWinPtr ??= _winLib().lookupFunction<
        Int32 Function(IntPtr, Pointer<Uint8>, Int32, Int32),
        int Function(int, Pointer<Uint8>, int, int)>('send');

int Function(SocketHandle, Pointer<Uint8>, int, int) get _recvWin =>
    _recvWinPtr ??= _winLib().lookupFunction<
        Int32 Function(IntPtr, Pointer<Uint8>, Int32, Int32),
        int Function(int, Pointer<Uint8>, int, int)>('recv');

int Function(SocketHandle) get _closesocketWin => _closesocketWinPtr ??=
    _winLib()
        .lookupFunction<Int32 Function(IntPtr), int Function(int)>('closesocket');

int Function(SocketHandle, int, Pointer<Uint32>) get _ioctlsocket =>
    _ioctlsocketPtr ??= _winLib().lookupFunction<
        Int32 Function(IntPtr, Int32, Pointer<Uint32>),
        int Function(int, int, Pointer<Uint32>)>('ioctlsocket');

int Function(Pointer<PollFd>, int, int) get _wsaPoll => _wsaPollPtr ??=
    _winLib().lookupFunction<
        Int32 Function(Pointer<PollFd>, Uint32, Int32),
        int Function(Pointer<PollFd>, int, int)>('WSAPoll');

int Function(SocketHandle, Pointer<Uint8>, int, int, Pointer, Pointer<Int32>)
    get _recvfromWin => _recvfromWinPtr ??= _winLib().lookupFunction<
        Int32 Function(IntPtr, Pointer<Uint8>, Int32, Int32, Pointer,
            Pointer<Int32>),
        int Function(int, Pointer<Uint8>, int, int, Pointer,
            Pointer<Int32>)>('recvfrom');

int Function(SocketHandle, Pointer<Uint8>, int, int, Pointer, int)
    get _sendtoWin => _sendtoWinPtr ??= _winLib().lookupFunction<
        Int32 Function(IntPtr, Pointer<Uint8>, Int32, Int32, Pointer, Int32),
        int Function(int, Pointer<Uint8>, int, int, Pointer, int)>('sendto');

int Function(SocketHandle, Pointer, Pointer<Int32>) get _getsocknameWin =>
    _getsocknameWinPtr ??= _winLib().lookupFunction<
        Int32 Function(IntPtr, Pointer, Pointer<Int32>),
        int Function(int, Pointer, Pointer<Int32>)>('getsockname');

int Function() get _WSAGetLastError => _wsaGetLastErrorPtr ??=
    _winLib().lookupFunction<Int32 Function(), int Function()>('WSAGetLastError');

int Function(SocketHandle, int, int, Pointer<Uint8>, int) get _setsockoptWin =>
    _setsockoptWinPtr ??= _winLib().lookupFunction<
        Int32 Function(IntPtr, Int32, Int32, Pointer<Uint8>, Int32),
        int Function(int, int, int, Pointer<Uint8>, int)>('setsockopt');

int Function(SocketHandle, int) get _shutdownWin => _shutdownWinPtr ??=
    _winLib().lookupFunction<
        Int32 Function(IntPtr, Int32), int Function(int, int)>('shutdown');

int Function(int) get _htonsWin => _htonsWinPtr ??=
    _winLib().lookupFunction<Uint16 Function(Uint16), int Function(int)>('htons');

int Function(int) get _ntohsWin => _ntohsWinPtr ??=
    _winLib().lookupFunction<Uint16 Function(Uint16), int Function(int)>('ntohs');

int Function(int, Pointer<Utf8>, Pointer) get _inetPtonWin =>
    _inetPtonWinPtr ??= _winLib().lookupFunction<
        Int32 Function(Int32, Pointer<Utf8>, Pointer),
        int Function(int, Pointer<Utf8>, Pointer)>('inet_pton');

Pointer<Utf8> Function(int, Pointer, Pointer<Utf8>, int) get _inetNtopWin =>
    _inetNtopWinPtr ??= _winLib().lookupFunction<
        Pointer<Utf8> Function(Int32, Pointer, Pointer<Utf8>, Int32),
        Pointer<Utf8> Function(int, Pointer, Pointer<Utf8>, int)>('inet_ntop');

int Function(Pointer<Uint8>, int) get _gethostnameWin =>
    _gethostnameWinPtr ??= _winLib().lookupFunction<
        Int32 Function(Pointer<Uint8>, Int32),
        int Function(Pointer<Uint8>, int)>('gethostname');