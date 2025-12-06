library tlslite_socket_native_ffi;

import 'dart:ffi';
import 'dart:ffi' as ffi;
import 'dart:io' show Platform;
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'package:tlslite/src/net_ffi/socket_exceptions.dart';
import '../raw_transport.dart';
import '../native_buffer_utils.dart';
part 'platform/windows.dart';
part 'platform/linux.dart';
part 'runtime_helpers.dart';

typedef SocketHandle = int;

int Function(int, Pointer<Utf8>, Pointer) get _inetPton =>
    Platform.isWindows ? _inetPtonWin : _inetPtonUnix;

Pointer<Utf8> Function(int, Pointer, Pointer<Utf8>, int) get _inetNtop =>
    Platform.isWindows ? _inetNtopWin : _inetNtopUnix;

int Function(Pointer<Uint8>, int) get _gethostname =>
    Platform.isWindows ? _gethostnameWin : _gethostnameUnix;

int Function(int) get _htons => Platform.isWindows ? _htonsWin : _htonsPosix;

int Function(int) get _ntohs => Platform.isWindows ? _ntohsWin : _ntohsPosix;

int _getsockname(dynamic handle, Pointer addr, Pointer<Int32> addrLen) {
  return Platform.isWindows
      ? _getsocknameWin(handle as SocketHandle, addr, addrLen)
      : _getsocknameUnix(handle as int, addr, addrLen);
}

extension Uint8Pointer on Pointer<Uint8> {
  Pointer<Uint8> elementAt(int index) =>
      Pointer.fromAddress(address + sizeOf<Uint8>() * index);

  Pointer<Uint8> operator +(int offset) =>
      Pointer.fromAddress(address + sizeOf<Uint8>() * offset);

  Pointer<Uint8> operator -(int offset) =>
      Pointer.fromAddress(address - sizeOf<Uint8>() * offset);
}

final class SockaddrIn extends Struct {
  @Int16()
  external int sin_family;

  @Uint16()
  external int sin_port;

  @Uint32()
  external int s_addr;

  @Array<Uint8>(8)
  external Array<Uint8> sin_zero;
}

final class WSADATA extends Struct {
  @Uint16()
  external int wVersion;

  @Uint16()
  external int wHighVersion;

  @Array<Int8>(WSADESCRIPTION_LEN + 1)
  external Array<Int8> szDescription;

  @Array<Int8>(WSASYS_STATUS_LEN + 1)
  external Array<Int8> szSystemStatus;

  @Uint16()
  external int iMaxSockets;

  @Uint16()
  external int iMaxUdpDg;

  external Pointer<Int8> lpVendorInfo;
}

final class In6Addr extends Struct {
  @Array<Uint8>(16)
  external Array<Uint8> s6_addr;
}

final class ScopeIdStruct extends Struct {
  @Uint32()
  external int someField;
}

final class ScopeIdUnion extends Union {
  @Uint32()
  external int sin6_scope_id;
  external ScopeIdStruct sin6_scope_struct;
}

final class SockAddrIn6 extends Struct {
  @Uint16()
  external int sin6_family;

  @Uint16()
  external int sin6_port;

  @Uint32()
  external int sin6_flowinfo;

  external In6Addr sin6_addr;

  @Uint32()
  external int sin6_scope_id;
}

final class PollFd extends Struct {
  @IntPtr()
  external int fd;

  @Int16()
  external int events;

  @Int16()
  external int revents;
}

const int WSADESCRIPTION_LEN = 256;
const int WSASYS_STATUS_LEN = 128;
const int AF_INET = 2;
const int SOCK_STREAM = 1;
const int IPPROTO_TCP = 6;
const int AF_INET6 = 23;
const int SOCK_DGRAM = 2;
const int INET6_ADDRSTRLEN = 46;
const int POLLIN = 0x0001;
const int POLLOUT = 0x0004;
const int POLLERR = 0x0008;
const int POLLHUP = 0x0010;
const int POLLNVAL = 0x0020;
const int _FIONBIO = 0x8004667E;
const int _WSAEWOULDBLOCK = 10035;
const int _WSAEINTR = 10004;
const int _POSIX_EINTR = 4;
const int _POSIX_EAGAIN_LINUX = 11;
const int _POSIX_EAGAIN_MAC = 35;
const int _O_NONBLOCK_LINUX = 0x00000800;
const int _O_NONBLOCK_MAC = 0x00000004;
const int _SOL_SOCKET_POSIX = 1;
const int _SOL_SOCKET_WINDOWS = 0xFFFF;
const int _SO_REUSEADDR_POSIX = 2;
const int _SO_REUSEADDR_WINDOWS = 0x0004;
const int _SO_REUSEPORT_POSIX = 15;
const int _SO_REUSEPORT_WINDOWS = 0x0200;
const int _TCP_NODELAY_OPT = 1;

/// TODO Extend the test matrix (IPv6/UDP, non‑blocking happy paths, Linux/macOS CI) to close TODO #4.
/// Consider an isolate-backed helper that builds on the new non‑blocking plumbing for long-lived DB or traceroute tasks.
class SocketNative implements RawTransport {
  static Pointer<WSADATA>? _winsockData;
  static int _winsockRefCount = 0;

  static void _winsockAcquire() {
    if (!Platform.isWindows) {
      return;
    }
    _winsockRefCount++;
    if (_winsockRefCount == 1) {
      final data = calloc<WSADATA>();
      final result = _WSAStartup(0x0202, data);
      if (result != 0) {
        calloc.free(data);
        _winsockRefCount = 0;
        throw SocketException('WSAStartup failed: $result');
      }
      _winsockData = data;
    }
  }

  static void _winsockRelease() {
    if (!Platform.isWindows || _winsockRefCount == 0) {
      return;
    }
    _winsockRefCount--;
    if (_winsockRefCount == 0) {
      _WSACleanup();
      if (_winsockData != null) {
        calloc.free(_winsockData!);
        _winsockData = null;
      }
    }
  }

  SocketHandle? _socketHandle; // Windows socket handle
  /// Windows socket handle
  SocketHandle? getWindowsSocketHandle() {
    return _socketHandle;
  }

  /// Unix socket handle
  int? getUnixSocketHandle() {
    return _fd;
  }

  int? _fd; // Unix file descriptor
  bool _closed = false;
  final int _family; // AF_INET ou AF_INET6
  final int _type; // SOCK_STREAM ou SOCK_DGRAM
  double? _timeout; // Timeout em segundos
  SocketBlockingMode _mode = SocketBlockingMode.blocking;

  @override
  (String, int) get address => getAddress();

  @override
  int get port => getAddress().$2;

  @override
  int? get nativeHandle => Platform.isWindows ? _socketHandle : _fd;

  (String, int) getAddress() {
    String host;
    int port;
    final buffer = calloc<Uint8>(INET6_ADDRSTRLEN);

    if (_family == AF_INET) {
      // Para IPv4, aloca SockaddrIn.
      final addr = calloc<SockaddrIn>();
      final addrLen = calloc<Int32>()..value = sizeOf<SockaddrIn>();
      final handle = Platform.isWindows ? _socketHandle : _fd;
      final result = _getsockname(handle!, addr.cast(), addrLen);
      if (result == -1) {
        calloc.free(addr);
        calloc.free(addrLen);
        calloc.free(buffer);
        _throwWithOsError('getsockname');
      }
      // O campo s_addr começa aos 4 bytes.
      final ptr = addr.cast<Uint8>() + 4;
      final convResult =
          _inetNtop(AF_INET, ptr, buffer.cast(), INET6_ADDRSTRLEN);
      if (convResult == nullptr) {
        calloc.free(addr);
        calloc.free(addrLen);
        calloc.free(buffer);
        throw SocketException('Failed to convert address');
      }
      host = buffer.cast<Utf8>().toDartString();
      port = _ntohs(addr.ref.sin_port);
      calloc.free(addr);
      calloc.free(addrLen);
    } else {
      // Para IPv6, aloca SockAddrIn6.
      final addr = calloc<SockAddrIn6>();
      final addrLen = calloc<Int32>()..value = sizeOf<SockAddrIn6>();
      final handle = Platform.isWindows ? _socketHandle : _fd;
      final result = _getsockname(handle!, addr.cast(), addrLen);
      if (result == -1) {
        calloc.free(addr);
        calloc.free(addrLen);
        calloc.free(buffer);
        _throwWithOsError('getsockname');
      }
      // O campo sin6_addr inicia aos 8 bytes (2+2+4).
      const sin6AddrOffset = 8;
      final ptr = addr.cast<Uint8>() + sin6AddrOffset;
      final convResult =
          _inetNtop(AF_INET6, ptr, buffer.cast(), INET6_ADDRSTRLEN);
      if (convResult == nullptr) {
        calloc.free(addr);
        calloc.free(addrLen);
        calloc.free(buffer);
        throw SocketException('Failed to convert address');
      }
      host = buffer.cast<Utf8>().toDartString();
      port = _ntohs(addr.ref.sin6_port);
      calloc.free(addr);
      calloc.free(addrLen);
    }

    calloc.free(buffer);
    return (host, port);
  }

  /// Construtor principal
  SocketNative(int family, int type, int protocol,
      {SocketBlockingMode blockingMode = SocketBlockingMode.blocking})
      : _family = family,
        _type = type,
        _mode = blockingMode {
    if (family != AF_INET && family != AF_INET6) {
      throw SocketException('Unsupported address family');
    }
    if (type != SOCK_STREAM && type != SOCK_DGRAM) {
      throw SocketException('Unsupported socket type');
    }
    if (Platform.isWindows) {
      _winsockAcquire();
      _socketHandle = _socketWin(family, type, protocol);
      if (_socketHandle == _INVALID_SOCKET) {
        _winsockRelease();
        throw SocketException('Failed to create socket');
      }
      _applyBlockingMode(blockingMode);
    } else {
      _fd = _socketUnix(family, type, protocol);
      if (_fd == -1) {
        throw SocketException('Failed to create socket');
      }
      _applyBlockingMode(blockingMode);
    }
  }

  factory SocketNative.blocking(int family, int type, int protocol) =>
      SocketNative(family, type, protocol,
          blockingMode: SocketBlockingMode.blocking);

  factory SocketNative.nonBlocking(int family, int type, int protocol) =>
      SocketNative(family, type, protocol,
          blockingMode: SocketBlockingMode.nonBlocking);

  SocketNative._fromSocket(SocketHandle socket, this._family, this._type,
      {SocketBlockingMode mode = SocketBlockingMode.blocking}) {
    if (Platform.isWindows) {
      _winsockAcquire();
    }
    _socketHandle = socket;
    _applyBlockingMode(mode);
  }
  SocketNative._fromFd(int fd, this._family, this._type,
      {SocketBlockingMode mode = SocketBlockingMode.blocking})
      : _fd = fd {
    _applyBlockingMode(mode);
  }

  @override
  SocketBlockingMode get blockingMode => _mode;

  @override
  bool get isClosed => _closed;

  // **1. Suporte a gethostname()**
  static String gethostname() {
    final buffer = calloc<Uint8>(256);
    final result = _gethostname(buffer, 256);
    if (result != 0) {
      calloc.free(buffer);
      throw SocketException('Failed to get hostname');
    }
    final hostname = buffer.cast<Utf8>().toDartString();
    calloc.free(buffer);
    return hostname;
  }

  // **2. Suporte a settimeout()**
  void settimeout(double? timeout) {
    _timeout = timeout;
  }

  // **3. Suporte a sendall()**
  void sendall(Uint8List data) {
    final sent = send(data);
    if (sent != data.length) {
      throw SocketException('Connection closed before all bytes were sent');
    }
  }

  // **4. Suporte a UDP (SOCK_DGRAM)**
  (Uint8List, String, int) recvfrom(int bufferSize) {
    if (_type != SOCK_DGRAM) {
      throw SocketException('recvfrom is only for UDP sockets');
    }
    final buffer = NativeUint8Buffer.pooled(bufferSize);
    final addr =
        _family == AF_INET ? calloc<SockaddrIn>() : calloc<SockAddrIn6>();
    final addrLen = calloc<Int32>()
      ..value =
          _family == AF_INET ? sizeOf<SockaddrIn>() : sizeOf<SockAddrIn6>();
    try {
      while (true) {
        _maybeWaitForEvent(TransportEvent.read);
        final received = Platform.isWindows
            ? _recvfromWin(_socketHandle!, buffer.pointer, bufferSize, 0,
                addr.cast(), addrLen)
            : _recvfromUnix(
                _fd!, buffer.pointer, bufferSize, 0, addr.cast(), addrLen);
        if (received >= 0) {
          final data = buffer.copyToDart(received);
          final addrBuffer = calloc<Uint8>(INET6_ADDRSTRLEN);
          try {
            String host;
            int port;
            if (_family == AF_INET) {
              final sockAddrIn = addr.cast<SockaddrIn>().ref;
              final ptr = addr.cast<Uint8>() + 4;
              final result =
                  _inetNtop(AF_INET, ptr, addrBuffer.cast(), INET6_ADDRSTRLEN);
              if (result == nullptr) {
                _throwWithOsError('inet_ntop');
              }
              host = addrBuffer.cast<Utf8>().toDartString();
              port = _ntohs(sockAddrIn.sin_port);
            } else {
              final sockAddrIn6 = addr.cast<SockAddrIn6>().ref;
              final ptr = addr.cast<Uint8>() + 8;
              final result =
                  _inetNtop(AF_INET6, ptr, addrBuffer.cast(), INET6_ADDRSTRLEN);
              if (result == nullptr) {
                _throwWithOsError('inet_ntop');
              }
              host = addrBuffer.cast<Utf8>().toDartString();
              port = _ntohs(sockAddrIn6.sin6_port);
            }
            return (data, host, port);
          } finally {
            calloc.free(addrBuffer);
          }
        }
        final code = _lastErrorCode();
        if (_isRetryable(code)) {
          continue;
        }
        if (_isWouldBlock(code)) {
          if (_mode == SocketBlockingMode.nonBlocking) {
            throw SocketWouldBlockException(
                'recvfrom would block (code=$code)');
          }
          continue;
        }
        _throwWithOsError('recvfrom');
      }
    } finally {
      buffer.release();
      calloc.free(addr);
      calloc.free(addrLen);
    }
  }

  int sendto(Uint8List data, String host, int port) {
    if (_type != SOCK_DGRAM) {
      throw SocketException('sendto is only for UDP sockets');
    }

    Pointer addr;
    int addrSize;
    if (_family == AF_INET) {
      final ipv4 = calloc<SockaddrIn>();
      ipv4.ref.sin_family = AF_INET;
      ipv4.ref.sin_port = _htons(port);
      final hostPtr = host.toNativeUtf8();
      final ipBuffer = calloc<Uint32>();
      final ip = _inetPton(AF_INET, hostPtr, ipBuffer.cast());
      calloc.free(hostPtr);
      if (ip != 1) {
        calloc.free(ipBuffer);
        calloc.free(ipv4);
        throw SocketException('Invalid address');
      }
      ipv4.ref.s_addr = ipBuffer.value;
      calloc.free(ipBuffer);
      addr = ipv4.cast();
      addrSize = sizeOf<SockaddrIn>();
    } else {
      final ipv6 = calloc<SockAddrIn6>();
      ipv6.ref.sin6_family = AF_INET6;
      ipv6.ref.sin6_port = _htons(port);
      final hostPtr = host.toNativeUtf8();
      final ip = _inetPton(AF_INET6, hostPtr, ipv6.cast<Uint8>().elementAt(8));
      calloc.free(hostPtr);
      if (ip != 1) {
        calloc.free(ipv6);
        throw SocketException('Invalid address');
      }
      addr = ipv6.cast();
      addrSize = sizeOf<SockAddrIn6>();
    }

    final buffer = NativeUint8Buffer.fromBytes(
      data,
      pool: NativeUint8BufferPool.global,
    );
    try {
      while (true) {
        _maybeWaitForEvent(TransportEvent.write);
        final sent = Platform.isWindows
            ? _sendtoWin(
                _socketHandle!, buffer.pointer, data.length, 0, addr, addrSize)
            : _sendtoUnix(_fd!, buffer.pointer, data.length, 0, addr, addrSize);
        if (sent >= 0) {
          return sent;
        }
        final code = _lastErrorCode();
        if (_isRetryable(code)) {
          continue;
        }
        if (_isWouldBlock(code)) {
          if (_mode == SocketBlockingMode.nonBlocking) {
            throw SocketWouldBlockException('sendto would block (code=$code)');
          }
          continue;
        }
        _throwWithOsError('sendto');
      }
    } finally {
      buffer.release();
      calloc.free(addr);
    }
  }

  void bind(String host, int port) {
    if (_family == AF_INET) {
      // IPv4
      final addr = calloc<SockaddrIn>();
      addr.ref.sin_family = AF_INET;
      addr.ref.sin_port = _htons(port);

      final hostPtr = host.toNativeUtf8();
      final ipBuffer = calloc<Uint32>();
      final ip = _inetPton(AF_INET, hostPtr, ipBuffer.cast());
      calloc.free(hostPtr);
      if (ip != 1) {
        calloc.free(ipBuffer);
        calloc.free(addr);
        throw SocketException('Invalid address');
      }
      // Atribui o endereço binário ao campo s_addr
      addr.ref.s_addr = ipBuffer.value;
      calloc.free(ipBuffer);

      int result = Platform.isWindows
          ? _bindWin(_socketHandle!, addr.cast(), sizeOf<SockaddrIn>())
          : _bindUnix(_fd!, addr.cast(), sizeOf<SockaddrIn>());
      calloc.free(addr);
      if (result != 0) throw SocketException('Bind failed');
    } else {
      // IPv6
      final addr = calloc<SockAddrIn6>();
      addr.ref.sin6_family = AF_INET6;
      addr.ref.sin6_port = _htons(port);

      // Aloca buffer temporário para receber os 16 bytes do endereço IPv6
      final temp = calloc<Uint8>(16);
      final hostPtr = host.toNativeUtf8();
      final ip = _inetPton(AF_INET6, hostPtr, temp);
      calloc.free(hostPtr);
      if (ip != 1) {
        calloc.free(temp);
        calloc.free(addr);
        throw SocketException('Invalid address');
      }

      // Cálculo de offset: sin6_family(2 bytes) + sin6_port(2 bytes) + sin6_flowinfo(4 bytes) = 8 bytes
      // Logo, o campo sin6_addr começa no offset 8
      const sin6AddrOffset = 8;

      // Ponteiro para o início da estrutura
      final addrPtr = addr.cast<Uint8>();

      // Copia os 16 bytes do buffer temporário (temp) para o campo sin6_addr
      for (int i = 0; i < 16; i++) {
        addrPtr.elementAt(sin6AddrOffset + i).value = temp[i];
      }
      calloc.free(temp);

      int result = Platform.isWindows
          ? _bindWin(_socketHandle!, addr.cast(), sizeOf<SockAddrIn6>())
          : _bindUnix(_fd!, addr.cast(), sizeOf<SockAddrIn6>());
      calloc.free(addr);
      if (result != 0) throw SocketException('Bind failed');
    }
  }

  void connect(String host, int port) {
    if (_family == AF_INET) {
      final addr = calloc<SockaddrIn>();
      addr.ref.sin_family = AF_INET;
      addr.ref.sin_port = _htons(port);

      // Aloca buffer temporário para receber o endereço IPv4.
      final ipBuffer = calloc<Uint32>();
      final hostPtr = host.toNativeUtf8();
      final ip = _inetPton(AF_INET, hostPtr, ipBuffer.cast());
      calloc.free(hostPtr);

      if (ip != 1) {
        calloc.free(ipBuffer);
        calloc.free(addr);
        throw SocketException('Invalid address');
      }
      // Copia o valor convertido para o campo s_addr.
      addr.ref.s_addr = ipBuffer.value;
      calloc.free(ipBuffer);

      int result = Platform.isWindows
          ? _connectWin(_socketHandle!, addr.cast(), sizeOf<SockaddrIn>())
          : _connectUnix(_fd!, addr.cast(), sizeOf<SockaddrIn>());
      calloc.free(addr);

      if (result != 0) throw SocketException('Connect failed');
    } else {
      final addr = calloc<SockAddrIn6>();
      addr.ref.sin6_family = AF_INET6;
      addr.ref.sin6_port = _htons(port);

      // Aloca buffer temporário de 16 bytes para o endereço IPv6.
      final temp = calloc<Uint8>(16);
      final hostPtr = host.toNativeUtf8();
      final ip = _inetPton(AF_INET6, hostPtr, temp);
      calloc.free(hostPtr);

      if (ip != 1) {
        calloc.free(temp);
        calloc.free(addr);
        throw SocketException('Invalid address');
      }

      // Cálculo de offset para sin6_addr: sin6_family(2) + sin6_port(2) + sin6_flowinfo(4) = 8 bytes
      const sin6AddrOffset = 8;
      final addrPtr = addr.cast<Uint8>();

      // Copia os 16 bytes de temp para o campo sin6_addr.
      for (int i = 0; i < 16; i++) {
        addrPtr.elementAt(sin6AddrOffset + i).value = temp[i];
      }
      calloc.free(temp);

      int result = Platform.isWindows
          ? _connectWin(_socketHandle!, addr.cast(), sizeOf<SockAddrIn6>())
          : _connectUnix(_fd!, addr.cast(), sizeOf<SockAddrIn6>());
      calloc.free(addr);

      if (result != 0) throw SocketException('Connect failed');
    }
  }

  SocketNative accept() {
    if (_family == AF_INET) {
      final clientAddr = calloc<SockaddrIn>();
      final addrLen = calloc<Int32>()..value = sizeOf<SockaddrIn>();
      if (Platform.isWindows) {
        final clientSocket =
            _acceptWin(_socketHandle!, clientAddr.cast(), addrLen);
        calloc.free(clientAddr);
        calloc.free(addrLen);
        if (clientSocket == _INVALID_SOCKET) {
          throw SocketException('Accept failed');
        }
        final child =
            SocketNative._fromSocket(clientSocket, AF_INET, _type, mode: _mode);
        child._timeout = _timeout;
        return child;
      } else {
        final clientFd = _acceptUnix(_fd!, clientAddr.cast(), addrLen);
        calloc.free(clientAddr);
        calloc.free(addrLen);
        if (clientFd == -1) throw SocketException('Accept failed');
        final child =
            SocketNative._fromFd(clientFd, AF_INET, _type, mode: _mode);
        child._timeout = _timeout;
        return child;
      }
    } else {
      final clientAddr = calloc<SockAddrIn6>();
      final addrLen = calloc<Int32>()..value = sizeOf<SockAddrIn6>();
      if (Platform.isWindows) {
        final clientSocket =
            _acceptWin(_socketHandle!, clientAddr.cast(), addrLen);
        calloc.free(clientAddr);
        calloc.free(addrLen);
        if (clientSocket == _INVALID_SOCKET) {
          throw SocketException('Accept failed');
        }
        final child = SocketNative._fromSocket(clientSocket, AF_INET6, _type,
            mode: _mode);
        child._timeout = _timeout;
        return child;
      } else {
        final clientFd = _acceptUnix(_fd!, clientAddr.cast(), addrLen);
        calloc.free(clientAddr);
        calloc.free(addrLen);
        if (clientFd == -1) throw SocketException('Accept failed');
        final child =
            SocketNative._fromFd(clientFd, AF_INET6, _type, mode: _mode);
        child._timeout = _timeout;
        return child;
      }
    }
  }

  // **6. Modos não bloqueantes**
  void setblocking(bool flag) {
    setBlockingMode(
        flag ? SocketBlockingMode.blocking : SocketBlockingMode.nonBlocking);
  }

  int send(Uint8List data) {
    if (data.isEmpty) {
      return 0;
    }
    final nativeBuffer = NativeUint8Buffer.fromBytes(
      data,
      pool: NativeUint8BufferPool.global,
    );
    var offset = 0;
    try {
      while (offset < data.length) {
        _maybeWaitForEvent(TransportEvent.write);
        final ptr = nativeBuffer.slice(offset);
        final remaining = data.length - offset;
        final result = Platform.isWindows
            ? _sendWin(_socketHandle!, ptr, remaining, 0)
            : _sendUnix(_fd!, ptr, remaining, 0);
        if (result > 0) {
          offset += result;
          continue;
        }
        if (result == 0) {
          throw SocketException('Remote peer closed connection during send');
        }
        final code = _lastErrorCode();
        if (_isRetryable(code)) {
          continue;
        }
        if (_isWouldBlock(code)) {
          if (_mode == SocketBlockingMode.nonBlocking) {
            throw SocketWouldBlockException('send would block (code=$code)');
          }
          continue;
        }
        _throwWithOsError('send');
      }
      return offset;
    } finally {
      nativeBuffer.release();
    }
  }

  Uint8List recv(int bufferSize) {
    if (bufferSize <= 0) {
      throw ArgumentError.value(bufferSize, 'bufferSize', 'must be positive');
    }
    final buffer = NativeUint8Buffer.pooled(bufferSize);
    try {
      while (true) {
        _maybeWaitForEvent(TransportEvent.read);
        final received = Platform.isWindows
            ? _recvWin(_socketHandle!, buffer.pointer, bufferSize, 0)
            : _recvUnix(_fd!, buffer.pointer, bufferSize, 0);
        if (received > 0) {
          final data = buffer.copyToDart(received);
          return data;
        }
        if (received == 0) {
          return Uint8List(0);
        }
        final code = _lastErrorCode();
        if (_isRetryable(code)) {
          continue;
        }
        if (_isWouldBlock(code)) {
          if (_mode == SocketBlockingMode.nonBlocking) {
            throw SocketWouldBlockException('recv would block (code=$code)');
          }
          continue;
        }
        _throwWithOsError('recv');
      }
    } finally {
      buffer.release();
    }
  }

  void listen(int backlog) {
    int result = Platform.isWindows
        ? _listenWin(_socketHandle!, backlog)
        : _listenUnix(_fd!, backlog);
    if (result != 0) throw SocketException('Listen failed');
  }

  void close() {
    if (_closed) return;
    int result =
        Platform.isWindows ? _closesocketWin(_socketHandle!) : _closeUnix(_fd!);
    if (result != 0) throw SocketException('Close failed');
    _closed = true;
    if (Platform.isWindows) {
      _socketHandle = null;
      _winsockRelease();
    } else {
      _fd = null;
    }
  }

  void setBlockingMode(SocketBlockingMode mode) => _applyBlockingMode(mode);

  void setTimeout(Duration? duration) {
    _timeout = duration == null ? null : duration.inMicroseconds / 1000000;
  }

  @override
  Duration? get timeoutDuration => _timeout == null
      ? null
      : SocketRuntimeHelper.secondsToDuration(_timeout!);

  bool waitForRead({Duration? timeout}) =>
      _pollForAvailability(TransportEvent.read, timeout);

  bool waitForWrite({Duration? timeout}) =>
      _pollForAvailability(TransportEvent.write, timeout);

  void setReuseAddress(bool enabled) {
    _setSocketOptionInt(_solSocketLevel, _soReuseAddrOption, enabled ? 1 : 0);
  }

  void setReusePort(bool enabled) {
    _setSocketOptionInt(_solSocketLevel, _soReusePortOption, enabled ? 1 : 0);
  }

  void setNoDelay(bool enabled) {
    _setSocketOptionInt(IPPROTO_TCP, _TCP_NODELAY_OPT, enabled ? 1 : 0);
  }

  void shutdown([SocketShutdown how = SocketShutdown.both]) {
    final flag = switch (how) {
      SocketShutdown.receive => 0,
      SocketShutdown.send => 1,
      SocketShutdown.both => 2,
    };
    final result = Platform.isWindows
        ? _shutdownWin(_socketHandle!, flag)
        : _shutdownUnix(_fd!, flag);
    if (result != 0) {
      _throwWithOsError('shutdown');
    }
  }

  void _applyBlockingMode(SocketBlockingMode mode) {
    if (Platform.isWindows) {
      final modePtr = calloc<Uint32>()
        ..value = mode == SocketBlockingMode.blocking ? 0 : 1;
      try {
        final result = _ioctlsocket(_socketHandle!, _FIONBIO, modePtr);
        if (result != 0) {
          _throwWithOsError('ioctlsocket');
        }
      } finally {
        calloc.free(modePtr);
      }
    } else {
      final flags = _fcntl(_fd!, 3, 0); // F_GETFL
      if (flags == -1) {
        _throwWithOsError('fcntl(F_GETFL)');
      }
      final desiredFlag = _oNonBlockFlag;
      final newFlags = mode == SocketBlockingMode.blocking
          ? flags & ~desiredFlag
          : flags | desiredFlag;
      if (_fcntl(_fd!, 4, newFlags) == -1) {
        _throwWithOsError('fcntl(F_SETFL)');
      }
    }
    _mode = mode;
  }

  bool _pollForAvailability(TransportEvent event, Duration? timeout) {
    final pollFd = calloc<PollFd>();
    try {
      pollFd.ref.fd = Platform.isWindows ? _socketHandle! : _fd!;
      pollFd.ref.events = event == TransportEvent.read ? POLLIN : POLLOUT;
      pollFd.ref.revents = 0;
      final duration = timeout ??
          (_timeout == null
              ? null
              : SocketRuntimeHelper.secondsToDuration(_timeout!));
      final timeoutMs = duration?.inMilliseconds ?? -1;
      final result = Platform.isWindows
          ? _wsaPoll(pollFd, 1, timeoutMs)
          : _pollUnix(pollFd, 1, timeoutMs);
      if (result == 0) {
        return false;
      }
      if (result < 0) {
        _throwWithOsError('poll');
      }
      final revents = pollFd.ref.revents;
      if ((revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        throw SocketException(
            'Socket error during poll (events=0x${revents.toRadixString(16)})');
      }
      return true;
    } finally {
      calloc.free(pollFd);
    }
  }

  void _maybeWaitForEvent(TransportEvent event) {
    if (_timeout == null || _mode == SocketBlockingMode.nonBlocking) {
      return;
    }
    TransportRuntime.ensureEvent(
      this,
      event,
      timeout: SocketRuntimeHelper.secondsToDuration(_timeout!),
    );
  }

  int _lastErrorCode() => SocketRuntimeHelper.lastErrorCode();

  bool _isRetryable(int code) => SocketRuntimeHelper.isRetryable(code);

  bool _isWouldBlock(int code) => SocketRuntimeHelper.isWouldBlock(code);

  Never _throwWithOsError(String operation) =>
      SocketRuntimeHelper.throwWithOsError(operation);

  void _setSocketOptionInt(int level, int option, int value) {
    final optval = calloc<Int32>()..value = value;
    try {
      final result = Platform.isWindows
          ? _setsockoptWin(
              _socketHandle!, level, option, optval.cast(), sizeOf<Int32>())
          : _setsockoptUnix(
              _fd!, level, option, optval.cast(), sizeOf<Int32>());
      if (result != 0) {
        _throwWithOsError('setsockopt');
      }
    } finally {
      calloc.free(optval);
    }
  }

  int get _solSocketLevel =>
      Platform.isWindows ? _SOL_SOCKET_WINDOWS : _SOL_SOCKET_POSIX;

  int get _soReuseAddrOption =>
      Platform.isWindows ? _SO_REUSEADDR_WINDOWS : _SO_REUSEADDR_POSIX;

  int get _soReusePortOption =>
      Platform.isWindows ? _SO_REUSEPORT_WINDOWS : _SO_REUSEPORT_POSIX;

  int get _oNonBlockFlag =>
      Platform.isMacOS ? _O_NONBLOCK_MAC : _O_NONBLOCK_LINUX;
}

class TransportRuntime {
  const TransportRuntime._();

  static Duration? _effectiveTimeout(
          RawTransport transport, Duration? override) =>
      override ?? transport.timeoutDuration;

  static bool waitForEvent(RawTransport transport, TransportEvent event,
      {Duration? timeout}) {
    final duration = _effectiveTimeout(transport, timeout);
    return event == TransportEvent.read
        ? transport.waitForRead(timeout: duration)
        : transport.waitForWrite(timeout: duration);
  }

  static void ensureEvent(
    RawTransport transport,
    TransportEvent event, {
    Duration? timeout,
  }) {
    final ready = waitForEvent(transport, event, timeout: timeout);
    if (!ready) {
      throw SocketTimeoutException('Operation timed out');
    }
  }
}
