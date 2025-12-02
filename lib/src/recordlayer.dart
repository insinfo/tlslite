

/// Implementation of the TLS Record Layer protocol

import 'dart:io';
import 'dart:typed_data';

import 'constants.dart';
import 'tls_protocol.dart';
import 'utils/cipherfactory.dart';
import 'utils/codec.dart';
import 'utils/cryptomath.dart';
import 'errors.dart';
import 'mathtls.dart';

/// Socket wrapper for reading and writing TLS Records
class RecordSocket {
  RecordSocket(this.socket);

  final Socket socket;
  TlsProtocolVersion version = const TlsProtocolVersion(0, 0);
  bool tls13record = false;
  int recvRecordLimit = 1 << 14;

  /// Send message through socket
  Future<void> send(Message msg, [int padding = 0]) async {
    final data = msg.write();
    Uint8List headerBytes;
    
    if (version == const TlsProtocolVersion(2, 0) || version == const TlsProtocolVersion(0, 2)) {
      final header = RecordHeader2().create(data.length, padding);
      headerBytes = header.write();
    } else {
      final header = RecordHeader3().create(version, msg.contentType, data.length);
      headerBytes = header.write();
    }

    socket.add([...headerBytes, ...data]);
    await socket.flush();
  }

  /// Read record from socket
  Future<(dynamic, Uint8List)> recv() async {
    // Read first byte
    var buf = await _readBytes(1);
    
    bool ssl2 = false;
    if (ContentType.all.contains(buf[0])) {
      ssl2 = false;
      buf = Uint8List.fromList([...buf, ...await _readBytes(4)]);
    } else {
      ssl2 = true;
      final readLen = (buf[0] & 0x80) != 0 ? 1 : 2;
      buf = Uint8List.fromList([...buf, ...await _readBytes(readLen)]);
    }

    dynamic header;
    if (ssl2) {
      header = RecordHeader2().parse(Parser(buf));
      if ((header.padding > header.length) || (header.padding != 0 && header.length % 8 != 0)) {
        throw TLSIllegalParameterException('Malformed record layer header');
      }
    } else {
      header = RecordHeader3().parse(Parser(buf));
    }

    if (header.length > recvRecordLimit + 2048) {
      throw TLSRecordOverflow();
    }
    if (tls13record && header.length > recvRecordLimit + 256) {
      throw TLSRecordOverflow();
    }

    final data = await _readBytes(header.length);
    return (header, data);
  }

  Future<Uint8List> _readBytes(int length) async {
    final buf = <int>[];
    await for (final chunk in socket) {
      buf.addAll(chunk);
      if (buf.length >= length) {
        return Uint8List.fromList(buf.sublist(0, length));
      }
    }
    throw TLSAbruptCloseError();
  }
}

/// Preserve connection state for reading and writing data to records
class ConnectionState {
  ConnectionState();

  dynamic macContext;
  dynamic encContext;
  Uint8List? fixedNonce;
  int seqnum = 0;
  bool encryptThenMAC = false;

  Uint8List getSeqNumBytes() {
    final writer = Writer();
    writer.add(seqnum, 8);
    seqnum++;
    return writer.bytes;
  }

  ConnectionState copy() {
    final ret = ConnectionState();
    ret.macContext = macContext;
    ret.encContext = encContext;
    ret.fixedNonce = fixedNonce;
    ret.seqnum = seqnum;
    ret.encryptThenMAC = encryptThenMAC;
    return ret;
  }
}

/// Implementation of TLS record layer protocol
class RecordLayer {
  RecordLayer(this.sock) {
    _recordSocket = RecordSocket(sock);
  }

  final Socket sock;
  late RecordSocket _recordSocket;
  TlsProtocolVersion _version = const TlsProtocolVersion(0, 0);
  bool _tls13record = false;

  bool client = true;

  ConnectionState _writeState = ConnectionState();
  ConnectionState _readState = ConnectionState();
  ConnectionState _pendingWriteState = ConnectionState();
  ConnectionState _pendingReadState = ConnectionState();
  Uint8List? fixedIVBlock;

  bool handshakeFinished = false;
  int sendRecordLimit = 1 << 14;

  int get recvRecordLimit => _recordSocket.recvRecordLimit;
  set recvRecordLimit(int value) => _recordSocket.recvRecordLimit = value;

  bool get encryptThenMAC => _writeState.encryptThenMAC;
  set encryptThenMAC(bool value) {
    _pendingWriteState.encryptThenMAC = value;
    _pendingReadState.encryptThenMAC = value;
  }

  int get blockSize => _writeState.encContext?.blockSize ?? 0;

  bool get tls13record => _tls13record;
  set tls13record(bool val) {
    _tls13record = val;
    _recordSocket.tls13record = val;
    _handleTls13Record();
  }

  bool _isTls13Plus() => _version > const TlsProtocolVersion(3, 3) && _tls13record;

  void _handleTls13Record() {
    if (_isTls13Plus()) {
      _recordSocket.version = const TlsProtocolVersion(3, 3);
    } else {
      _recordSocket.version = _version;
    }
  }

  TlsProtocolVersion get version => _version;
  set version(TlsProtocolVersion val) {
    _version = val;
    _handleTls13Record();
  }

  String? getCipherName() => _writeState.encContext?.name;

  void shutdown() {
    _writeState = ConnectionState();
    _readState = ConnectionState();
    _pendingWriteState = ConnectionState();
    _pendingReadState = ConnectionState();
  }

  bool isCBCMode() {
    return _writeState.encContext?.isBlockCipher ?? false;
  }

  Uint8List addPadding(Uint8List data) {
    final currentLength = data.length;
    final blockLength = blockSize;
    final paddingLength = blockLength - 1 - (currentLength % blockLength);
    final paddingBytes = Uint8List(paddingLength + 1);
    paddingBytes.fillRange(0, paddingBytes.length, paddingLength);
    return Uint8List.fromList([...data, ...paddingBytes]);
  }

  Uint8List calculateMAC(dynamic mac, Uint8List seqnumBytes, int contentType, Uint8List data) {
    mac.update(seqnumBytes);
    mac.update(Uint8List.fromList([contentType]));
    if (version != const TlsProtocolVersion(3, 0)) {
      mac.update(Uint8List.fromList([version.major, version.minor]));
    }
    final len = data.length;
    mac.update(Uint8List.fromList([len >> 8, len & 0xff]));
    mac.update(data);
    return Uint8List.fromList(mac.digest());
  }

  Future<void> sendRecord(Message msg) async {
    var data = msg.write();
    var contentType = msg.contentType;

    if (_writeState.encContext != null) {
      if (_writeState.macContext != null) {
        final seqnumBytes = _writeState.getSeqNumBytes();
        final mac = _writeState.macContext.copy();
        final macBytes = calculateMAC(mac, seqnumBytes, contentType, data);
        data = Uint8List.fromList([...data, ...macBytes]);
      }

      if (_writeState.encContext.isBlockCipher) {
        if (version >= const TlsProtocolVersion(3, 2)) {
          data = Uint8List.fromList([...fixedIVBlock!, ...data]);
        }
        data = addPadding(data);
      }
      data = _writeState.encContext.encrypt(data);
    }

    final encryptedMessage = Message(contentType, data);
    await _recordSocket.send(encryptedMessage);
  }

  Future<(dynamic, Parser)> recvRecord() async {
    final (header, data) = await _recordSocket.recv();
    var decryptedData = data;

    if (_readState.encContext != null) {
      decryptedData = _readState.encContext.decrypt(data);
      
      if (_readState.encContext.isBlockCipher && version >= const TlsProtocolVersion(3, 2)) {
        decryptedData = decryptedData.sublist(_readState.encContext.blockSize);
      }
    }

    if (_readState.macContext != null) {
      final macLength = _readState.macContext.digestSize as int;
      if (decryptedData.length < macLength) {
        throw TLSBadRecordMAC('Truncated MAC');
      }
      
      final checkBytes = decryptedData.sublist(decryptedData.length - macLength);
      decryptedData = decryptedData.sublist(0, decryptedData.length - macLength);

      if (_readState.encContext?.isBlockCipher ?? false) {
        final paddingLength = decryptedData[decryptedData.length - 1];
        final totalPaddingLength = paddingLength + 1;
        decryptedData = decryptedData.sublist(0, decryptedData.length - totalPaddingLength);
      }

      final seqnumBytes = _readState.getSeqNumBytes();
      final mac = _readState.macContext.copy();
      final macBytes = calculateMAC(mac, seqnumBytes, header.type, decryptedData);
      
      bool macGood = true;
      if (macBytes.length != checkBytes.length) {
        macGood = false;
      } else {
        for (var i = 0; i < macBytes.length; i++) {
          if (macBytes[i] != checkBytes[i]) {
            macGood = false;
            break;
          }
        }
      }
      
      if (!macGood) {
        throw TLSBadRecordMAC('MAC verification failed');
      }
    }

    if (decryptedData.length > recvRecordLimit) {
      throw TLSRecordOverflow();
    }

    return (header, Parser(decryptedData));
  }

  void changeWriteState() {
    if (version == const TlsProtocolVersion(0, 2) || version == const TlsProtocolVersion(2, 0)) {
      _pendingWriteState.seqnum = _writeState.seqnum;
    }
    _writeState = _pendingWriteState;
    _pendingWriteState = ConnectionState();
  }

  void changeReadState() {
    if (version == const TlsProtocolVersion(0, 2) || version == const TlsProtocolVersion(2, 0)) {
      _pendingReadState.seqnum = _readState.seqnum;
    }
    _readState = _pendingReadState;
    _pendingReadState = ConnectionState();
  }

  static (int, int, Function?) _getCipherSettings(int cipherSuite) {
    if (CipherSuite.aes256GcmSuites.contains(cipherSuite)) {
      return (32, 4, createAESGCM);
    } else if (CipherSuite.aes128GcmSuites.contains(cipherSuite)) {
      return (16, 4, createAESGCM);
    } else if (CipherSuite.aes128Suites.contains(cipherSuite)) {
      return (16, 16, createAES);
    } else if (CipherSuite.aes256Suites.contains(cipherSuite)) {
      return (32, 16, createAES);
    } else if (CipherSuite.rc4Suites.contains(cipherSuite)) {
      return (16, 0, createRC4);
    } else if (CipherSuite.tripleDESSuites.contains(cipherSuite)) {
      return (24, 8, createTripleDES);
    } else if (CipherSuite.nullSuites.contains(cipherSuite)) {
      return (0, 0, null);
    }
    throw AssertionError('Unknown cipher suite: $cipherSuite');
  }

  static (int, String?) _getMacSettings(int cipherSuite) {
    if (CipherSuite.aeadSuites.contains(cipherSuite)) {
      return (0, null);
    } else if (CipherSuite.shaSuites.contains(cipherSuite)) {
      return (20, 'sha1');
    } else if (CipherSuite.sha256Suites.contains(cipherSuite)) {
      return (32, 'sha256');
    } else if (CipherSuite.md5Suites.contains(cipherSuite)) {
      return (16, 'md5');
    }
    throw AssertionError('Unknown cipher suite for MAC: $cipherSuite');
  }

  void calcPendingStates(int cipherSuite, Uint8List masterSecret, Uint8List clientRandom,
      Uint8List serverRandom, List<String>? implementations) {
    final (keyLength, ivLength, createCipherFunc) = _getCipherSettings(cipherSuite);
    final (macLength, digestmod) = _getMacSettings(cipherSuite);

    final outputLength = (macLength * 2) + (keyLength * 2) + (ivLength * 2);
    final keyBlock = calcKey([version.major, version.minor], masterSecret, cipherSuite,
        Uint8List.fromList('key expansion'.codeUnits),
        clientRandom: clientRandom, serverRandom: serverRandom, outputLength: outputLength);

    final clientPendingState = ConnectionState();
    final serverPendingState = ConnectionState();
    final parser = Parser(keyBlock);
    final clientMACBlock = parser.getFixBytes(macLength);
    final serverMACBlock = parser.getFixBytes(macLength);
    final clientKeyBlock = parser.getFixBytes(keyLength);
    final serverKeyBlock = parser.getFixBytes(keyLength);
    final clientIVBlock = parser.getFixBytes(ivLength);
    final serverIVBlock = parser.getFixBytes(ivLength);

    if (digestmod != null) {
      clientPendingState.macContext = createHMAC(clientMACBlock, digestmod);
      serverPendingState.macContext = createHMAC(serverMACBlock, digestmod);
      if (createCipherFunc != null) {
        clientPendingState.encContext = createCipherFunc(clientKeyBlock, clientIVBlock, implementations: implementations);
        serverPendingState.encContext = createCipherFunc(serverKeyBlock, serverIVBlock, implementations: implementations);
      }
    } else {
      clientPendingState.macContext = null;
      serverPendingState.macContext = null;
      if (createCipherFunc != null) {
        clientPendingState.encContext = createCipherFunc(clientKeyBlock, implementations: implementations);
        serverPendingState.encContext = createCipherFunc(serverKeyBlock, implementations: implementations);
      }
      clientPendingState.fixedNonce = clientIVBlock;
      serverPendingState.fixedNonce = serverIVBlock;
    }

    if (client) {
      clientPendingState.encryptThenMAC = _pendingWriteState.encryptThenMAC;
      _pendingWriteState = clientPendingState;
      serverPendingState.encryptThenMAC = _pendingReadState.encryptThenMAC;
      _pendingReadState = serverPendingState;
    } else {
      serverPendingState.encryptThenMAC = _pendingWriteState.encryptThenMAC;
      _pendingWriteState = serverPendingState;
      clientPendingState.encryptThenMAC = _pendingReadState.encryptThenMAC;
      _pendingReadState = clientPendingState;
    }

    if (version >= const TlsProtocolVersion(3, 2) && ivLength > 0) {
      fixedIVBlock = getRandomBytes(ivLength);
    }
  }
}

class RecordHeader2 {
  int length = 0;
  int padding = 0;
  int type = 0;

  RecordHeader2 create(int length, int padding) {
    this.length = length;
    this.padding = padding;
    return this;
  }

  RecordHeader2 parse(Parser parser) {
    final firstByte = parser.get(1);
    if ((firstByte & 0x80) != 0) {
      length = ((firstByte & 0x7f) << 8) | parser.get(1);
      padding = 0;
    } else {
      length = ((firstByte & 0x3f) << 8) | parser.get(1);
      padding = parser.get(1);
    }
    return this;
  }

  Uint8List write() {
    final writer = Writer();
    if (padding == 0) {
      writer.add(0x80 | (length >> 8), 1);
      writer.add(length & 0xff, 1);
    } else {
      writer.add((length >> 8) & 0x3f, 1);
      writer.add(length & 0xff, 1);
      writer.add(padding, 1);
    }
    return writer.bytes;
  }
}

class RecordHeader3 {
  int type = 0;
  TlsProtocolVersion version = const TlsProtocolVersion(0, 0);
  int length = 0;

  RecordHeader3 create(TlsProtocolVersion version, int type, int length) {
    this.version = version;
    this.type = type;
    this.length = length;
    return this;
  }

  RecordHeader3 parse(Parser parser) {
    type = parser.get(1);
    final major = parser.get(1);
    final minor = parser.get(1);
    version = TlsProtocolVersion(major, minor);
    length = parser.get(2);
    return this;
  }

  Uint8List write() {
    final writer = Writer();
    writer.add(type, 1);
    writer.add(version.major, 1);
    writer.add(version.minor, 1);
    writer.add(length, 2);
    return writer.bytes;
  }
}

class Message {
  Message(this.contentType, this.data);

  final int contentType;
  final Uint8List data;

  Uint8List write() => data;
}
