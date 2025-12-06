/// Implementation of the TLS Record Layer protocol

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';


import 'constants.dart';
import 'tls_protocol.dart';
import 'utils/cipherfactory.dart';
import 'utils/codec.dart';
import 'utils/cryptomath.dart';
import 'utils/constanttime.dart';
import 'errors.dart';
import 'mathtls.dart';


import 'utils/binary_io.dart';

/// Socket wrapper for reading and writing TLS Records
class RecordSocket {
  RecordSocket.fromSocket(this.socket) {
    _input = SocketBinaryInput(socket!);
    _output = SocketBinaryOutput(socket!);
  }

  RecordSocket.fromTransport({
    required BinaryInput input,
    required BinaryOutput output,
  })  : socket = null,
        _input = input,
        _output = output;

  final Socket? socket;
  late final BinaryInput _input;
  late final BinaryOutput _output;

  TlsProtocolVersion version = const TlsProtocolVersion(0, 0);
  bool tls13record = false;
  int recvRecordLimit = 1 << 14;

  void close() {
    // SocketBinaryInput handles subscription internally, but we can't explicitly cancel it 
    // without exposing a cancel method on it. However, closing the socket usually suffices.
    // For now, we rely on the socket closure.
  }

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

    _output.writeBytes(headerBytes);
    _output.writeBytes(data);
    await _output.flush();
  }

  /// Read record from socket
  Future<(dynamic, Uint8List)> recv() async {
    try {
      // Read first byte
      await _input.ensureBytes(1);
      final firstByte = _input.readUint8();
      var buf = <int>[firstByte];
      
      bool ssl2 = false;
      if (ContentType.all.contains(firstByte)) {
        ssl2 = false;
        // SSLv3 record layer header is 5 bytes long, we already read 1
        await _input.ensureBytes(4);
        buf.addAll(_input.readBytes(4));
      } else {
        ssl2 = true;
        // if header has no padding the header is 2 bytes long, 3 otherwise
        // at the same time we already read 1 byte
        final readLen = (firstByte & 0x80) != 0 ? 1 : 2;
        await _input.ensureBytes(readLen);
        buf.addAll(_input.readBytes(readLen));
      }

      dynamic header;
      final headerBytes = Uint8List.fromList(buf);
      if (ssl2) {
        header = RecordHeader2().parse(Parser(headerBytes));
        if ((header.padding > header.length) || (header.padding != 0 && header.length % 8 != 0)) {
          throw TLSIllegalParameterException('Malformed record layer header');
        }
      } else {
        header = RecordHeader3().parse(Parser(headerBytes));
      }

      // Check the record header fields
      // 18432 = 2**14 (default record size limit) + 1024 (maximum compression
      // overhead) + 1024 (maximum encryption overhead)
      if (header.length > recvRecordLimit + 2048) {
        throw TLSRecordOverflow();
      }
      if (tls13record && header.length > recvRecordLimit + 256) {
        throw TLSRecordOverflow();
      }

      await _input.ensureBytes(header.length);
      final data = Uint8List.fromList(_input.readBytes(header.length));
      return (header, data);
    } on StateError catch (error) {
      throw TLSAbruptCloseError(error.message);
    } on SocketException catch (error) {
      throw TLSAbruptCloseError(error.message);
    }
  }
}

/// Preserve connection state for reading and writing data to records
class ConnectionState {
  ConnectionState();

  dynamic macContext; // TlsHmac?
  dynamic encContext; // Cipher object
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
    ret.macContext = macContext?.copy();
    ret.encContext = encContext; // Ciphers might be mutable? Python uses copy.copy().
    // In Dart, if encContext has state, we might need to copy it.
    // Most cipher implementations here seem to be stateful (e.g. CBC residue).
    // We need to check if we can copy them.
    // For now, shallow copy or reference.
    ret.fixedNonce = fixedNonce;
    ret.seqnum = seqnum;
    ret.encryptThenMAC = encryptThenMAC;
    return ret;
  }
}

/// Implementation of TLS record layer protocol
class RecordLayer {
  RecordLayer(this.sock) {
    _recordSocket = RecordSocket.fromSocket(sock!);
  }

  RecordLayer.custom(BinaryInput input, BinaryOutput output) : sock = null {
    _recordSocket = RecordSocket.fromTransport(input: input, output: output);
  }

  final Socket? sock;
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
  
  // TLS 1.3 properties
  bool _earlyDataOk = false;
  int maxEarlyData = 0;
  int _earlyDataProcessed = 0;
  
  dynamic padding_cb; // Function(int, int, int) -> List<int>

  int get recvRecordLimit => _recordSocket.recvRecordLimit;
  set recvRecordLimit(int value) => _recordSocket.recvRecordLimit = value;

  bool get earlyDataOk => _earlyDataOk;
  set earlyDataOk(bool val) {
    _earlyDataProcessed = 0;
    _earlyDataOk = val;
  }

  bool get encryptThenMAC => _writeState.encryptThenMAC;
  set encryptThenMAC(bool value) {
    _pendingWriteState.encryptThenMAC = value;
    _pendingReadState.encryptThenMAC = value;
  }
  
  // ignore: unused_element
  bool _getPendingStateEtm() {
    return _pendingWriteState.encryptThenMAC;
  }

  int get blockSize => _writeState.encContext?.blockSize ?? 0; // Assuming blockSize getter

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
  
  String? getCipherImplementation() => _writeState.encContext?.implementation;

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
    // assert version in ((3, 0), (3, 1), (3, 2), (3, 3))
    if (version != const TlsProtocolVersion(3, 0)) {
      mac.update(Uint8List.fromList([version.major, version.minor]));
    }
    final len = data.length;
    mac.update(Uint8List.fromList([len >> 8, len & 0xff]));
    mac.update(data);
    return Uint8List.fromList(mac.digest());
  }
  
  Uint8List _macThenEncrypt(Uint8List data, int contentType) {
    if (_writeState.macContext != null) {
      final seqnumBytes = _writeState.getSeqNumBytes();
      final mac = _writeState.macContext.copy();
      final macBytes = calculateMAC(mac, seqnumBytes, contentType, data);
      data = Uint8List.fromList([...data, ...macBytes]);
    }

    if (_writeState.encContext != null) {
      if (_writeState.encContext.isBlockCipher) {
        if (version >= const TlsProtocolVersion(3, 2)) {
          data = Uint8List.fromList([...fixedIVBlock!, ...data]);
        }
        data = addPadding(data);
      }
      data = _writeState.encContext.encrypt(data);
    }
    return data;
  }
  
  Uint8List _encryptThenMAC(Uint8List buf, int contentType) {
    if (_writeState.encContext != null) {
      if (version >= const TlsProtocolVersion(3, 2)) {
        buf = Uint8List.fromList([...fixedIVBlock!, ...buf]);
      }
      buf = addPadding(buf);
      buf = _writeState.encContext.encrypt(buf);
    }
    
    if (_writeState.macContext != null) {
      final seqnumBytes = _writeState.getSeqNumBytes();
      final mac = _writeState.macContext.copy();
      final macBytes = calculateMAC(mac, seqnumBytes, contentType, buf);
      buf = Uint8List.fromList([...buf, ...macBytes]);
    }
    return buf;
  }
  
  Uint8List _getNonce(ConnectionState state, Uint8List seqnum) {
    if ((state.encContext.name == "chacha20-poly1305" && state.fixedNonce!.length == 12) || _isTls13Plus()) {
      final pad = Uint8List(state.fixedNonce!.length - seqnum.length);
      final paddedSeq = Uint8List.fromList([...pad, ...seqnum]);
      final nonce = Uint8List(state.fixedNonce!.length);
      for (var i = 0; i < nonce.length; i++) {
        nonce[i] = paddedSeq[i] ^ state.fixedNonce![i];
      }
      return nonce;
    } else {
      return Uint8List.fromList([...state.fixedNonce!, ...seqnum]);
    }
  }
  
  Uint8List _encryptThenSeal(Uint8List buf, int contentType) {
    final seqNumBytes = _writeState.getSeqNumBytes();
    Uint8List authData;
    
    if (!_isTls13Plus()) {
      authData = Uint8List.fromList([
        ...seqNumBytes,
        contentType,
        version.major,
        version.minor,
        buf.length >> 8,
        buf.length & 0xff
      ]);
    } else {
      final outLen = buf.length + (_writeState.encContext.tagLength as int);
      authData = Uint8List.fromList([
        contentType,
        _recordSocket.version.major,
        _recordSocket.version.minor,
        outLen >> 8,
        outLen & 0xff
      ]);
    }
    
    final nonce = _getNonce(_writeState, seqNumBytes);
    
    // Assuming seal returns ciphertext + tag
    buf = _writeState.encContext.seal(nonce, buf, authData);
    
    if (_writeState.encContext.name.contains("aes") && !_isTls13Plus()) {
      buf = Uint8List.fromList([...seqNumBytes, ...buf]);
    }
    
    return buf;
  }
  
  (Uint8List, int) _ssl2Encrypt(Uint8List data) {
    final seqnumBytes = _writeState.getSeqNumBytes();
    int padding = 0;
    
    if (_writeState.encContext != null && _writeState.encContext.isBlockCipher) {
      final plaintextLen = data.length;
      data = addPadding(data);
      padding = data.length - plaintextLen;
    }
    
    if (_writeState.macContext != null) {
      final mac = _writeState.macContext.copy();
      mac.update(data); // compatHMAC(data)
      mac.update(seqnumBytes.sublist(seqnumBytes.length - 4)); // compatHMAC(seqnumBytes[-4:])
      final macBytes = mac.digest();
      data = Uint8List.fromList([...macBytes, ...data]);
    }
    
    if (_writeState.encContext != null) {
      data = _writeState.encContext.encrypt(data);
    }
    
    return (data, padding);
  }

  Future<void> sendRecord(Message msg) async {
    var data = msg.write();
    var contentType = msg.contentType;

    if (_isTls13Plus() && _writeState.encContext != null && contentType != ContentType.change_cipher_spec) {
      data = Uint8List.fromList([...data, contentType]);
      if (padding_cb != null) {
        final maxPadding = sendRecordLimit - data.length - 1;
        final padding = padding_cb(data.length, contentType, maxPadding) as List<int>;
        data = Uint8List.fromList([...data, ...padding]);
      }
      contentType = ContentType.application_data;
    }

    int padding = 0;
    if (version == const TlsProtocolVersion(0, 2) || version == const TlsProtocolVersion(2, 0)) {
      final res = _ssl2Encrypt(data);
      data = res.$1;
      padding = res.$2;
    } else if (version > const TlsProtocolVersion(3, 3) && contentType == ContentType.change_cipher_spec) {
      // TLS 1.3 does not encrypt CCS
    } else if (_writeState.encContext != null && (_writeState.encContext.isAEAD ?? false)) {
      data = _encryptThenSeal(data, contentType);
    } else if (_writeState.encryptThenMAC) {
      data = _encryptThenMAC(data, contentType);
    } else {
      data = _macThenEncrypt(data, contentType);
    }

    final encryptedMessage = Message(contentType, data);
    await _recordSocket.send(encryptedMessage, padding);
  }
  
  Uint8List _decryptStreamThenMAC(int recordType, Uint8List data) {
    if (_readState.encContext != null) {
      data = _readState.encContext.decrypt(data);
    }
    
    if (_readState.macContext != null) {
      bool macGood = true;
      final macLength = _readState.macContext.digestSize as int;
      if (data.length < macLength) {
        macGood = false;
      } else {
        final checkBytes = data.sublist(data.length - macLength);
        final seqnumBytes = _readState.getSeqNumBytes();
        final content = data.sublist(0, data.length - macLength);
        final mac = _readState.macContext.copy();
        final macBytes = calculateMAC(mac, seqnumBytes, recordType, content);
        
        if (!ctCompareDigest(macBytes, checkBytes)) {
          macGood = false;
        }
        data = content;
      }
      
      if (!macGood) {
        throw TLSBadRecordMAC();
      }
    }
    return data;
  }
  
  Uint8List _decryptThenMAC(int recordType, Uint8List data) {
    if (_readState.encContext != null) {
      // assert block cipher
      final blockLength = _readState.encContext.blockSize as int;
      if (data.length % blockLength != 0) {
        throw TLSDecryptionFailed();
      }
      data = _readState.encContext.decrypt(data);
      if (version >= const TlsProtocolVersion(3, 2)) {
        data = data.sublist(blockLength);
      }
      
      final seqnumBytes = _readState.getSeqNumBytes();
      
      if (!ctCheckCbcMacAndPad(data, _readState.macContext, seqnumBytes, recordType, [version.major, version.minor], blockSize: blockLength)) {
        throw TLSBadRecordMAC();
      }
      
      final endLength = data[data.length - 1] + 1 + (_readState.macContext.digestSize as int);
      data = data.sublist(0, data.length - endLength);
    }
    return data;
  }
  
  Uint8List _macThenDecrypt(int recordType, Uint8List buf) {
    if (_readState.macContext != null) {
      final macLength = _readState.macContext.digestSize as int;
      if (buf.length < macLength) {
        throw TLSBadRecordMAC("Truncated data");
      }
      
      final checkBytes = buf.sublist(buf.length - macLength);
      buf = buf.sublist(0, buf.length - macLength);
      
      final seqnumBytes = _readState.getSeqNumBytes();
      final mac = _readState.macContext.copy();
      final macBytes = calculateMAC(mac, seqnumBytes, recordType, buf);
      
      if (!ctCompareDigest(macBytes, checkBytes)) {
        throw TLSBadRecordMAC("MAC mismatch");
      }
    }
    
    if (_readState.encContext != null) {
      final blockLength = _readState.encContext.blockSize as int;
      if (buf.length % blockLength != 0) {
        throw TLSDecryptionFailed("data length not multiple of block size");
      }
      
      buf = _readState.encContext.decrypt(buf);
      
      if (version >= const TlsProtocolVersion(3, 2)) {
        buf = buf.sublist(blockLength);
      }
      
      if (buf.isEmpty) {
        throw TLSBadRecordMAC("No data left after IV removal");
      }
      
      final paddingLength = buf[buf.length - 1];
      if (paddingLength + 1 > buf.length) {
        throw TLSBadRecordMAC("Invalid padding length");
      }
      
      bool paddingGood = true;
      final totalPaddingLength = paddingLength + 1;
      if (version != const TlsProtocolVersion(3, 0)) {
        for (var i = buf.length - totalPaddingLength; i < buf.length - 1; i++) {
          if (buf[i] != paddingLength) {
            paddingGood = false;
          }
        }
      }
      
      if (!paddingGood) {
        throw TLSBadRecordMAC("Invalid padding byte values");
      }
      
      buf = buf.sublist(0, buf.length - totalPaddingLength);
    }
    return buf;
  }
  
  Uint8List _decryptAndUnseal(dynamic header, Uint8List buf) {
    final seqnumBytes = _readState.getSeqNumBytes();
    Uint8List nonce;
    
    if (_readState.encContext.name.contains("aes") && !_isTls13Plus()) {
      final explicitNonceLength = 8;
      if (explicitNonceLength > buf.length) {
        throw TLSBadRecordMAC("Truncated nonce");
      }
      nonce = Uint8List.fromList([..._readState.fixedNonce!, ...buf.sublist(0, explicitNonceLength)]);
      buf = buf.sublist(8);
    } else {
      nonce = _getNonce(_readState, seqnumBytes);
    }
    
    if ((_readState.encContext.tagLength as int) > buf.length) {
      throw TLSBadRecordMAC("Truncated tag");
    }
    
    Uint8List authData;
    if (!_isTls13Plus()) {
      final plaintextLen = buf.length - (_readState.encContext.tagLength as int);
      authData = Uint8List.fromList([
        ...seqnumBytes,
        header.type,
        version.major,
        version.minor,
        plaintextLen >> 8,
        plaintextLen & 0xff
      ]);
    } else {
      if (header.type != ContentType.application_data) {
        throw TLSUnexpectedMessage("Invalid ContentType for encrypted record");
      }
      if (header.version != const TlsProtocolVersion(3, 3)) {
        throw TLSIllegalParameterException("Unexpected version in encrypted record");
      }
      if (header.length != buf.length) {
        throw TLSBadRecordMAC("Length mismatch");
      }
      authData = header.write();
    }
    
    final result = _readState.encContext.open(nonce, buf, authData);
    if (result == null) {
      throw TLSBadRecordMAC("Invalid tag, decryption failure");
    }
    return result;
  }
  
  Uint8List _decryptSSL2(Uint8List data, int padding) {
    final seqnumBytes = _readState.getSeqNumBytes();
    
    if (_readState.encContext != null) {
      if (_readState.encContext.isBlockCipher) {
        final blockLength = _readState.encContext.blockSize as int;
        if (data.length % blockLength != 0) {
          throw TLSDecryptionFailed();
        }
      }
      data = _readState.encContext.decrypt(data);
    }
    
    if (_readState.macContext != null) {
      final macBytes = data.sublist(0, 16);
      data = data.sublist(16);
      
      final mac = _readState.macContext.copy();
      mac.update(data);
      mac.update(seqnumBytes.sublist(seqnumBytes.length - 4));
      final calcMac = mac.digest();
      
      if (!ctCompareDigest(macBytes, calcMac)) {
        throw TLSBadRecordMAC();
      }
    }
    
    if (padding > 0) {
      data = data.sublist(0, data.length - padding);
    }
    return data;
  }
  
  static (Uint8List, int) _tls13DePad(Uint8List data) {
    for (var i = data.length - 1; i >= 0; i--) {
      if (data[i] != 0) {
        return (data.sublist(0, i), data[i]);
      }
    }
    throw TLSUnexpectedMessage("Malformed record layer inner plaintext - content type missing");
  }

  Future<(dynamic, Parser)> recvRecord() async {
    while (true) {
      final (header, data) = await _recordSocket.recv();
      var decryptedData = data;
      
      ConnectionState? readStateCopy;
      if (earlyDataOk) {
        readStateCopy = _readState.copy();
      }
      
      try {
        if (header is RecordHeader2) {
          decryptedData = _decryptSSL2(decryptedData, header.padding);
          if (handshakeFinished) {
            header.type = ContentType.application_data;
          }
        } else if (_isTls13Plus() && header.type == ContentType.change_cipher_spec) {
          // Pass
        } else if (_isTls13Plus() && header.type == ContentType.alert && decryptedData.length < 3 && _readState.encContext != null && _readState.seqnum == 0) {
          // Pass
        } else if (_readState.encContext != null && (_readState.encContext.isAEAD ?? false)) {
          decryptedData = _decryptAndUnseal(header, decryptedData);
        } else if (_readState.encryptThenMAC) {
          decryptedData = _macThenDecrypt(header.type, decryptedData);
        } else if (_readState.encContext != null && _readState.encContext.isBlockCipher) {
          decryptedData = _decryptThenMAC(header.type, decryptedData);
        } else {
          decryptedData = _decryptStreamThenMAC(header.type, decryptedData);
        }
        
        if (_readState.encContext == null && _readState.macContext == null && earlyDataOk && header.type == ContentType.application_data) {
          throw TLSBadRecordMAC("early data received");
        }
      } catch (e) {
        if (e is TLSBadRecordMAC && earlyDataOk && (_earlyDataProcessed + decryptedData.length < maxEarlyData)) {
          _earlyDataProcessed += decryptedData.length;
          _readState = readStateCopy!;
          continue;
        }
        rethrow;
      }
      
      earlyDataOk = false;
      
      if (_isTls13Plus() && _readState.encContext != null && header.type == ContentType.application_data) {
        if (decryptedData.length > recvRecordLimit + 1) {
          throw TLSRecordOverflow();
        }
        final res = _tls13DePad(decryptedData);
        decryptedData = res.$1;
        final contentType = res.$2;
        // Recreate header
        // header = RecordHeader3().create(const TlsProtocolVersion(3, 4), contentType, decryptedData.length);
        // But header is dynamic, so we can just modify it or return a new one.
        // The caller expects (header, Parser).
        // We should probably update the header object.
        if (header is RecordHeader3) {
           header.type = contentType;
           header.length = decryptedData.length;
        }
      }
      
      if (decryptedData.length > recvRecordLimit) {
        throw TLSRecordOverflow();
      }

      return (header, Parser(decryptedData));
    }
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
    } else if (CipherSuite.chacha20Suites.contains(cipherSuite)) {
      return (32, 12, createCHACHA20);
    } else if (CipherSuite.chacha20draft00Suites.contains(cipherSuite)) {
      return (32, 4, createCHACHA20);
    } else if (CipherSuite.aes128CcmSuites.contains(cipherSuite)) {
      return (16, 4, createAESCCM);
    } else if (CipherSuite.aes256CcmSuites.contains(cipherSuite)) {
      return (32, 4, createAESCCM);
    } else if (CipherSuite.aes128Ccm_8Suites.contains(cipherSuite)) {
      return (16, 4, createAESCCM8);
    } else if (CipherSuite.aes256Ccm_8Suites.contains(cipherSuite)) {
      return (32, 4, createAESCCM8); // Assuming createAESCCM8 handles 256 bit keys
    }
    
    // Fallback or error
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
    } else if (CipherSuite.sha384Suites.contains(cipherSuite)) {
      return (48, 'sha384');
    }
    throw AssertionError('Unknown cipher suite for MAC: $cipherSuite');
  }
  
  static Function _getHMACMethod(TlsProtocolVersion version) {
    if (version == const TlsProtocolVersion(3, 0)) {
      return createMAC_SSL;
    } else {
      return createHMAC;
    }
  }

  void calcPendingStates(int cipherSuite, Uint8List masterSecret, Uint8List clientRandom,
      Uint8List serverRandom, List<String>? implementations) {
    final (keyLength, ivLength, createCipherFunc) = _getCipherSettings(cipherSuite);
    final (macLength, digestmod) = _getMacSettings(cipherSuite);
    
    Function? createMACFunc;
    if (digestmod != null) {
      createMACFunc = _getHMACMethod(version);
    }

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
      clientPendingState.macContext = createMACFunc!(clientMACBlock, digestmod);
      serverPendingState.macContext = createMACFunc(serverMACBlock, digestmod);
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
  
  void calcTLS1_3PendingState(int cipherSuite, Uint8List clTrafficSecret, Uint8List srTrafficSecret, List<String>? implementations) {
    final prfName = CipherSuite.sha384PrfSuites.contains(cipherSuite) ? 'sha384' : 'sha256';
    final (keyLength, ivLength, createCipherFunc) = _getCipherSettings(cipherSuite);
    // ivLength is 12 for TLS 1.3
    
    final clientPendingState = ConnectionState();
    final serverPendingState = ConnectionState();
    
    clientPendingState.macContext = null;
    clientPendingState.encContext = createCipherFunc!(
      HKDF_expand_label(clTrafficSecret, Uint8List.fromList('key'.codeUnits), Uint8List(0), keyLength, prfName),
      implementations: implementations
    );
    clientPendingState.fixedNonce = HKDF_expand_label(clTrafficSecret, Uint8List.fromList('iv'.codeUnits), Uint8List(0), 12, prfName);
    
    serverPendingState.macContext = null;
    serverPendingState.encContext = createCipherFunc(
      HKDF_expand_label(srTrafficSecret, Uint8List.fromList('key'.codeUnits), Uint8List(0), keyLength, prfName),
      implementations: implementations
    );
    serverPendingState.fixedNonce = HKDF_expand_label(srTrafficSecret, Uint8List.fromList('iv'.codeUnits), Uint8List(0), 12, prfName);
    
    if (client) {
      _pendingWriteState = clientPendingState;
      _pendingReadState = serverPendingState;
    } else {
      _pendingWriteState = serverPendingState;
      _pendingReadState = clientPendingState;
    }
  }
  
  (Uint8List, ConnectionState) _calcTLS1_3KeyUpdate(int cipherSuite, Uint8List appSecret) {
    final (prfName, prfLength) = CipherSuite.sha384PrfSuites.contains(cipherSuite) ? ('sha384', 48) : ('sha256', 32);
    final (keyLength, ivLength, createCipherFunc) = _getCipherSettings(cipherSuite);
    
    final newAppSecret = HKDF_expand_label(appSecret, Uint8List.fromList('traffic upd'.codeUnits), Uint8List(0), prfLength, prfName);
    final newState = ConnectionState();
    newState.macContext = null;
    newState.encContext = createCipherFunc!(
      HKDF_expand_label(newAppSecret, Uint8List.fromList('key'.codeUnits), Uint8List(0), keyLength, prfName),
      implementations: null
    );
    newState.fixedNonce = HKDF_expand_label(newAppSecret, Uint8List.fromList('iv'.codeUnits), Uint8List(0), 12, prfName);
    
    return (newAppSecret, newState);
  }
  
  (Uint8List, Uint8List) calcTLS1_3KeyUpdateSender(int cipherSuite, Uint8List clAppSecret, Uint8List srAppSecret) {
    if (client) {
      final res = _calcTLS1_3KeyUpdate(cipherSuite, clAppSecret);
      _writeState = res.$2;
      return (res.$1, srAppSecret);
    } else {
      final res = _calcTLS1_3KeyUpdate(cipherSuite, srAppSecret);
      _writeState = res.$2;
      return (clAppSecret, res.$1);
    }
  }
  
  (Uint8List, Uint8List) calcTLS1_3KeyUpdateReceiver(int cipherSuite, Uint8List clAppSecret, Uint8List srAppSecret) {
    if (client) {
      final res = _calcTLS1_3KeyUpdate(cipherSuite, srAppSecret);
      _readState = res.$2;
      return (clAppSecret, res.$1);
    } else {
      final res = _calcTLS1_3KeyUpdate(cipherSuite, clAppSecret);
      _readState = res.$2;
      return (res.$1, srAppSecret);
    }
  }
}

class RecordHeader2 {
  int length = 0;
  int padding = 0;
  int type = ContentType.handshake;
  TlsProtocolVersion version = const TlsProtocolVersion(2, 0);

  RecordHeader2 create(int length, int padding) {
    this.length = length;
    this.padding = padding;
    type = ContentType.handshake;
    version = const TlsProtocolVersion(2, 0);
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
    type = ContentType.handshake;
    version = const TlsProtocolVersion(2, 0);
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
