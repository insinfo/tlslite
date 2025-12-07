
/// Wrapper of TLS RecordLayer providing message-level abstraction

import 'dart:typed_data';
import 'package:logging/logging.dart';

import 'recordlayer.dart';
import 'constants.dart';
import 'defragmenter.dart';
import 'utils/codec.dart';
import 'tls_protocol.dart';

import 'utils/binary_io.dart';

/// TLS Record Layer socket that provides Message level abstraction
///
/// Because the record layer has a hard size limit on sent messages, they need
/// to be fragmented before sending. Similarly, a single record layer record
/// can include multiple handshake protocol messages (very common with
/// ServerHello, Certificate and ServerHelloDone), as such, the user of
/// RecordLayer needs to fragment those records into multiple messages.
/// 
/// This class provides abstraction for handling Handshake protocol messages.
class MessageSocket extends RecordLayer {
  MessageSocket(super.sock, this.defragmenter, {Logger? logger})
      : super(logger: logger);

  MessageSocket.custom(
    BinaryInput input,
    BinaryOutput output,
    this.defragmenter, {
    Logger? logger,
  }) : super.custom(input, output, logger: logger);

  /// Defragmenter used for read records
  final Defragmenter defragmenter;

  /// Data types which will be passed as-read
  final unfragmentedDataTypes = [
    ContentType.application_data,
    ContentType.heartbeat,
    ContentType.change_cipher_spec,
    ContentType.alert,
  ];

  var _lastRecordVersion = const TlsProtocolVersion(0, 0);
  final _sendBuffer = <int>[];
  int? _sendBufferType;

  /// Maximum size of records sent through socket
  int recordSize = 1 << 14; // 2^14

  /// Read next message in queue
  Future<(dynamic, Parser)> recvMessage() async {
    while (true) {
      // Check defragmenter for complete messages
      while (true) {
        final ret = defragmenter.getMessage();
        if (ret == null) break;

        final header = RecordHeader3().create(
          _lastRecordVersion,
          ret.$1,
          0,
        );
        return (header, Parser(ret.$2));
      }

      // Read record from network
      final (header, parser) = await recvRecord();

      // Pass through unfragmented data types
      if (unfragmentedDataTypes.contains(header.type)) {
        return (header, parser);
      }

      // SSLv2 records are already message-aligned, so bypass the defragmenter.
      if (header is RecordHeader2) {
        return (header, parser);
      }

      // Add to defragmenter
      final remainingBytes = parser.getFixBytes(parser.getRemainingLength());
      defragmenter.addData(header.type, remainingBytes);
      _lastRecordVersion = header.version;
    }
  }

  /// Empty the queue of messages to write
  Future<void> flush() async {
    while (_sendBuffer.isNotEmpty) {
      final recordPayload = Uint8List.fromList(
        _sendBuffer.take(recordSize).toList(),
      );
      _sendBuffer.removeRange(0, recordPayload.length);

      final msg = Message(_sendBufferType!, recordPayload);
      await sendRecord(msg);
    }

    assert(_sendBuffer.isEmpty);
    _sendBufferType = null;
  }

  /// Queue message for sending
  Future<void> queueMessage(Message msg) async {
    if (_sendBufferType == null) {
      _sendBufferType = msg.contentType;
    }

    if (msg.contentType == _sendBufferType) {
      _sendBuffer.addAll(msg.write());
      return;
    }

    await flush();

    assert(_sendBufferType == null);
    _sendBufferType = msg.contentType;
    _sendBuffer.addAll(msg.write());
  }

  /// Fragment and send a message
  Future<void> sendMessage(Message msg) async {
    await queueMessage(msg);
    await flush();
  }

  /// Blocking variants kept for API parity with generators.
  Future<(dynamic, Parser)> recvMessageBlocking() {
    return recvMessage();
  }

  Future<void> flushBlocking() {
    return flush();
  }

  Future<void> queueMessageBlocking(Message msg) {
    return queueMessage(msg);
  }

  Future<void> sendMessageBlocking(Message msg) {
    return sendMessage(msg);
  }
}
