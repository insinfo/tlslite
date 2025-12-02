

/// Helper class for handling fragmentation of messages.

import 'dart:typed_data';
import 'utils/codec.dart' show Parser;

/// Class for demultiplexing TLS messages.
///
/// Since messages can be interleaved and fragmented between each other
/// we need to cache incomplete ones and return in order of urgency.
///
/// Supports messages with given size (like Alerts) or with a length header
/// in specific place (like Handshake messages).
class Defragmenter {
  /// Order in which messages from given types should be returned.
  final List<int> priorities = [];

  /// Data buffers for message types.
  final Map<int, ByteData> buffers = {};

  /// Functions which check buffers if a message of given type is complete.
  final Map<int, int? Function(Uint8List)> decoders = {};

  /// Set up empty defragmenter.
  Defragmenter();

  /// Add a message type which all messages are of same length.
  ///
  /// [msgType] - the type of message to register
  /// [size] - the fixed size of messages of this type
  void addStaticSize(int msgType, int size) {
    if (priorities.contains(msgType)) {
      throw ArgumentError('Message type already defined');
    }
    if (size < 1) {
      throw ArgumentError('Message size must be positive integer');
    }

    priorities.add(msgType);
    buffers[msgType] = ByteData(0);

    int? sizeHandler(Uint8List data) {
      /// Size of message in parameter
      ///
      /// If complete message is present in parameter returns its size,
      /// null otherwise.
      if (data.length < size) {
        return null;
      } else {
        return size;
      }
    }

    decoders[msgType] = sizeHandler;
  }

  /// Add a message type which has a dynamic size set in a header.
  ///
  /// [msgType] - the type of message to register
  /// [sizeOffset] - offset in bytes from start of message where size is located
  /// [sizeOfSize] - number of bytes used to encode the size
  void addDynamicSize(int msgType, int sizeOffset, int sizeOfSize) {
    if (priorities.contains(msgType)) {
      throw ArgumentError('Message type already defined');
    }
    if (sizeOfSize < 1) {
      throw ArgumentError('Size of size must be positive integer');
    }
    if (sizeOffset < 0) {
      throw ArgumentError("Offset can't be negative");
    }

    priorities.add(msgType);
    buffers[msgType] = ByteData(0);

    int? sizeHandler(Uint8List data) {
      /// Size of message in parameter
      ///
      /// If complete message is present in parameter returns its size,
      /// null otherwise.
      if (data.length < sizeOffset + sizeOfSize) {
        return null;
      } else {
        final parser = Parser(data);
        // skip the header
        parser.skipBytes(sizeOffset);

        final payloadLength = parser.get(sizeOfSize);
        if (parser.getRemainingLength() < payloadLength) {
          // not enough bytes in buffer
          return null;
        }
        return sizeOffset + sizeOfSize + payloadLength;
      }
    }

    decoders[msgType] = sizeHandler;
  }

  /// Adds data to buffers.
  ///
  /// [msgType] - the type of message this data belongs to
  /// [data] - the data to add to the buffer
  void addData(int msgType, Uint8List data) {
    if (!priorities.contains(msgType)) {
      throw ArgumentError('Message type not defined');
    }

    final currentBuf = buffers[msgType]!;
    final newBuf = ByteData(currentBuf.lengthInBytes + data.length);
    
    // Copy existing data
    for (var i = 0; i < currentBuf.lengthInBytes; i++) {
      newBuf.setUint8(i, currentBuf.getUint8(i));
    }
    
    // Append new data
    for (var i = 0; i < data.length; i++) {
      newBuf.setUint8(currentBuf.lengthInBytes + i, data[i]);
    }
    
    buffers[msgType] = newBuf;
  }

  /// Extract the highest priority complete message from buffer.
  ///
  /// Returns a tuple of (msgType, data) if a complete message is available,
  /// or null if no complete message is ready.
  (int, Uint8List)? getMessage() {
    for (final msgType in priorities) {
      final buf = buffers[msgType]!;
      final bufBytes = Uint8List.view(buf.buffer);
      final length = decoders[msgType]!(bufBytes);
      
      if (length == null) {
        continue;
      }

      // Extract message
      final data = Uint8List.fromList(bufBytes.sublist(0, length));
      
      // Remove it from buffer
      final remaining = bufBytes.sublist(length);
      final newBuf = ByteData(remaining.length);
      for (var i = 0; i < remaining.length; i++) {
        newBuf.setUint8(i, remaining[i]);
      }
      buffers[msgType] = newBuf;
      
      return (msgType, data);
    }
    return null;
  }

  /// Remove all data from buffers.
  void clearBuffers() {
    for (final key in buffers.keys) {
      buffers[key] = ByteData(0);
    }
  }

  /// Return true if all buffers are empty.
  bool isEmpty() {
    return buffers.values.every((buf) => buf.lengthInBytes == 0);
  }

  /// Returns true if there is buffered data for [msgType].
  bool hasPending(int msgType) {
    final buffer = buffers[msgType];
    if (buffer == null) {
      return false;
    }
    return buffer.lengthInBytes > 0;
  }
}
