import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:tlslite/src/defragmenter.dart';

void main() {
  group('Defragmenter', () {
    test('addStaticSize registers message type correctly', () {
      final defrag = Defragmenter();
      defrag.addStaticSize(1, 10);
      
      expect(defrag.priorities, contains(1));
      expect(defrag.buffers.containsKey(1), isTrue);
      expect(defrag.decoders.containsKey(1), isTrue);
    });

    test('addStaticSize throws on duplicate message type', () {
      final defrag = Defragmenter();
      defrag.addStaticSize(1, 10);
      
      expect(() => defrag.addStaticSize(1, 20), throwsArgumentError);
    });

    test('addStaticSize throws on invalid size', () {
      final defrag = Defragmenter();
      
      expect(() => defrag.addStaticSize(1, 0), throwsArgumentError);
      expect(() => defrag.addStaticSize(1, -1), throwsArgumentError);
    });

    test('addDynamicSize registers message type correctly', () {
      final defrag = Defragmenter();
      defrag.addDynamicSize(2, 1, 2); // size at offset 1, 2 bytes long
      
      expect(defrag.priorities, contains(2));
      expect(defrag.buffers.containsKey(2), isTrue);
      expect(defrag.decoders.containsKey(2), isTrue);
    });

    test('addDynamicSize throws on invalid parameters', () {
      final defrag = Defragmenter();
      
      expect(() => defrag.addDynamicSize(1, 0, 0), throwsArgumentError);
      expect(() => defrag.addDynamicSize(1, -1, 1), throwsArgumentError);
    });

    test('addData adds data to buffer', () {
      final defrag = Defragmenter();
      defrag.addStaticSize(1, 5);
      
      final data = Uint8List.fromList([1, 2, 3]);
      defrag.addData(1, data);
      
      final buf = defrag.buffers[1]!;
      expect(buf.lengthInBytes, equals(3));
    });

    test('addData throws on unregistered message type', () {
      final defrag = Defragmenter();
      final data = Uint8List.fromList([1, 2, 3]);
      
      expect(() => defrag.addData(99, data), throwsArgumentError);
    });

    test('getMessage returns null when no complete message', () {
      final defrag = Defragmenter();
      defrag.addStaticSize(1, 10);
      defrag.addData(1, Uint8List.fromList([1, 2, 3])); // only 3 bytes, need 10
      
      expect(defrag.getMessage(), isNull);
    });

    test('getMessage returns complete message with static size', () {
      final defrag = Defragmenter();
      defrag.addStaticSize(1, 5);
      defrag.addData(1, Uint8List.fromList([1, 2, 3, 4, 5]));
      
      final result = defrag.getMessage();
      expect(result, isNotNull);
      expect(result!.$1, equals(1)); // message type
      expect(result.$2, equals([1, 2, 3, 4, 5])); // data
    });

    test('getMessage removes extracted message from buffer', () {
      final defrag = Defragmenter();
      defrag.addStaticSize(1, 3);
      defrag.addData(1, Uint8List.fromList([1, 2, 3, 4, 5]));
      
      final result1 = defrag.getMessage();
      expect(result1!.$2, equals([1, 2, 3]));
      
      // Buffer should still have [4, 5]
      final buf = defrag.buffers[1]!;
      expect(buf.lengthInBytes, equals(2));
    });

    test('getMessage with dynamic size', () {
      final defrag = Defragmenter();
      // Message format: [type][length_hi][length_lo][payload...]
      defrag.addDynamicSize(2, 1, 2); // size at offset 1, 2 bytes
      
      // Create message: type=0x16, length=0x0003, payload=[0xAA, 0xBB, 0xCC]
      final data = Uint8List.fromList([0x16, 0x00, 0x03, 0xAA, 0xBB, 0xCC]);
      defrag.addData(2, data);
      
      final result = defrag.getMessage();
      expect(result, isNotNull);
      expect(result!.$1, equals(2));
      expect(result.$2.length, equals(6)); // header + payload
    });

    test('getMessage returns null when dynamic size message incomplete', () {
      final defrag = Defragmenter();
      defrag.addDynamicSize(2, 1, 2);
      
      // Message with length=5 but only 3 bytes of payload
      final data = Uint8List.fromList([0x16, 0x00, 0x05, 0xAA, 0xBB, 0xCC]);
      defrag.addData(2, data);
      
      expect(defrag.getMessage(), isNull);
    });

    test('getMessage respects priority order', () {
      final defrag = Defragmenter();
      defrag.addStaticSize(1, 3);
      defrag.addStaticSize(2, 3);
      
      // Add complete messages to both types
      defrag.addData(2, Uint8List.fromList([7, 8, 9]));
      defrag.addData(1, Uint8List.fromList([1, 2, 3]));
      
      // Should return type 1 first (added first to priorities)
      final result1 = defrag.getMessage();
      expect(result1!.$1, equals(1));
      
      final result2 = defrag.getMessage();
      expect(result2!.$1, equals(2));
    });

    test('clearBuffers empties all buffers', () {
      final defrag = Defragmenter();
      defrag.addStaticSize(1, 5);
      defrag.addStaticSize(2, 5);
      
      defrag.addData(1, Uint8List.fromList([1, 2, 3]));
      defrag.addData(2, Uint8List.fromList([4, 5, 6]));
      
      defrag.clearBuffers();
      
      expect(defrag.buffers[1]!.lengthInBytes, equals(0));
      expect(defrag.buffers[2]!.lengthInBytes, equals(0));
    });

    test('isEmpty returns true when all buffers empty', () {
      final defrag = Defragmenter();
      defrag.addStaticSize(1, 5);
      
      expect(defrag.isEmpty(), isTrue);
      
      defrag.addData(1, Uint8List.fromList([1, 2, 3]));
      expect(defrag.isEmpty(), isFalse);
      
      defrag.clearBuffers();
      expect(defrag.isEmpty(), isTrue);
    });

    test('multiple messages can be extracted in sequence', () {
      final defrag = Defragmenter();
      defrag.addStaticSize(1, 3);
      
      // Add 9 bytes = 3 complete messages
      defrag.addData(1, Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9]));
      
      final msg1 = defrag.getMessage();
      expect(msg1!.$2, equals([1, 2, 3]));
      
      final msg2 = defrag.getMessage();
      expect(msg2!.$2, equals([4, 5, 6]));
      
      final msg3 = defrag.getMessage();
      expect(msg3!.$2, equals([7, 8, 9]));
      
      expect(defrag.getMessage(), isNull);
      expect(defrag.isEmpty(), isTrue);
    });

    test('fragmented messages are reassembled', () {
      final defrag = Defragmenter();
      defrag.addStaticSize(1, 10);
      
      // Add data in fragments
      defrag.addData(1, Uint8List.fromList([1, 2, 3]));
      expect(defrag.getMessage(), isNull); // incomplete
      
      defrag.addData(1, Uint8List.fromList([4, 5, 6]));
      expect(defrag.getMessage(), isNull); // still incomplete
      
      defrag.addData(1, Uint8List.fromList([7, 8, 9, 10]));
      final result = defrag.getMessage();
      expect(result, isNotNull);
      expect(result!.$2, equals([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));
    });
  });
}
