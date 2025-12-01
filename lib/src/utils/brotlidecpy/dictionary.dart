/* Copyright 2015 Google Inc. All Rights Reserved.

   Distributed under MIT license.
   See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
*/

import 'dart:typed_data';
import 'brotli_error.dart';
import 'utils.dart';
import 'dictionary_data_constants.dart';

/// Collection of static dictionary words.
///
/// Dictionary content is loaded from binary resource when [getData] is executed for the
/// first time. Consequently, it saves memory and CPU in case dictionary is not required.
class Dictionary {
  static const int MIN_DICTIONARY_WORD_LENGTH = 4;
  static const int MAX_DICTIONARY_WORD_LENGTH = 31;

  static Uint8List _data = Uint8List(0);
  static final Int32List offsets = Int32List(32);
  static final Int32List sizeBits = Int32List(32);

  static final int _DICTIONARY_DEBUG = Utils.isDebugMode();

  /// Initialize static dictionary.
  static void setData(Uint8List newData, List<int> newSizeBits) {
    if (_DICTIONARY_DEBUG != 0) {
      if (newSizeBits.length > MAX_DICTIONARY_WORD_LENGTH) {
        throw BrotliRuntimeException(
            "sizeBits length must be at most $MAX_DICTIONARY_WORD_LENGTH");
      }
      for (int i = 0; i < MIN_DICTIONARY_WORD_LENGTH; ++i) {
        if (newSizeBits[i] != 0) {
          throw BrotliRuntimeException(
              "first $MIN_DICTIONARY_WORD_LENGTH must be 0");
        }
      }
    }
    final Int32List dictionaryOffsets = offsets;
    final Int32List dictionarySizeBits = sizeBits;
    for (int i = 0; i < newSizeBits.length; ++i) {
      dictionarySizeBits[i] = newSizeBits[i];
    }
    int pos = 0;
    for (int i = 0; i < newSizeBits.length; ++i) {
      dictionaryOffsets[i] = pos;
      final int bits = dictionarySizeBits[i];
      if (bits != 0) {
        pos += i << (bits & 31);
        if (_DICTIONARY_DEBUG != 0) {
          if (bits >= 31) {
            throw BrotliRuntimeException("newSizeBits values must be less than 31");
          }
          if (pos <= 0 || pos > newData.length) {
            throw BrotliRuntimeException("newSizeBits is inconsistent: overflow");
          }
        }
      }
    }
    for (int i = newSizeBits.length; i < 32; ++i) {
      dictionaryOffsets[i] = pos;
    }
    if (_DICTIONARY_DEBUG != 0) {
      if (pos != newData.length) {
        throw BrotliRuntimeException("newSizeBits is inconsistent: underflow");
      }
    }
    _data = newData;
  }

  /// Access static dictionary.
  static Uint8List getData() {
    if (_data.isNotEmpty) {
      return _data;
    }

    // DataLoader logic
    final List<int> bytes = [];
    bytes.addAll(kDictionaryData0.codeUnits);
    bytes.addAll(kDictionaryData1.codeUnits);
    
    Uint8List dict = Uint8List.fromList(bytes);

    List<int> skipFlipRunes = kSkipFlip.codeUnits;

    int offset = 0;
    final int n = skipFlipRunes.length >> 1;
    for (int i = 0; i < n; ++i) {
      final int skip = skipFlipRunes[2 * i] - 36;
      final int flip = skipFlipRunes[2 * i + 1] - 36;
      for (int j = 0; j < skip; ++j) {
        dict[offset] = (dict[offset] ^ 3);
        offset++;
      }
      for (int j = 0; j < flip; ++j) {
        dict[offset] = (dict[offset] ^ 236);
        offset++;
      }
    }

    List<int> sizeBitsData = kSizeBitsData.codeUnits;
    List<int> dictionarySizeBits = List.filled(sizeBitsData.length, 0);
    for (int i = 0; i < sizeBitsData.length; ++i) {
      dictionarySizeBits[i] = sizeBitsData[i] - 65;
    }
    
    setData(dict, dictionarySizeBits);
    
    if (_data.isEmpty) {
      throw BrotliRuntimeException("brotli dictionary is not set");
    }
    return _data;
  }
}
