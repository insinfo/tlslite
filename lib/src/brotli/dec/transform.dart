import 'dart:typed_data';
import 'utils.dart';

final class Transforms {
  final int numTransforms;
  final Int32List triplets;
  final Uint8List prefixSuffixStorage;
  final Int32List prefixSuffixHeads;
  final Int16List params;

  Transforms(this.numTransforms, int prefixSuffixLen, int prefixSuffixCount)
      : triplets = Int32List(numTransforms * 3),
        params = Int16List(numTransforms),
        prefixSuffixStorage = Uint8List(prefixSuffixLen),
        prefixSuffixHeads = Int32List(prefixSuffixCount + 1);
}

final class Transform {
  static const int numRfcTransforms = 121;
  static final Transforms rfcTransforms = Transforms(numRfcTransforms, 167, 50);

  static const int omitFirstLastLimit = 9;

  static const int identity = 0;
  static const int omitLastBase = identity + 1 - 1;
  static const int uppercaseFirst = omitLastBase + omitFirstLastLimit + 1;
  static const int uppercaseAll = uppercaseFirst + 1;
  static const int omitFirstBase = uppercaseAll + 1 - 1;
  static const int shiftFirst = omitFirstBase + omitFirstLastLimit + 1;
  static const int shiftAll = shiftFirst + 1;

  static const String prefixSuffixSrc = "# #s #, #e #.# the #.com/#\u00C2\u00A0# of # and" +
      " # in # to #\"#\">#\n#]# for # a # that #. # with #'# from # by #. The # on # as # is #ing" +
      " #\n\t#:#ed #(# at #ly #=\"# of the #. This #,# not #er #al #='#ful #ive #less #est #ize #" +
      "ous #";
  static const String transformsSrc = "     !! ! ,  *!  &!  \" !  ) *   * -  ! # !  #!*!  " +
      "+  ,\$ !  -  %  .  / #   0  1 .  \"   2  3!*   4%  ! # /   5  6  7  8 0  1 &   \$   9 +   : " +
      " ;  < '  !=  >  ?! 4  @ 4  2  &   A *# (   B  C& ) %  ) !*# *-% A +! *.  D! %'  & E *6  F " +
      " G% ! *A *%  H! D  I!+!  J!+   K +- *4! A  L!*4  M  N +6  O!*% +.! K *G  P +%(  ! G *D +D " +
      " Q +# *K!*G!+D!+# +G +A +4!+% +K!+4!*D!+K!*K";

  static void unpackTransforms(Uint8List prefixSuffix,
      Int32List prefixSuffixHeads, Int32List transforms, String prefixSuffixSrc, String transformsSrc) {
    final Int32List prefixSuffixBytes = Utils.toUtf8Runes(prefixSuffixSrc);
    final int n = prefixSuffixBytes.length;
    int index = 1;
    int j = 0;
    for (int i = 0; i < n; ++i) {
      final int c = prefixSuffixBytes[i];
      if (c == 35) { // == #
        prefixSuffixHeads[index++] = j;
      } else {
        prefixSuffix[j++] = c;
      }
    }

    for (int i = 0; i < numRfcTransforms * 3; ++i) {
      transforms[i] = transformsSrc.codeUnitAt(i) - 32;
    }
  }

  static final bool _init = () {
    unpackTransforms(rfcTransforms.prefixSuffixStorage, rfcTransforms.prefixSuffixHeads,
        rfcTransforms.triplets, prefixSuffixSrc, transformsSrc);
    return true;
  }();

  static void _ensureInitialized() {
    if (!_init) {
      throw StateError('Failed to initialize Brotli transforms');
    }
  }

  static int transformDictionaryWord(Uint8List dst, int dstOffset, Uint8List src, int srcOffset,
      int wordLen, Transforms transforms, int transformIndex) {
    _ensureInitialized();
    int offset = dstOffset;
    final Int32List triplets = transforms.triplets;
    final Uint8List prefixSuffixStorage = transforms.prefixSuffixStorage;
    final Int32List prefixSuffixHeads = transforms.prefixSuffixHeads;
    final int transformOffset = 3 * transformIndex;
    final int prefixIdx = triplets[transformOffset];
    final int transformType = triplets[transformOffset + 1];
    final int suffixIdx = triplets[transformOffset + 2];
    int prefix = prefixSuffixHeads[prefixIdx];
    final int prefixEnd = prefixSuffixHeads[prefixIdx + 1];
    int suffix = prefixSuffixHeads[suffixIdx];
    final int suffixEnd = prefixSuffixHeads[suffixIdx + 1];

    int omitFirst = transformType - omitFirstBase;
    int omitLast = transformType - omitLastBase;
    if (omitFirst < 1 || omitFirst > omitFirstLastLimit) {
      omitFirst = 0;
    }
    if (omitLast < 1 || omitLast > omitFirstLastLimit) {
      omitLast = 0;
    }

    // Copy prefix.
    while (prefix != prefixEnd) {
      dst[offset++] = prefixSuffixStorage[prefix++];
    }

    int len = wordLen;
    // Copy trimmed word.
    if (omitFirst > len) {
      omitFirst = len;
    }
    int dictOffset = srcOffset + omitFirst;
    len -= omitFirst;
    len -= omitLast;
    int i = len;
    while (i > 0) {
      dst[offset++] = src[dictOffset++];
      i--;
    }

    // Ferment.
    if (transformType == uppercaseFirst || transformType == uppercaseAll) {
      int uppercaseOffset = offset - len;
      if (transformType == uppercaseFirst) {
        len = 1;
      }
      while (len > 0) {
        final int c0 = dst[uppercaseOffset] & 0xFF;
        if (c0 < 0xC0) {
          if (c0 >= 97 && c0 <= 122) { // in [a..z] range
            dst[uppercaseOffset] = dst[uppercaseOffset] ^ 32;
          }
          uppercaseOffset += 1;
          len -= 1;
        } else if (c0 < 0xE0) {
          dst[uppercaseOffset + 1] = dst[uppercaseOffset + 1] ^ 32;
          uppercaseOffset += 2;
          len -= 2;
        } else {
          dst[uppercaseOffset + 2] = dst[uppercaseOffset + 2] ^ 5;
          uppercaseOffset += 3;
          len -= 3;
        }
      }
    } else if (transformType == shiftFirst || transformType == shiftAll) {
      int shiftOffset = offset - len;
      final int param = transforms.params[transformIndex];
      /* Limited sign extension: scalar < (1 << 24). */
      int scalar = (param & 0x7FFF) + (0x1000000 - (param & 0x8000));
      while (len > 0) {
        int step = 1;
        final int c0 = dst[shiftOffset] & 0xFF;
        if (c0 < 0x80) {
          /* 1-byte rune / 0sssssss / 7 bit scalar (ASCII). */
          scalar += c0;
          dst[shiftOffset] = scalar & 0x7F;
        } else if (c0 < 0xC0) {
          /* Continuation / 10AAAAAA. */
        } else if (c0 < 0xE0) {
          /* 2-byte rune / 110sssss AAssssss / 11 bit scalar. */
          if (len >= 2) {
            final int c1 = dst[shiftOffset + 1];
            scalar += (c1 & 0x3F) | ((c0 & 0x1F) << 6);
            dst[shiftOffset] = 0xC0 | ((scalar >> 6) & 0x1F);
            dst[shiftOffset + 1] = (c1 & 0xC0) | (scalar & 0x3F);
            step = 2;
          } else {
            step = len;
          }
        } else if (c0 < 0xF0) {
          /* 3-byte rune / 1110ssss AAssssss BBssssss / 16 bit scalar. */
          if (len >= 3) {
            final int c1 = dst[shiftOffset + 1];
            final int c2 = dst[shiftOffset + 2];
            scalar += (c2 & 0x3F) | ((c1 & 0x3F) << 6) | ((c0 & 0x0F) << 12);
            dst[shiftOffset] = 0xE0 | ((scalar >> 12) & 0x0F);
            dst[shiftOffset + 1] = (c1 & 0xC0) | ((scalar >> 6) & 0x3F);
            dst[shiftOffset + 2] = (c2 & 0xC0) | (scalar & 0x3F);
            step = 3;
          } else {
            step = len;
          }
        } else if (c0 < 0xF8) {
          /* 4-byte rune / 11110sss AAssssss BBssssss CCssssss / 21 bit scalar. */
          if (len >= 4) {
            final int c1 = dst[shiftOffset + 1];
            final int c2 = dst[shiftOffset + 2];
            final int c3 = dst[shiftOffset + 3];
            scalar += (c3 & 0x3F) | ((c2 & 0x3F) << 6) | ((c1 & 0x3F) << 12) | ((c0 & 0x07) << 18);
            dst[shiftOffset] = 0xF0 | ((scalar >> 18) & 0x07);
            dst[shiftOffset + 1] = (c1 & 0xC0) | ((scalar >> 12) & 0x3F);
            dst[shiftOffset + 2] = (c2 & 0xC0) | ((scalar >> 6) & 0x3F);
            dst[shiftOffset + 3] = (c3 & 0xC0) | (scalar & 0x3F);
            step = 4;
          } else {
            step = len;
          }
        }
        shiftOffset += step;
        len -= step;
        if (transformType == shiftFirst) {
          len = 0;
        }
      }
    }

    // Copy suffix.
    while (suffix != suffixEnd) {
      dst[offset++] = prefixSuffixStorage[suffix++];
    }

    return offset - dstOffset;
  }
}
