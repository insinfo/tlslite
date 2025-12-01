from pathlib import Path
import json

JAVA_PATH = Path(r"c:\MyDartProjects\tlslite\brotli-google\java\org\brotli\dec\DictionaryData.java")
OUTPUT_PATH = Path(r"c:\MyDartProjects\tlslite\lib\src\utils\brotlidecpy\dictionary_data_constants.dart")

text = JAVA_PATH.read_text()

def extract(name: str) -> str:
    marker = f"private static final String {name} = \""
    start = text.index(marker) + len(marker)
    chars = []
    i = start
    while True:
        ch = text[i]
        if ch == '"' and text[i - 1] != '\\':
            break
        chars.append(ch)
        i += 1
    return ''.join(chars)


data0 = extract('DATA0')
data1 = extract('DATA1')
skip_flip = extract('SKIP_FLIP')
size_bits_data = extract('SIZE_BITS_DATA')
size_bits = [ord(c) - 65 for c in size_bits_data]

data0_literal = json.dumps(data0)
data1_literal = json.dumps(data1)
skip_flip_literal = json.dumps(skip_flip)
size_bits_literal = ', '.join(str(v) for v in size_bits)

output = f"""// AUTO-GENERATED FROM brotli-google/java/org/brotli/dec/DictionaryData.java
// Do not edit manually.
// Contains Brotli dictionary payload required for decoder parity with the Google reference.

const String kDictionaryData0 = {data0_literal};

const String kDictionaryData1 = {data1_literal};

const String kDictionarySkipFlip = {skip_flip_literal};

const List<int> kDictionarySizeBits = <int>[{size_bits_literal}];
"""

OUTPUT_PATH.write_text(output)
print(f"Wrote {OUTPUT_PATH}")
