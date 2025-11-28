import sys
import binascii

sys.path.insert(0, r'c:\MyDartProjects\tlslite\tlslite-ng')

from tlslite.utils.aesccm import AESCCM
from tlslite.utils.rijndael import Rijndael

key = bytes.fromhex('feffe9928665731c6d6a8f9467308308')
nonce = bytes.fromhex('cafebabefacedbaddecaf888')
aad = bytes.fromhex('feedfacedeadbeeffeedfacedeadbeefabaddad2')
plaintext = bytes.fromhex('6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b4179e66c3710')

aes = AESCCM(bytearray(key), 'python', Rijndael(bytearray(key), 16).encrypt)
result = aes.seal(bytearray(nonce), bytearray(plaintext), bytearray(aad))
print(binascii.hexlify(result).decode())
