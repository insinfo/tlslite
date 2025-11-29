import sys
sys.path.insert(0, r'c:\MyDartProjects\tlslite\tlslite-ng')

from unit_tests.test_tlslite_utils_aesccm import TestAESCCMIdentical
import binascii

TestAESCCMIdentical.setUpClass()
print(binascii.hexlify(TestAESCCMIdentical.ciphertext).decode())
