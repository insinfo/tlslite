import sys
import hashlib

sys.path.insert(0, 'tlslite-ng')

from tlslite.utils.python_rsakey import Python_RSAKey
from tlslite.utils import rsakey

n = int('a8d68acd413c5e195d5ef04e1b4faaf242365cb450196755e92e1215ba59802aafbadbf2564dd550956abb54f8b1c917844e5f36195d1088c600e07cada5c080ede679f50b3de32cf4026e514542495c54b1903768791aae9e36f082cd38e941ada89baecada61ab0dd37ad536bcb0a0946271594836e92ab5517301d45176b5', 16)
e = int('3', 16)
d = int('1c23c1cce034ba598f8fd2b7af37f1d30b090f7362aee68e5187adae49b9955c729f24a863b7a38d6e3c748e2972f6d940b7ba89043a2d6c2100256a1cf0f56a8cd35fc6ee205244876642f6f9c3820a3d9d2c8921df7d82aaadcaf2d7334d398931ddbba553190b3a416099f3aa07fd5b26214645a828419e122cfb857ad73b', 16)
p = int('c107a2fe924b76e206cb9bc4af2ab7008547c00846bf6d0680b3eac3ebcbd0c7fd7a54c2b9899b08f80cde1d3691eaaa2816b1eb11822d6be7beaf4e30977c49', 16)
q = int('dfea984ce4307eafc0d140c2bb82861e5dbac4f8567cbc981d70440dd639492079031486315e305eb83e591c4a2e96064966f7c894c3ca351925b5ce82d8ef0d', 16)

salt = bytes.fromhex('11223344555432167890')
pss_message = bytes.fromhex('c7f5270fca72725f9bd19f519a8d7cca3cc5c079024029f3bae510f9b02140fe238908e4f6c18f07a89c687c8684669b1f1db2baf9251a3c829faccb493084e16ec9e28d58868074a5d6221667dd6e528d16fe2c9f3db4cfaf6c4dce8c8439af38ceaaaa9ce2ecae7bc8f4a5a55e3bf96df9cd575c4f9cb327951b8cdfe4087168')


def fake_get_random_bytes(length: int) -> bytes:
    assert length == len(salt)
    return salt

rsakey.getRandomBytes = fake_get_random_bytes

key = Python_RSAKey(n, e, d, p, q)
m_hash = hashlib.sha1(pss_message).digest()
em = key.EMSA_PSS_encode(bytearray(m_hash), 1023, 'sha1', 10)
print(em.hex())
