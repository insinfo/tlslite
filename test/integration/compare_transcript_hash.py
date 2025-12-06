#!/usr/bin/env python3
"""
Compare exact transcript hash calculation between Python and Dart.
Uses captured raw handshake messages from a session.
"""

import sys
sys.path.insert(0, 'tlslite-ng')

from tlslite.mathtls import calc_key

def hex_to_bytes(s):
    return bytes.fromhex(s)

def bytes_to_hex(b):
    return b.hex()

# Sample raw handshake messages from a TLS 1.2 session (from Dart debug)
# These are the exact bytes of each handshake message
# We need to capture them from both Python and Dart and compare

# Let's test with fixed inputs to verify the PRF is the same

print("=== Testing calcFinished with fixed inputs ===")

# Fixed test vectors
master_secret = hex_to_bytes('0d36cc66603f174aa02ac40bc0b9409c' * 3)  # 48 bytes
handshake_hash = hex_to_bytes('c9aa1a577adc995f6ceac734fa496a69dcc3dc26840725071101a82705142421')  # 32 bytes SHA-256

version = (3, 3)  # TLS 1.2
cipher_suite = 0xcca8  # ECDHE_RSA_CHACHA20_POLY1305

# Create a HandshakeHashes object and override the digest
class FakeHandshakeHashes:
    def __init__(self, hash_value):
        self._hash_value = hash_value
    
    def digest(self, hashName='sha256'):
        return self._hash_value

fake_hashes = FakeHandshakeHashes(handshake_hash)

verify_data = calc_key(version, master_secret, cipher_suite,
                       b'client finished',
                       handshake_hashes=fake_hashes,
                       output_length=12)

print(f"Master Secret: {bytes_to_hex(master_secret)}")
print(f"Handshake Hash: {bytes_to_hex(handshake_hash)}")
print(f"Cipher Suite: 0x{cipher_suite:04x}")
print(f"Verify Data: {bytes_to_hex(verify_data)}")

# Now let's verify the PRF separately
from tlslite.mathtls import prf12

seed = handshake_hash
label = b'client finished'
output_length = 12

prf_output = prf12(master_secret, label, seed, output_length)
print(f"\nPRF12 output: {bytes_to_hex(prf_output)}")

# Test with the actual values from the Dart test run
print("\n=== Testing with actual values from Dart test ===")
actual_master = hex_to_bytes('5f6925bab50e4c003440995159f3bfbc' + '0' * 64)[:48]
actual_hash = hex_to_bytes('a68ce9213eb1bbf566a10ee2937ab9fa441632e0078c906bbe4df306cad3d623')
actual_verify = hex_to_bytes('600cd3ecbf6f42c86c07d125')

class FakeHandshakeHashes2:
    def __init__(self, hash_value):
        self._hash_value = hash_value
    
    def digest(self, hashName='sha256'):
        return self._hash_value

# The Dart had this master secret (from debug log, first 16 bytes shown)
# We need the FULL master secret to compare

print(f"Dart handshake hash: {bytes_to_hex(actual_hash)}")
print(f"Dart verify_data: {bytes_to_hex(actual_verify)}")

# To verify, we need to capture the exact master secret from Dart
# For now, let's just confirm the PRF function works the same
