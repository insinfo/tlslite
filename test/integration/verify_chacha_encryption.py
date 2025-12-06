#!/usr/bin/env python3
"""
Verify ChaCha20-Poly1305 encryption against Dart implementation.
Uses the exact values from the Dart debug output.
"""

import sys
sys.path.insert(0, 'tlslite-ng')

from tlslite.utils.python_chacha20_poly1305 import CHACHA20_POLY1305

def hex_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

def bytes_to_hex(b):
    return b.hex()

# Values from Dart debug output:
client_key = hex_to_bytes('ec05072843de41459c435ff241b367045950d210a1d32d74a1089d862c9985a8')
client_iv = hex_to_bytes('3dfa0141ec769e5b7fef64c4')
seq_num = hex_to_bytes('0000000000000000')
plaintext = hex_to_bytes('1400000c31bbf9d6680e909120cdbfd2')
dart_ciphertext = hex_to_bytes('2c717d02ff6fd05bd69c892268ff8b7ba2899e526a996c7e791e0fe11b56d88b')

# Nonce construction (ChaCha20-Poly1305 in TLS 1.2)
# nonce = fixedNonce XOR padded(seqnum)
padded_seq = bytes(12 - len(seq_num)) + seq_num
nonce = bytes(a ^ b for a, b in zip(client_iv, padded_seq))

# AAD construction for TLS 1.2
# AAD = seqnum + content_type + version + length
content_type = 22  # handshake
version = (3, 3)   # TLS 1.2
plaintext_length = len(plaintext)

aad = seq_num + bytes([content_type, version[0], version[1], 
                        plaintext_length >> 8, plaintext_length & 0xff])

print("=== Input Values ===")
print(f"Client Key: {bytes_to_hex(client_key)}")
print(f"Client IV (fixedNonce): {bytes_to_hex(client_iv)}")
print(f"Sequence Number: {bytes_to_hex(seq_num)}")
print(f"Padded Sequence: {bytes_to_hex(padded_seq)}")
print(f"Nonce: {bytes_to_hex(nonce)}")
print(f"AAD: {bytes_to_hex(aad)}")
print(f"Plaintext: {bytes_to_hex(plaintext)}")
print(f"Plaintext length: {len(plaintext)}")

# Encrypt using Python
cipher = CHACHA20_POLY1305(client_key, 'python')
python_ciphertext = cipher.seal(nonce, plaintext, aad)

print("\n=== Results ===")
print(f"Python Ciphertext: {bytes_to_hex(python_ciphertext)}")
print(f"Dart Ciphertext:   {bytes_to_hex(dart_ciphertext)}")
print(f"Match: {python_ciphertext == dart_ciphertext}")

if python_ciphertext != dart_ciphertext:
    print("\n=== Difference Analysis ===")
    # Try with different nonce/aad combinations
    
    # Maybe Dart is using nonce without XOR?
    alt_nonce = client_iv
    alt_ciphertext = cipher.seal(alt_nonce, plaintext, aad)
    print(f"Alt (no XOR nonce): {bytes_to_hex(alt_ciphertext)}")
    print(f"  Match: {alt_ciphertext == dart_ciphertext}")
    
    # Maybe AAD is wrong?
    alt_aad = bytes([content_type, version[0], version[1], 
                     plaintext_length >> 8, plaintext_length & 0xff])
    alt_ciphertext2 = cipher.seal(nonce, plaintext, alt_aad)
    print(f"Alt (no seqnum in AAD): {bytes_to_hex(alt_ciphertext2)}")
    print(f"  Match: {alt_ciphertext2 == dart_ciphertext}")
    
    # Try with seqnum as explicit nonce (AES-GCM style)
    aes_gcm_nonce = client_iv + seq_num
    if len(aes_gcm_nonce) == 12:
        alt_ciphertext3 = cipher.seal(aes_gcm_nonce, plaintext, aad)
        print(f"Alt (AES-GCM style nonce): {bytes_to_hex(alt_ciphertext3)}")
        print(f"  Match: {alt_ciphertext3 == dart_ciphertext}")

print("\n=== Verification by Decryption ===")
try:
    # Try to decrypt Dart ciphertext with Python
    decrypted = cipher.open(nonce, dart_ciphertext, aad)
    print(f"Decrypted Dart ciphertext: {bytes_to_hex(decrypted)}")
    print(f"Plaintext match: {decrypted == plaintext}")
except Exception as e:
    print(f"Failed to decrypt Dart ciphertext: {e}")
    
    # Try alternative decryption attempts
    try:
        decrypted = cipher.open(client_iv, dart_ciphertext, aad)
        print(f"Decrypted with raw IV: {bytes_to_hex(decrypted)}")
    except:
        print("Failed with raw IV too")
