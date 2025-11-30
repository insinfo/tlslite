mask = 0xFFFFFFFFFFFFFFFF
prime2 = 0xC2B2AE3D27D4EB4F
prime3 = 0x165667B19E3779F9
prime5 = 0x27D4EB2F165667C5
hash_value = (prime5) & mask
hash_value = (hash_value + 0) & mask
hash_value ^= (hash_value >> 33)
hash_value = (hash_value * prime2) & mask
hash_value ^= (hash_value >> 29)
hash_value = (hash_value * prime3) & mask
hash_value ^= (hash_value >> 32)
print(hex(hash_value & mask))
