import os
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
# Test the encrypted data
# ct = b'\xaa\xfa\x8e\xb1|\xdf\xf3i\xba\x12r\xcf.Q\xc0\x94' # cipher text
# key = bytes("SzE6pcNdUGbF0nVTNjqDj79v8JwBf7P2","utf-8") # 32 byte key
# iv = os.urandom(16) # 16 byte IV
# iv = b'\x89iu\xfaE){Fvx7M\x8a\xf3\xb9\x1a' # Need the original IV
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
decryptor = cipher.decryptor()
message = decryptor.update(ct) + decryptor.finalize()
print("The message is: ", message)