import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
# encrypt prep
key = bytes("SzE6pcNdUGbF0nVTNjqDj79v8JwBf7P2","utf-8") # 32 byte key
iv = os.urandom(16) # 16 byte IV
print("The IV is: ", iv)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
encryptor = cipher.encryptor()
ct = encryptor.update(b"a secret message") + encryptor.finalize()
print("The cipher text is: ", ct)
decryptor = cipher.decryptor()
message = decryptor.update(ct) + decryptor.finalize()
print("The message is: ", message)
