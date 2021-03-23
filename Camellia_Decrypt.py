import os
import argparse
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
######
# TEST AREA
######
# The cipher text is:  b'\xb2<\x06\xafl\x9e\xc7\xcd\x0ep,\xdf\xd2\xbd<\xab\x1d,S\x0f\xa3\x96\x8f\x1d%\xe5!\x93+\x06:\rD\xf5\xcf\x00\xdf\xf0\x86O\xdb>\x18]YF\xd0,'
# The length of the cipher text is:  48
# The iv is:  b'\x82\x95\xa9v\xb6\x06~\x9e\xd4\xd1>\x96\xab\xde\x02\xe7'
# The salt is:  b'S\xa4Z\x99\xdb\x9d\xd5'
# The length of the original message is:  38
# key = b"SzE6pcNdUGbF0nVTNjqDj79v8JwBf7P2"
# encoding = 'utf-8'
# cipher_text = b'\xb2<\x06\xafl\x9e\xc7\xcd\x0ep,\xdf\xd2\xbd<\xab\x1d,S\x0f\xa3\x96\x8f\x1d%\xe5!\x93+\x06:\rD\xf5\xcf\x00\xdf\xf0\x86O\xdb>\x18]YF\xd0,'
# len_cipher_text = 48
# iv = b'\x82\x95\xa9v\xb6\x06~\x9e\xd4\xd1>\x96\xab\xde\x02\xe7'
# salt = b'S\xa4Z\x99\xdb\x9d\xd5'
# len_original_message = 38
# total_pad = len_cipher_text - len_original_message
# combined_bytes = iv + salt + cipher_text
# print("Combined bytes: ", combined_bytes) # cool this works
# print("Combined bytes length: ", len(combined_bytes))
# ###
# # # Test decrypt
# print("Attempting to decode cipher text: ", cipher_text)
# new_key = hashlib.pbkdf2_hmac('sha256', key, salt, 4096)
# print("The new key is: ", new_key)
# print("The length of the new key is: ", len(new_key))
# cipher = Cipher(algorithms.AES(new_key), modes.CBC(iv), default_backend())
# decryptor = cipher.decryptor()
# message = decryptor.update(cipher_text) + decryptor.finalize()
# print("The decrypted payload is: ", message[0:(len_cipher_text - total_pad) - 1])
# print("The message is: ", message.decode(encoding))
# Get the encrypted symmetric key and decrypt with private key
# This result should match the symmetric key generated on the encrypt side.
######
# GET PRIVATE KEY
######
encrypted_sym_key = b'ObtHFphloV1ug9YRjXAk+S1sv+bEyJPCISF8J7DA9wsEG4xYeoqQPKY+swYKfTK3tgBVSqK2UDEOH2KThFbNz5Ueq0TSQz6g3' \
                    b'5S9VqfMLIreYKz+LZmY75G/OAFGSrRgbwFrmsakNi33Doy6+676dD9mgJwdy2Ms7lUUretLCFBnvEodezB5cmyIC9viDPJ/DB' \
                    b'aXCv0D6ZibiyX0fhnaTmGt0jt5U6QHukkMrddpRn/BE/+heTtEOH2OiCrW9wtL/kOetA4PaIqC5L5re2eIUAUo+jWUx3L2nId' \
                    b'c53h7ArqasOFeXbOH2XjcXRWuA/hjf4tI8bgP+g/BBz5Xiycci2W4A1khGPMhWPCsd8tcOELiv3Hdphsh9na6UbRCaCv2TqPM' \
                    b'8SJJ5bDlcHqtS+GYYFUep+F07Y+8uMy68OV4rGHEQm8tdyWcvRZNKW3Bm+6gg22nzV1LiY7UE9TXAxkA2cwvFUqhv9ZckkjtW' \
                    b'ek5YuUBHJfFl4kY5M4ULJZKbF5/3H169IR5px978cCUlzcSnxydY4bclPJx9UAg0e8SP559Iocz76HWHyrRItAZpDRqje7Zage' \
                    b'6G0FLWSbAIL9qz14HQZ3+oYVDyZkKm0bn9HDEQlKvU0UFxD0zqFfcXaZavmdbDeZOUY/w0oPuZas2GgKULtkuO+0gK9XCNtjLa' \
                    b'+U='
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
decrypted_symmetric_key = private_key.decrypt(base64.b64decode(encrypted_sym_key),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
print("The decrypted assymetric key is: ", decrypted_symmetric_key)
# CHECK DEC SYMM KEY: b"\xba\x88\x80\x0e\x04&\xb4$[\x82\xca\x94\x0e\x15 '\xc6_z\xcf}\x0c(\xeay\xdb\x17|\xd9\xc5,\xe2"
cipher_text = b"\x01z\nz%\x95S\x1a`MxK\x18\xad\xb2\xe2\x1f;p/y\xf2\x8by\xd7A2\x89\x87'\x83\x99\xfb\x06\xd1E\xa7B\\\x9f+\x0c/C\x01\xb6~\x12"
len_cipher_text = len(cipher_text)
iv = b"\x8bc='\xb9\x82\x8d\x90\xe3\x07\xd0\xb7\xbaVP\xcc"
salt = b'\x9a\xac*\xf9\x06^\xfd'
len_original_message = 38
tot_padding = 10
#### Things are looking good! So lets try to get the camellia decryption process rolling!
# # # Test decrypt
print("Attempting to decode cipher text: ", cipher_text)
new_key = hashlib.pbkdf2_hmac('sha256', decrypted_symmetric_key, salt, 4096)
print("The new key is: ", new_key)
print("The length of the new key is: ", len(new_key))
cipher = Cipher(algorithms.AES(new_key), modes.CBC(iv), default_backend())
decryptor = cipher.decryptor()
message = decryptor.update(cipher_text) + decryptor.finalize()
print("The decrypted payload is: ", message[0:(len_cipher_text - tot_padding) - 1])
######
# MAIN DECRYPT CLASS
######
# A few things need to go here in order for the decryption to be successful.
# 1. We will the secret message that was encrypted using the 1 time generated 32 byte key
# 2. We will need the encrypted blob that the encryption side generated using the public key
def decrypt_message(cipher_text):
    return


if '__name__'=='__main__':
    try:
        decrypt_message()
        # print("Attempting to decode cipher text: ", ct)
        # decryptor = cipher.decryptor()
        # message = decryptor.update(ct) + decryptor.finalize()
        # print("The message is: ", message.decode('utf-8'))
    except Exception as err:
        print("An error occured when trying to decrypt the message.")
        print("Error: ",err)
        exit(-1)
# Test decrypt
# print("Attempting to decode cipher text: ", ct)
# decryptor = cipher.decryptor()
# message = decryptor.update(ct) + decryptor.finalize()
# print("The message is: ", message.decode('utf-8'))