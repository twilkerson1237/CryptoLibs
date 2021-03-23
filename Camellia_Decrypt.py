import os
import argparse
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
######
# TEST AREA
######
# The cipher text is:  b'\xb2<\x06\xafl\x9e\xc7\xcd\x0ep,\xdf\xd2\xbd<\xab\x1d,S\x0f\xa3\x96\x8f\x1d%\xe5!\x93+\x06:\rD\xf5\xcf\x00\xdf\xf0\x86O\xdb>\x18]YF\xd0,'
# The length of the cipher text is:  48
# The iv is:  b'\x82\x95\xa9v\xb6\x06~\x9e\xd4\xd1>\x96\xab\xde\x02\xe7'
# The salt is:  b'S\xa4Z\x99\xdb\x9d\xd5'
# The length of the original message is:  38
key = b"SzE6pcNdUGbF0nVTNjqDj79v8JwBf7P2"
encoding = 'utf-8'
cipher_text = b'\xb2<\x06\xafl\x9e\xc7\xcd\x0ep,\xdf\xd2\xbd<\xab\x1d,S\x0f\xa3\x96\x8f\x1d%\xe5!\x93+\x06:\rD\xf5\xcf\x00\xdf\xf0\x86O\xdb>\x18]YF\xd0,'
len_cipher_text = 48
iv = b'\x82\x95\xa9v\xb6\x06~\x9e\xd4\xd1>\x96\xab\xde\x02\xe7'
salt = b'S\xa4Z\x99\xdb\x9d\xd5'
len_original_message = 38
total_pad = len_cipher_text - len_original_message
combined_bytes = iv + salt + cipher_text
print("Combined bytes: ", combined_bytes) # cool this works
print("Combined bytes length: ", len(combined_bytes))
###
# # Test decrypt
print("Attempting to decode cipher text: ", cipher_text)
new_key = hashlib.pbkdf2_hmac('sha256', key, salt, 4096)
print("The new key is: ", new_key)
print("The length of the new key is: ", len(new_key))
cipher = Cipher(algorithms.AES(new_key), modes.CBC(iv), default_backend())
decryptor = cipher.decryptor()
message = decryptor.update(cipher_text) + decryptor.finalize()
print("The decrypted payload is: ", message[0:(len_cipher_text - total_pad) - 1])
# print("The message is: ", message.decode(encoding))
######
# MAIN DECRYPT CLASS
######
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