import os
import hashlib
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
############################
# Begin encryption routine #
############################
print("WORKING ENCRYPT")
salt_size = 8  # WolfSSL salt size is 8 bytes
camellia_block_size = 16  # Camellia uses block sizes of 16
padCounter = 0
key = bytes("SzE6pcNdUGbF0nVTNjqDj79v8JwBf7P2", 'utf-8')
print("Our original key is: ", key)
message = bytes("Hello there, you decrypted the string",'utf-8')
# message = bytes("A really secret message", 'utf-8')
# First need to length in bytes of plaintext
length_message_bytes = len(message) + 1  # +1 to include null pointer since we decrypt in C
# Get the size of the key in bytes
length_key_bytes = len(key)
print("The length of the message is: {} bytes".format(length_message_bytes))
print("The length of your key is: {} bytes".format(length_key_bytes))
# Need to get correct padding for message. Should be nearest multiple of 16
while (length_message_bytes % camellia_block_size) != 0:
    length_message_bytes += 1
    padCounter += 1
# Check post processing
print("The length of padded message is: ", length_message_bytes)  # This should be 48
print("The padcounter is at: ", padCounter)  # This should be 10
"""
Pad with zero bytes to plaintext message
"""
message = message + bytes((padCounter + 1) * '\0'.encode('utf-8'))
print("The length of the message is: ", len(message))
print("The message with padding is: ", message)
"""
Get generate IV
It looks like wolf ssl has to spin up a RNG
Replicate generate block func that writes random data to buffer
In this case our buffer is the iv buffer
"""
iv = os.urandom(16)  # create and assign random data to iv var
print("The IV is: ", iv)
"""
Generate salt
Wolfssl run wc_RNG_GenerateBlock again but on salt_size - 1 and
writes that data to the salt buffer
"""
salt = os.urandom(salt_size - 1)  # generate a random set of 7 bytes
print("The salt is: ", salt)
"""
Stretch the key using PBKDF2
"""
new_key = hashlib.pbkdf2_hmac('sha256', key, salt, 4096)
print("New key: ", new_key)
print("The size of our new key is: ", len(new_key))
# Encrypt
cipher = Cipher(algorithms.AES(new_key), modes.CBC(iv), default_backend())
encryptor = cipher.encryptor()
print("Preparing to encrypt message: ", message)  # Make sure we are encrypting our message
ct = encryptor.update(message) + encryptor.finalize()
print("The cipher text is: ", ct)
print("END WORKING ENCRYPT")
# print("The cipher text length is: ",
#       len(ct))  # The length of the cipher text is 32 because we have null byte padding at the end
# # Test decrypt
# print("Attempting to decode cipher text: ", ct)
# decryptor = cipher.decryptor()
# message = decryptor.update(ct) + decryptor.finalize()
# print("The message is: ", message.decode('utf-8'))