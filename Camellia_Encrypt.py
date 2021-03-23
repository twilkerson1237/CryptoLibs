import os
import hashlib
import argparse
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


CAMELLIA_BLOCK_SIZE = 16  # Camellia block size is in multiples of 16
SALT_SIZE = 8  # WolfSSL salt size is 8 bytes

################
# main routine #
################
class CamelliaEncrypt:
    def __init__(self, message, message_size, key, key_size, file_to_write, encoding):
        self.message = message  # The message the user wants to encrypt
        self.message_size = message_size  # The size of the message the user is going input. DONT include null byte at
        # the end. So if your message is "Hello" then just input 5 and the program will include the null byte for you.
        self.key = key  # The encryption key. Use 32 byte(256 bit) length keys for Camellia
        self.key_size = key_size  # The size of the key you think you are inputting
        self.file_to_write = file_to_write  # The name of the file you want to write to otherwise leave as None
        self.encoding = encoding  # The encoding type for your message.

    # setters
    def set_message(self, message):
        """
        The set_message method sets the message for Camellia encryption
        :param message: The message parameter is the message the user wants to encrypt
        :return:
        """
        self.message = message

    def set_message_size(self, message_size):
        """
        The set_message_size method sets the message size in bytes.
        NOTE: Do not include the null pointer in your calculation. This function will compute that
        extra byte for you.
        :param message_size: The message_size parameter should be the number of bytes for the message
        :return:
        """
        self.message_size = message_size + 1

    def set_encryption_key(self, key):
        """
        The set_encryption_key method sets the encyption key method. The key must be 32(256 bits) bytes long otherwise the program
        will terminate.
        :param key:
        :return:
        """
        if len(key.encode('utf-8')) != 32:
            print("Your encryption key is not 32 bytes(256 bits) long. Please try again.")
            exit(-1)
        elif len(key.encode('utf-8') == 32):
            print("Key matches 32 bytes(256 bits) long. Setting key now.")
            self.key = key

    def set_keysize(self, key_size):
        """
        Key size should always be 32 bytes(256 bits) long. Running this method will first check the users key size
        input and if it doesn't match 32 bytes then the method will exit.
        :param key_size:
        :return:
        """
        if key_size != 32:
            print("Your key size is not set to 32 bytes(256 bits)! Please enter a new key size.")
            exit(-1)
        elif key_size == 32:
            print("Setting key size now.")
            self.key_size = key_size

    def set_encoding(self, encoding):
        """
        The set_encoding method sets the encoding type for the message that is going to be encrypted.
        :param encoding: The user need to pass in an encoding type
        :return:
        """
        self.encoding = encoding

    # print functions
    def print_message(self):
        print("The message is: ", self.message)

    def print_message_length(self):
        """
        The print_message_length method prints the length of the message the user inputs plus the null byte
        :return:
        """
        print("The message length is: ",self.message_size + 1)

    def print_key(self):
        """
        The print_key method prints the key the user input
        :return:
        """
        print("The key is: ",self.key)

    def print_key_size(self):
        """
        The print_key_size method prints the size of the key the user thinks they are inputting.
        :return:
        """
        print("The key size is: ", self.key_size)

    # getters
    def get_message(self):
        """
        The get_message method returns to the user the message that is to be encrypted.
        :return: Returns the message to be encrypted.
        """
        return self.message


    def get_message_size(self):
        """
        The get_message_size method returns the size of the users message that is being encrypted.
        :return: Returns the size of the message in bytes
        """
        return self.message_size + 1


    def get_encryption_key(self):
        """
        The get encryption key returns the encryption key entered by the user.
        :return: Returns the
        """
        return self.key


    def get_encryptionkey_size(self):
        """
        The get_encryptionkey_size method returns to the user the size of the encryption key size
        :return: Returns the encryption key the user input
        """
        return self.key_size


    def get_encoding(self):
        """
        The get_encoding method returns the encoding type the programmer has selected.
        :return:
        """
        return self.encoding

    # main functions
    def symmetric_key_gen(self):
        """
        The symmetric_key_gen method generates a one time symmetric key that is 32 bytes(256 bits) long
        :return: Returns symmetric key
        """
        symmetric_key = os.urandom(32)
        return symmetric_key

    # Need to validate that the key size they are putting in is indeed 32 bytes(256 bit) long
    def check_key_size(self):
        """
        The check_key_size method ensures the user is using 32 byte(256 bit) keys for encryption
        :return:
        """
        if len(self.key) != 32:  # check to see if the byte length of key is equal 32 bytes
            print("You do not have a 32 byte(256 bit) length key. Please use a 32 byte(256 bit) key for encryption."
                  "Exiting program now.")
            exit(-1)
        elif len(self.key) == 32:
            print("Verified 32 byte key.")

    @staticmethod
    def pad_message(length_message, message):
        """
        The pad_message method is a static method that taken in the length of the message in bytes and the message to be
        encrypted and then pads the message with null bytes
        :param length_message_bytes:
        :param message:
        :return:
        """
        padCounter = 0
        while (length_message % CAMELLIA_BLOCK_SIZE) != 0:
            length_message += 1
            padCounter += 1
        print("The padcounter in the function is: ", padCounter)
        padded_message = message + bytes((padCounter + 1) * '\0'.encode('utf-8'))
        return padded_message

    def iv_gen(self):
        """
        The gen_iv method generates iv during the encryption session.
        :return:
        """
        iv = os.urandom(16)  # Set the IV
        return iv

    def salt_gen(self):
        """
        The salt_gen method generates the salt during the encryption session.
        :return:
        """
        salt = os.urandom(SALT_SIZE - 1)
        return salt

    @staticmethod
    def new_key(key, salt):
        """
        The new_key method implements pbkdf2_hmac function.
        :param key: The 32 bytes(256 bit) key the user wants to use to encrypt
        :param salt: The salt that is generated during the encryption routine
        :return: Returns the newly stretched key
        """
        new_key = hashlib.pbkdf2_hmac('sha256', key, salt, 4096)
        return new_key

    @staticmethod
    def cipher_text_gen(message, new_key, iv):
        """
        The cipher_text_gen method generates the encrypted cipher text.
        :param message: The padded message
        :param new_key: The new key generated from the pdkdf2_hmac method
        :param iv: The iv generated
        :return: Returns the encrypted cipher text
        """
        cipher = Cipher(algorithms.AES(new_key), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(message) + encryptor.finalize()
        return cipher_text

    def byte_convert(self):
        """
        Based on the encoding type the user selects the byte_convert method converts the message and key to a byte. Also
        this method computes the key and message length in bytes
        array
        :return: Return the key, keylength, message, and message length
        """
        try:
            b_key = self.key
            key_length = len(self.key)
            b_message = bytes(self.message, self.encoding)
            message_length = len(self.message.encode(self.encoding)) + 1
            return b_key, key_length, b_message, message_length
        except LookupError as lkup_error:
            print("A LookupError occured! Cannot encode your key and message.")
            print("Error: ", lkup_error)
            exit(-1)
        except Exception as err:
            print("A general exception occured. Something went wrong.")
            print("Error: ", err)
            exit(-1)

    def camellia_encrypt(self):
        if self.file_to_write == False:
            print("PREPARING SESSION! PLEASE HANDLE OUTPUT ON YOUR OWN")
            iv = self.iv_gen()
            salt = self.salt_gen()
            b_key, key_length, b_message, message_length = self.byte_convert()
            padded_message = self.pad_message(message_length, b_message)
            new_key = self.new_key(b_key, salt)
            cipher_text = self.cipher_text_gen(padded_message, new_key, iv)
            print("The symmetric key is: ", b_key)
            print("The cipher text is: ", cipher_text)
            print("The length of the cipher text is: ", len(cipher_text))
            print("The iv is: ", iv)
            print("The salt is: ", salt)
            print("The length of the original message is: ", message_length)
            # Encrypt the key using the public that has been shared
            with open("shared_public_key.pem", "rb") as key_file:
                public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
            encrypted_symmetric_key = base64.b64encode(public_key.encrypt(b_key,
                                                            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                                         algorithm=hashes.SHA256(), label=None)))
            print("The encrypted symmetric key is: ", encrypted_symmetric_key)

            ##################
            return cipher_text
        else:
            # abs_filepath = os.path.dirname(os.path.abspath(__file__))
            print("PREPARING SESSION! ENCRYPTING TO A FILE. PLEASE HANDLE OUTPUT ON YOUR OWN")
            # print("Writing file to: ", abs_filepath)
            with open(r'C:\Users\black\Desktop\UL\Crypto\CryptoLibs\Python\CamelliaEncrypt\SecretMessage.txt' , "wb") as encrypted_file:
                iv = self.iv_gen()
                salt = self.salt_gen()
                b_key, key_length, b_message, message_length = self.byte_convert()
                padded_message = self.pad_message(message_length, b_message)
                new_key = self.new_key(b_key, salt)
                cipher_text = self.cipher_text_gen(padded_message, new_key, iv)
                # print("The cipher text is: ", cipher_text)
                # print("The length of the cipher text is: ", len(cipher_text))
                # print("The iv is: ", iv)
                # print("The salt is: ", salt)
                # print("The length of the original message is: ", message_length)
                encrypted_file.write(cipher_text)
            encrypted_file.close()

# run main
if __name__ == '__main__':
    # parse args

    # # WRITE TO BUFFER EXAMPLE
    # key = "SzE6pcNdUGbF0nVTNjqDj79v8JwBf7P2"
    key = os.urandom(32)
    message = "Hello there, you decrypted the string"
    encoding = 'utf-8'
    message_length = len(message)
    key_len = len(key)
    # Args:  message, message_size, key, key_size, file_to_write,  encoding
    cam_t = CamelliaEncrypt(message, message_length, key, key_len, False, 'utf-8')
    cam_t.camellia_encrypt()
    # # WRITE TO FILE EXAMPLE
    # key = "SzE6pcNdUGbF0nVTNjqDj79v8JwBf7P2"
    key = os.urandom(32)
    message = "Hello there, you decrypted the string"
    encoding = 'utf-8'
    message_length = len(message)
    key_len = len(key)
    # Args:  message, message_size, key, key_size, file_to_write,  encoding
    cam_t = CamelliaEncrypt(message, message_length, key, key_len, "secret_file.txt", 'utf-8')
    cam_t.camellia_encrypt()
