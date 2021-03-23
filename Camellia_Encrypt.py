import os
import hashlib
import argparse
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
            b_key = bytes(self.key, self.encoding)
            key_length = len(self.key.encode(self.encoding))
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
            print("Encrypting message please handle message on your own!")
            iv = self.iv_gen()
            salt = self.salt_gen()
            b_key, key_length, b_message, message_length = self.byte_convert()
            padded_message = self.pad_message(message_length, b_message)
            new_key = self.new_key(b_key, salt)
            cipher_text = self.cipher_text_gen(padded_message, new_key, iv)
            print("The cipher text is: ", cipher_text)
            print("The length of the cipher text is: ", len(cipher_text))
            print("The iv is: ", iv)
            print("The salt is: ", salt)
            print("The length of the original message is: ", message_length)
            return cipher_text
        else:
            abs_filepath = os.path.dirname(os.path.abspath(__file__))+'\\Output\\'
            print("Encrypting and writing to file!")
            print("Writing file to: ", abs_filepath)
            with open(abs_filepath + self.file_to_write, "wb") as encrypted_file:
                iv = self.iv_gen()
                salt = self.salt_gen()
                b_key, key_length, b_message, message_length = self.byte_convert()
                padded_message = self.pad_message(message_length, b_message)
                new_key = self.new_key(b_key, salt)
                cipher_text = self.cipher_text_gen(padded_message, new_key, iv)
                print("The cipher text is: ", cipher_text)
                print("The iv is: ", iv)
                print("The salt is: ", salt)
                print("The length of the original message is: ", message_length)
                encrypted_file.write(cipher_text)
            encrypted_file.close()

# run main
if __name__ == '__main__':
    # parse args

    # # write to buffer example
    key = "SzE6pcNdUGbF0nVTNjqDj79v8JwBf7P2"
    message = "Hello there, you decrypted the string"
    encoding = 'utf-8'
    message_length = len(message)
    key_len = len(key)
    # Args:  message, message_size, key, key_size, file_to_write,  encoding
    cam_t = CamelliaEncrypt(message, message_length, key, key_len, False, 'utf-8')
    cam_t.camellia_encrypt()
    # write to file example
    key = "SzE6pcNdUGbF0nVTNjqDj79v8JwBf7P2"
    message = "Hello there, you decrypted the string"
    encoding = 'utf-8'
    message_length = len(message)
    key_len = len(key)
    # Args:  message, message_size, key, key_size, file_to_write,  encoding
    cam_t = CamelliaEncrypt(message, message_length, key, key_len, "secret_file.txt", 'utf-8')
    cam_t.camellia_encrypt()
