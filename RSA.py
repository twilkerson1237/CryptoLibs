import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def utf8(s: bytes):
    return str(s, 'utf-8')

######
# Generate private key
######
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096,
    backend=default_backend()
)
#####
# Generate public key
#####
public_key = private_key.public_key()

#####
# Gen private pem
#####
private_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

######
# Write private key to file and generate private pem file
######
with open('private_key.pem', 'wb') as f:
    f.write(private_pem)

#####
# Generate public pem and generate public pem file
#####
public_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)
print("My public pem: ", public_pem)
with open('public_key.pem', 'wb') as f:
    f.write(public_pem)

#####
# Read bytes and store in private_key variable
#####
with open("private_key.pem", "rb") as key_file:
    private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
#####

# Read bytes and store in public_key variable
#####
with open("public_key.pem", "rb") as key_file:
    public_key = serialization.load_pem_public_key(key_file.read(),backend=default_backend())

#####
# Set some plain text for in encryption
#####
plaintext = b'this is the correct plaintext!'

print(f'plaintext: ',utf8(plaintext))
#####
# Encrypt plaintext and store in encrypted variable
#####
encrypted = base64.b64encode(public_key.encrypt(plaintext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)))
#####
# Here's our encrypted blob
#####
print(f'encrypted: ',utf8(encrypted))

#####
# Use our private key to decrypt blob and store in decrpyted variable
#####
decrypted = private_key.decrypt(base64.b64decode(encrypted),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
#####
# Print decrypted blob
#####
print(f'decrypted: ', utf8(decrypted))