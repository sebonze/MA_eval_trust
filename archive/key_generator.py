# Using cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# Using pycryptodome
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA as RSA_dome
from Crypto.Random import get_random_bytes

# Symmetric Key Generation and Encryption/Decryption using cryptography
def cryptography_generate_symmetric_key():
    return Fernet.generate_key()

def cryptography_symmetric_encrypt(key, plaintext):
    cipher = Fernet(key)
    return cipher.encrypt(plaintext.encode())

def cryptography_symmetric_decrypt(key, ciphertext):
    cipher = Fernet(key)
    return cipher.decrypt(ciphertext).decode()

# Asymmetric Key Generation and Encryption/Decryption using cryptography
def cryptography_generate_asymmetric_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def cryptography_asymmetric_encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def cryptography_asymmetric_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Symmetric Key Generation and Encryption/Decryption using pycryptodome
def pycryptodome_generate_symmetric_key():
    return get_random_bytes(16)

def pycryptodome_symmetric_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return (nonce, ciphertext)

def pycryptodome_symmetric_decrypt(key, nonce, ciphertext):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()

# Asymmetric Key Generation and Encryption/Decryption using pycryptodome
def pycryptodome_generate_asymmetric_keypair():
    key = RSA_dome.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def pycryptodome_asymmetric_encrypt(public_key, plaintext):
    recipient_key = RSA_dome.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    ciphertext = cipher_rsa.encrypt(plaintext.encode())
    return ciphertext

def pycryptodome_asymmetric_decrypt(private_key, ciphertext):
    key = RSA_dome.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(key)
    plaintext = cipher_rsa.decrypt(ciphertext)
    return plaintext.decode()

# Debug/Demonstration functions
if __name__ == "__main__":
    # Demonstration for cryptography
    print("Using cryptography:")
    symmetric_key = cryptography_generate_symmetric_key()
    encrypted_message = cryptography_symmetric_encrypt(symmetric_key, "Hello, Kerberos!")
    decrypted_message = cryptography_symmetric_decrypt(symmetric_key, encrypted_message)
    print(f"Encrypted Message: {encrypted_message}")
    print(f"Decrypted Message: {decrypted_message}\n")

    # Demonstration for pycryptodome
    print("Using pycryptodome:")
    symmetric_key = pycryptodome_generate_symmetric_key()
    nonce, encrypted_message = pycryptodome_symmetric_encrypt(symmetric_key, "Hello, Kerberos!")
    decrypted_message = pycryptodome_symmetric_decrypt(symmetric_key, nonce, encrypted_message)
    print(f"Encrypted Message: {encrypted_message}")
    print(f"Decrypted Message: {decrypted_message}\n")