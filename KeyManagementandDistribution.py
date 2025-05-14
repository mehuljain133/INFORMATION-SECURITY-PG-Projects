# Unit-V Key Management and Distribution : Symmetric Key Distribution, X.509 Certificate public key infrastructures. 

pip install pycryptodome cryptography

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.x509 import CertificateBuilder
from cryptography.hazmat.primitives.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import Name, NameAttribute
import datetime
import random
import string

# Helper function to generate random messages
def generate_random_message(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# --- Symmetric Key Distribution (AES) ---
def generate_symmetric_key():
    return get_random_bytes(16)  # AES 128-bit key

def encrypt_with_symmetric_key(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce, tag, ciphertext

def decrypt_with_symmetric_key(nonce, tag, ciphertext, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# --- Asymmetric Key Generation for RSA ---
def generate_rsa_keys():
    private_key = RSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key

# --- Encrypt and Decrypt using RSA (Public/Private) ---
def encrypt_with_rsa(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message.encode())

def decrypt_with_rsa(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext).decode()

# --- X.509 Certificate Creation ---
def create_x509_certificate(private_key, public_key):
    # Subject and issuer for simplicity (self-signed certificate)
    subject = issuer = Name([NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                             NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
                             NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
                             NameAttribute(NameOID.ORGANIZATION_NAME, u"Example Corp"),
                             NameAttribute(NameOID.COMMON_NAME, u"example.com")])

    # Generate certificate valid from 'today' to one year later
    not_valid_before = datetime.datetime.utcnow()
    not_valid_after = not_valid_before + datetime.timedelta(days=365)

    # Create the certificate builder
    builder = CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)
    builder = builder.serial_number(random.randint(100000, 999999)).not_valid_before(not_valid_before).not_valid_after(not_valid_after)

    # Sign the certificate with the private key
    certificate = builder.sign(private_key, hashes.SHA256())

    # Return the certificate in PEM format
    return certificate.public_bytes(Encoding.PEM)

# --- Example usage ---

if __name__ == "__main__":
    print("=== Key Management and Distribution ===")

    # Symmetric Key Distribution (AES Example)
    print("\n=== Symmetric Key Distribution (AES) ===")
    key = generate_symmetric_key()
    message = generate_random_message()
    print(f"Original Message: {message}")
    nonce, tag, ciphertext = encrypt_with_symmetric_key(message, key)
    print(f"Ciphertext: {ciphertext.hex()}")
    decrypted_message = decrypt_with_symmetric_key(nonce, tag, ciphertext, key)
    print(f"Decrypted Message: {decrypted_message}")

    # RSA Key Generation and Encryption/Decryption
    print("\n=== RSA Encryption/Decryption ===")
    private_key, public_key = generate_rsa_keys()
    message = generate_random_message()
    print(f"Original Message: {message}")
    ciphertext = encrypt_with_rsa(public_key, message)
    print(f"Ciphertext (RSA): {ciphertext.hex()}")
    decrypted_message = decrypt_with_rsa(private_key, ciphertext)
    print(f"Decrypted Message (RSA): {decrypted_message}")

    # X.509 Certificate Creation
    print("\n=== X.509 Certificate Creation ===")
    certificate = create_x509_certificate(private_key, public_key)
    print(f"Generated X.509 Certificate:\n{certificate.decode()}")

