# Unit-III Cryptography: Substitution, transposition ciphers, symmetric-key algorithms: Data Encryption Standard, Advanced Encryption Standard, IDEA, Block cipher Operation, Stream  Ciphers: RC-4. Public key encryption: RSA, ElGamal. Diffie-Hellman key exchange. Elliptic Curve, EC cryptography, Message Authentication code (MAC), Cryptographic hash function.

from Crypto.Cipher import DES, AES, ARC4
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import random
import string
import math

# Helper function for generating random strings
def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# --- Substitution Cipher ---
def substitution_cipher(text, key):
    key = key.lower()
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    cipher = ''.join([key[alphabet.index(c)] if c in alphabet else c for c in text.lower()])
    return cipher

# --- Transposition Cipher ---
def transposition_cipher(text, key):
    n = len(text)
    columns = len(key)
    rows = math.ceil(n / columns)
    grid = ['' for _ in range(columns)]
    for i in range(n):
        grid[i % columns] += text[i]
    return ''.join(grid)

# --- Symmetric-key Algorithms ---
def des_encryption(plain_text, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(plain_text.ljust(8))

def aes_encryption(plain_text, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plain_text.ljust(16))

def rc4_encryption(plain_text, key):
    cipher = ARC4.new(key)
    return cipher.encrypt(plain_text.encode())

# --- Public Key Encryption (RSA) ---
def rsa_encryption(plain_text, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plain_text.encode())

def rsa_decryption(cipher_text, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(cipher_text).decode()

# --- ElGamal Encryption ---
def elgamal_keygen(p, g):
    x = random.randint(1, p-1)
    y = pow(g, x, p)
    return x, y

def elgamal_encryption(p, g, y, m):
    k = random.randint(1, p-1)
    c1 = pow(g, k, p)
    c2 = (m * pow(y, k, p)) % p
    return c1, c2

def elgamal_decryption(p, x, c1, c2):
    s = pow(c1, x, p)
    m = (c2 * pow(s, p-2, p)) % p
    return m

# --- Diffie-Hellman Key Exchange ---
def diffie_hellman_key_exchange(p, g, a_private, b_private):
    A = pow(g, a_private, p)
    B = pow(g, b_private, p)
    shared_key_a = pow(B, a_private, p)
    shared_key_b = pow(A, b_private, p)
    return shared_key_a, shared_key_b

# --- Elliptic Curve Cryptography (ECC) ---
def elliptic_curve_keygen():
    private_key = random.randint(1, 100)
    public_key = private_key * 2  # Simple simulation of ECC point multiplication
    return private_key, public_key

# --- Message Authentication Code (MAC) ---
def mac_generation(key, message):
    h = SHA256.new()
    h.update((key + message).encode())
    return h.hexdigest()

# --- Cryptographic Hash Function ---
def hash_function(message):
    h = SHA256.new()
    h.update(message.encode())
    return h.hexdigest()

# Example usage
if __name__ == "__main__":
    print("=== Cryptography Example ===")

    # Substitution Cipher Example
    print("\nSubstitution Cipher:")
    key = 'qwertyuiopasdfghjklzxcvbnm'  # Example key for substitution
    text = "hello"
    print(f"Encrypted Text: {substitution_cipher(text, key)}")

    # Transposition Cipher Example
    print("\nTransposition Cipher:")
    text = "hello"
    key = "3142"  # Example key for transposition
    print(f"Encrypted Text: {transposition_cipher(text, key)}")

    # Symmetric-key Encryption (DES, AES, RC4)
    key = get_random_bytes(8)  # DES requires 8 bytes
    text = "hello"
    print("\nDES Encryption:")
    print(des_encryption(text, key))

    aes_key = get_random_bytes(16)  # AES requires 16 bytes
    print("\nAES Encryption:")
    print(aes_encryption(text, aes_key))

    rc4_key = get_random_bytes(16)  # RC4 uses variable length key
    print("\nRC4 Encryption:")
    print(rc4_encryption(text, rc4_key))

    # Public Key Encryption: RSA
    rsa_key = RSA.generate(2048)
    public_key = rsa_key.publickey()
    private_key = rsa_key
    encrypted_text = rsa_encryption("Hello RSA", public_key)
    print("\nRSA Encryption:")
    print(rsa_decryption(encrypted_text, private_key))

    # ElGamal Encryption
    p = 23  # Example prime number
    g = 5  # Example base
    x, y = elgamal_keygen(p, g)
    m = 6  # Example message
    c1, c2 = elgamal_encryption(p, g, y, m)
    print("\nElGamal Encryption:")
    print(elgamal_decryption(p, x, c1, c2))

    # Diffie-Hellman Key Exchange
    p = 23  # Example prime number
    g = 5  # Example base
    a_private = random.randint(1, p-1)
    b_private = random.randint(1, p-1)
    shared_key_a, shared_key_b = diffie_hellman_key_exchange(p, g, a_private, b_private)
    print("\nDiffie-Hellman Key Exchange:")
    print(f"Shared key: {shared_key_a}, {shared_key_b}")

    # Elliptic Curve Cryptography
    private_key, public_key = elliptic_curve_keygen()
    print("\nElliptic Curve Cryptography (ECC):")
    print(f"Private Key: {private_key}, Public Key: {public_key}")

    # Message Authentication Code (MAC)
    key = "secret_key"
    message = "This is a test message"
    print("\nMAC Generation:")
    print(mac_generation(key, message))

    # Cryptographic Hash Function (SHA-256)
    message = "Hello, World!"
    print("\nCryptographic Hash Function (SHA-256):")
    print(hash_function(message))
