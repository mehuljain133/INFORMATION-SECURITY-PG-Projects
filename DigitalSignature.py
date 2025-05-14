# Unit-IV Digital signatures: ElGamal digital signature scheme , Elliptic Curve digital signature scheme, NISTdigital signature scheme

pip install pycryptodome cryptography

from Crypto.PublicKey import DSA, ElGamal
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import random
import string

# Helper function to generate random messages
def generate_random_message(length=32):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# --- ElGamal Digital Signature Scheme ---
def elgamal_keygen(p, g):
    x = random.randint(1, p - 1)
    y = pow(g, x, p)
    return x, y

def elgamal_sign(message, p, g, x):
    h = SHA256.new(message.encode())
    m = int(h.hexdigest(), 16)
    k = random.randint(1, p - 1)  # Random integer
    r = pow(g, k, p)
    s = (m - x * r) * pow(k, -1, p - 1) % (p - 1)
    return r, s

def elgamal_verify(message, r, s, p, g, y):
    h = SHA256.new(message.encode())
    m = int(h.hexdigest(), 16)
    v1 = pow(y, r, p) * pow(r, s, p) % p
    v2 = pow(g, m, p)
    return v1 == v2

# --- Elliptic Curve Digital Signature Scheme (ECDSA) ---
def ecdsa_keygen():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def ecdsa_sign(private_key, message):
    signature = private_key.sign(
        message.encode(),
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def ecdsa_verify(public_key, signature, message):
    try:
        public_key.verify(
            signature,
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except:
        return False

# --- NIST Digital Signature Algorithm (DSA) ---
def dsa_keygen():
    private_key = DSA.generate(2048)
    public_key = private_key.publickey()
    return private_key, public_key

def dsa_sign(private_key, message):
    h = SHA256.new(message.encode())
    signer = DSS.new(private_key, 'fips-186-3')
    return signer.sign(h)

def dsa_verify(public_key, signature, message):
    h = SHA256.new(message.encode())
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False

# --- Example Usage ---
if __name__ == "__main__":
    print("=== Digital Signature Schemes ===")

    # ElGamal Digital Signature
    print("\n=== ElGamal Digital Signature ===")
    p = 7919  # Example prime number
    g = 5  # Example generator
    x, y = elgamal_keygen(p, g)
    message = generate_random_message()
    print(f"Message: {message}")
    r, s = elgamal_sign(message, p, g, x)
    print(f"Signature (r, s): ({r}, {s})")
    is_valid = elgamal_verify(message, r, s, p, g, y)
    print(f"ElGamal Signature Valid: {is_valid}")

    # Elliptic Curve Digital Signature (ECDSA)
    print("\n=== Elliptic Curve Digital Signature (ECDSA) ===")
    private_key, public_key = ecdsa_keygen()
    message = generate_random_message()
    print(f"Message: {message}")
    signature = ecdsa_sign(private_key, message)
    print(f"Signature: {signature.hex()}")
    is_valid = ecdsa_verify(public_key, signature, message)
    print(f"ECDSA Signature Valid: {is_valid}")

    # NIST Digital Signature Algorithm (DSA)
    print("\n=== NIST Digital Signature Algorithm (DSA) ===")
    private_key, public_key = dsa_keygen()
    message = generate_random_message()
    print(f"Message: {message}")
    signature = dsa_sign(private_key, message)
    print(f"Signature: {signature.hex()}")
    is_valid = dsa_verify(public_key, signature, message)
    print(f"DSA Signature Valid: {is_valid}")
