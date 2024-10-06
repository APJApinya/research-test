from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
import base64

# Password Hashing with PBKDF2
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(salt + key).decode()

# Symmetric key encryption (AES-GCM)
def encrypt_message(key, message):
    iv = os.urandom(12)  # GCM mode requires a 12-byte IV
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encryptor.tag + ciphertext).decode()

# Symmetric key decryption (AES-GCM)
def decrypt_message(key, ciphertext):
    data = base64.urlsafe_b64decode(ciphertext.encode())
    iv = data[:12]
    tag = data[12:28]
    ciphertext = data[28:]
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Key Rotation
def rotate_key(old_key):
    new_key = os.urandom(32)
    return new_key
