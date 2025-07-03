import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def derive_key(passphrase: str, salt: bytes, iterations: int = 100_000) -> bytes:
    """
    Derive a 32‑byte (256‑bit) AES key from the given passphrase and salt.
    Uses PBKDF2‑HMAC‑SHA256 with the specified iteration count.
    """
    # Encode the passphrase to bytes
    pwd_bytes = passphrase.encode('utf-8')
    # Build the KDF
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    # Derive and return the key
    return kdf.derive(pwd_bytes)


def encrypt_file(infile: str, outfile: str, passphrase: str):
    salt = os.urandom(16)                # For key derivation
    iv = os.urandom(12)                  # For AES-GCM

    key = derive_key(passphrase, salt)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    with open(infile, 'rb') as fin, open(outfile, 'wb') as fout:
        fout.write(salt)                # Write salt to file
        fout.write(iv)                  # Write IV to file

        while chunk := fin.read(64 * 1024):  # Read in chunks (64 KB)
            encrypted = encryptor.update(chunk)
            fout.write(encrypted)

        fout.write(encryptor.finalize())     # Final block
        fout.write(encryptor.tag)            # Write 16B auth tag
