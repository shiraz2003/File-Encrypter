import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

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


# Test key derivation
passphrase = "mysecret"
salt = os.urandom(16)
key = derive_key(passphrase, salt)
print(f"Derived key (hex): {key.hex()}")
print(f"Salt (hex):        {salt.hex()}")
