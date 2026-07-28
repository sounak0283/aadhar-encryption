"""
key_utils.py
Utilities for RSA key generation and PEM import/export.
"""


from Crypto.PublicKey import RSA
from typing import Tuple

def generate_keys(bits: int = 2048) -> Tuple[bytes, bytes]:
    """
    Generate an RSA keypair.

    Args:
        bits: RSA modulus size in bits (2048 recommended).

    Returns:
        Tuple containing (private_pem_bytes, public_pem_bytes)
    """
    key = RSA.generate(bits)
    private_pem = key.export_key(format="PEM")
    public_pem = key.publickey().export_key(format="PEM")
    return private_pem, public_pem

def load_private_key(pem_bytes: bytes):
    """Load a private RSA key from PEM bytes."""
    return RSA.import_key(pem_bytes)

def load_public_key(pem_bytes: bytes):
    """Load a public RSA key from PEM bytes."""
    return RSA.import_key(pem_bytes)

def save_file(path: str, data: bytes) -> None:
    """Write bytes to a file (overwrites existing)."""
    with open(path, "wb") as f:
        f.write(data)

def read_file(path: str) -> bytes:
    """Read bytes from a file and return them."""
    with open(path, "rb") as f:
        return f.read()