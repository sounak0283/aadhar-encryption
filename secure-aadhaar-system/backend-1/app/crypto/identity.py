"""
identity.py
Ed25519 signing identity (server/sender) and X25519 encryption identity (admin).
Keys cross this module's boundary as raw bytes so callers never need to import
PyNaCl types directly.
"""
from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey, PublicKey
from nacl.exceptions import BadSignatureError as _NaclBadSignatureError

from .exceptions import BadSignatureError


def generate_signing_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair. Returns (signing_key_seed, verify_key), 32 bytes each."""
    sk = SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def generate_encryption_keypair() -> tuple[bytes, bytes]:
    """Generate an X25519 keypair. Returns (private_key, public_key), 32 bytes each."""
    priv = PrivateKey.generate()
    return bytes(priv), bytes(priv.public_key)


def sign(payload: bytes, signing_key_seed: bytes) -> bytes:
    """Sign payload with an Ed25519 private key. Returns the raw 64-byte signature."""
    sk = SigningKey(signing_key_seed)
    return sk.sign(payload).signature


def verify_key_from_signing_key(signing_key_seed: bytes) -> bytes:
    """Derive the public verify key from a signing key seed — Ed25519 keypairs are
    deterministic from the seed, so this never needs to be stored separately."""
    return bytes(SigningKey(signing_key_seed).verify_key)


def verify(payload: bytes, signature: bytes, verify_key_bytes: bytes) -> bool:
    """Verify an Ed25519 signature. Returns True/False, never raises."""
    vk = VerifyKey(verify_key_bytes)
    try:
        vk.verify(payload, signature)
        return True
    except _NaclBadSignatureError:
        return False


def verify_or_raise(payload: bytes, signature: bytes, verify_key_bytes: bytes) -> None:
    """Verify an Ed25519 signature, raising BadSignatureError on failure."""
    if not verify(payload, signature, verify_key_bytes):
        raise BadSignatureError("signature verification failed")


def load_private_key(private_key_bytes: bytes) -> PrivateKey:
    return PrivateKey(private_key_bytes)


def load_public_key(public_key_bytes: bytes) -> PublicKey:
    return PublicKey(public_key_bytes)
