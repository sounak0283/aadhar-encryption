"""
password_utils.py
Two distinct password-related jobs live here:

1. Local provider: Argon2id password -> key derivation, used to encrypt the
   admin's X25519 private key at rest. No separately stored password hash —
   a wrong password simply fails to decrypt the private key (BadTagError).
2. AWS KMS provider: a plain Argon2id password *verifier* (hash_password /
   verify_password). There's no local private-key blob to decrypt in that
   mode, so the password's only job is authenticating the admin to this
   backend — see app/crypto/kms_provider.py and the README's "unlock chain
   — AWS KMS provider" section.
"""
import base64
from typing import TypedDict

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import hash_secret_raw, Type
from nacl.secret import SecretBox
from nacl.utils import random as nacl_random
from nacl.exceptions import CryptoError as _NaclCryptoError

from .exceptions import BadTagError

_password_hasher = PasswordHasher()

SALT_SIZE = 16
KEY_SIZE = SecretBox.KEY_SIZE  # 32 bytes
TIME_COST = 3
MEMORY_COST_KIB = 65536  # 64 MiB
PARALLELISM = 4


class EncryptedPrivateKey(TypedDict):
    kdf: str
    salt_b64: str
    time_cost: int
    memory_cost_kib: int
    parallelism: int
    sealed_priv_b64: str


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _ub64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def _derive_key(
    password: str,
    salt: bytes,
    time_cost: int = TIME_COST,
    memory_cost_kib: int = MEMORY_COST_KIB,
    parallelism: int = PARALLELISM,
) -> bytes:
    """Derive a 32-byte key from a password via Argon2id."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost_kib,
        parallelism=parallelism,
        hash_len=KEY_SIZE,
        type=Type.ID,
    )


def encrypt_private_key(private_key: bytes, password: str) -> EncryptedPrivateKey:
    """Encrypt a private key at rest under a fresh, password-derived Argon2id key."""
    salt = nacl_random(SALT_SIZE)
    key = _derive_key(password, salt)
    sealed = SecretBox(key).encrypt(private_key)

    return {
        "kdf": "argon2id",
        "salt_b64": _b64(salt),
        "time_cost": TIME_COST,
        "memory_cost_kib": MEMORY_COST_KIB,
        "parallelism": PARALLELISM,
        "sealed_priv_b64": _b64(sealed),
    }


def decrypt_private_key(record: EncryptedPrivateKey, password: str) -> bytes:
    """
    Decrypt a private key at rest. Raises BadTagError on a wrong password —
    the AEAD tag failing to authenticate *is* the password check.
    """
    if record["kdf"] != "argon2id":
        raise ValueError(f"unsupported kdf: {record['kdf']!r}")

    salt = _ub64(record["salt_b64"])
    key = _derive_key(
        password,
        salt,
        time_cost=record["time_cost"],
        memory_cost_kib=record["memory_cost_kib"],
        parallelism=record["parallelism"],
    )
    try:
        return SecretBox(key).decrypt(_ub64(record["sealed_priv_b64"]))
    except _NaclCryptoError as exc:
        raise BadTagError("wrong password") from exc


def hash_password(password: str) -> str:
    """Argon2id verifier for the AWS KMS provider — no decryption key involved,
    just standard password hashing (unlike encrypt_private_key above, which
    uses Argon2id as a KDF, not a verifier)."""
    return _password_hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Check a password against a hash_password() verifier. Never raises on mismatch."""
    try:
        _password_hasher.verify(hashed, password)
        return True
    except VerifyMismatchError:
        return False
