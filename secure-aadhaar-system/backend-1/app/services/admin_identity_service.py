"""
admin_identity_service.py
Loads the server's sender signing identity — one Ed25519 keypair for the
whole deployment, unrelated to how many admin accounts exist (that's
app/services/admins_service.py, Mongo-backed). Still file-based:
backend/secrets/sender_signing_key.b64, written once by bootstrap_admin.py
or the first admin registration, or overridden via SENDER_SIGNING_KEY_B64.
"""
import base64
import os
from functools import lru_cache
from pathlib import Path

from app.crypto import identity

SECRETS_DIR = Path(__file__).resolve().parent.parent.parent / "secrets"
SENDER_KEY_PATH = SECRETS_DIR / "sender_signing_key.b64"


class SenderKeyNotBootstrapped(Exception):
    """Raised when no sender signing key exists yet (first admin hasn't been created)."""


@lru_cache(maxsize=1)
def load_sender_signing_key() -> bytes:
    env_value = os.getenv("SENDER_SIGNING_KEY_B64")
    if env_value:
        return base64.b64decode(env_value)
    if not SENDER_KEY_PATH.exists():
        raise SenderKeyNotBootstrapped(
            f"No sender signing key found at {SENDER_KEY_PATH}. Run `python scripts/bootstrap_admin.py` "
            "or complete admin registration first."
        )
    return base64.b64decode(SENDER_KEY_PATH.read_text())


def load_sender_verify_key() -> bytes:
    """The sender's public verify key, derived on the fly — never stored separately."""
    return identity.verify_key_from_signing_key(load_sender_signing_key())


def write_sender_signing_key(sender_signing_key: bytes) -> None:
    """Persist a newly generated sender signing key. Refuses to overwrite an existing
    one — callers are responsible for only calling this once, at first-admin creation."""
    SECRETS_DIR.mkdir(exist_ok=True)
    SENDER_KEY_PATH.write_text(base64.b64encode(sender_signing_key).decode("ascii"))
    load_sender_signing_key.cache_clear()


def sender_key_exists() -> bool:
    return bool(os.getenv("SENDER_SIGNING_KEY_B64")) or SENDER_KEY_PATH.exists()
