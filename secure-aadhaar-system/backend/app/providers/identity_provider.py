"""
identity_provider.py
Common interface for admin private-key custody, so the rest of the app
(routers, services) never needs to know whether the admin's private key is
unlocked locally (dev/test) or held inside AWS KMS (production). TOTP
verification is a separate, provider-independent concern handled directly
by the login route, since it applies the same way regardless of which
provider holds the confidentiality key.

Each provider is also responsible for wrapping new DEKs (wrap_dek) and for
naming its own container "alg" — the two providers use genuinely different
wrapping mechanisms (X25519 SealedBox vs. KMS-backed P-256 ECDH), so a
container's alg field is what tells decrypt_service which one produced it.
"""
import base64
from typing import Protocol, runtime_checkable

from app.crypto import envelope, password_utils

LOCAL_ALG = envelope.ALG
KMS_ALG = "kms-ecdh-p256+secretbox-xsalsa20poly1305+ed25519-v3"
SUPPORTED_ALGS = {LOCAL_ALG, KMS_ALG}


@runtime_checkable
class UnlockedIdentity(Protocol):
    def unwrap_dek(self, wrapped_dek_b64: str) -> bytes:
        """Unwrap a message's DEK. Raises BadTagError on wrong key or wrong container."""
        ...

    def close(self) -> None:
        """Best-effort discard of any secret material held for this session."""
        ...


@runtime_checkable
class IdentityProvider(Protocol):
    def alg(self) -> str:
        """The container `alg` value this provider's wrap_dek() produces."""
        ...

    def public_key(self) -> bytes:
        """The admin's public key, safe to use for wrapping new DEKs."""
        ...

    def wrap_dek(self, dek: bytes) -> str:
        """Wrap a DEK to the admin's public key. Returns base64. Needs no unlock."""
        ...

    def unlock(self, password: str) -> UnlockedIdentity:
        """Authenticate the password and return an unlock capability. Raises BadTagError on failure."""
        ...


class LocalUnlockedIdentity:
    """Unlocked state for the local (dev/test) provider: the raw private key, held in app memory."""

    def __init__(self, private_key: bytes):
        self._private_key = private_key

    def unwrap_dek(self, wrapped_dek_b64: str) -> bytes:
        return envelope.unseal_dek(base64.b64decode(wrapped_dek_b64), self._private_key)

    def close(self) -> None:
        self._private_key = b"\x00" * len(self._private_key)


class LocalIdentityProvider:
    """
    Dev/test admin identity provider: X25519 keypair, private key encrypted at
    rest under a password-derived Argon2id key (see app/crypto/password_utils.py).
    """

    def __init__(self, admin_identity: dict):
        self._public_key = base64.b64decode(admin_identity["public_key_b64"])
        self._encrypted_private_key = admin_identity["encrypted_private_key"]

    def alg(self) -> str:
        return LOCAL_ALG

    def public_key(self) -> bytes:
        return self._public_key

    def wrap_dek(self, dek: bytes) -> str:
        wrapped = envelope.seal_dek(dek, self._public_key)
        return base64.b64encode(wrapped).decode("ascii")

    def unlock(self, password: str) -> LocalUnlockedIdentity:
        private_key = password_utils.decrypt_private_key(self._encrypted_private_key, password)
        return LocalUnlockedIdentity(private_key)


def load_identity_provider(admin_identity: dict) -> IdentityProvider:
    """Factory: build the right provider for this admin_identity document's `key_provider`."""
    provider_name = admin_identity.get("key_provider", "local")
    if provider_name == "local":
        return LocalIdentityProvider(admin_identity)
    if provider_name == "aws-kms":
        from app.crypto.kms_provider import KmsIdentityProvider  # lazy: no hard boto3 dependency for local-only setups

        return KmsIdentityProvider(admin_identity)
    raise ValueError(f"unknown key_provider: {provider_name!r}")
