"""
admin_management_service.py
Master-only sub-admin creation. Mirrors admin_registration_service.py's
two-step start/confirm flow, but gated by an authenticated master session
(the caller's admin_id and unlocked_identity) instead of the setup token,
and creates role="sub" admins.

confirm() also retroactively re-wraps every existing container so the new
sub-admin can decrypt records submitted before they existed: each
container's DEK is unwrapped once using the *master's* own entry in that
container's wrapped_deks map (via the master's already-unlocked session
key), then re-wrapped for the new admin too, and the container is re-signed
— the signature covers the whole wrapped_deks map, so adding an entry
changes what must be signed. Idempotent: a container that already has an
entry for the new admin's id is skipped, so a partially-failed re-wrap run
is always safe to simply re-run.
"""
import base64
import secrets
import time
from dataclasses import dataclass, field

from app import db
from app.config import get_app_totp_key
from app.crypto import envelope, identity, password_utils, totp_utils
from app.crypto.password_utils import EncryptedPrivateKey
from app.providers.identity_provider import UnlockedIdentity
from app.services import admin_identity_service, admins_service

PENDING_TTL_SECONDS = 10 * 60
MIN_PASSWORD_LENGTH = 12
MIN_USERNAME_LENGTH = 3


class UsernameTakenError(Exception):
    """Raised when the requested sub-admin username is already in use."""


class RegistrationNotFoundError(Exception):
    """Raised when a registration_token is unknown, expired, or belongs to a different master."""


class WeakPasswordError(Exception):
    """Raised when the submitted password is too short."""


class InvalidUsernameError(Exception):
    """Raised when the submitted username is too short."""


@dataclass
class PendingSubAdmin:
    username: str
    master_admin_id: str
    encrypted_private_key: EncryptedPrivateKey
    admin_public_key: bytes
    totp_secret: str
    expires_at: float = field(default_factory=lambda: time.monotonic() + PENDING_TTL_SECONDS)

    def is_expired(self) -> bool:
        return time.monotonic() >= self.expires_at


_pending: dict[str, PendingSubAdmin] = {}


def _sweep_expired() -> None:
    expired = [token for token, p in _pending.items() if p.is_expired()]
    for token in expired:
        del _pending[token]


async def start(master_admin_id: str, username: str, password: str) -> tuple[str, str, str, str]:
    """Returns (registration_token, otpauth_uri, manual_secret, qr_code_png_base64)."""
    if len(username) < MIN_USERNAME_LENGTH:
        raise InvalidUsernameError(f"username must be at least {MIN_USERNAME_LENGTH} characters")
    if await admins_service.get_by_username(username) is not None:
        raise UsernameTakenError(username)
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")

    _sweep_expired()

    admin_private_key, admin_public_key = identity.generate_encryption_keypair()
    encrypted_private_key = password_utils.encrypt_private_key(admin_private_key, password)
    del admin_private_key

    totp_secret = totp_utils.generate_totp_secret()
    otpauth_uri = totp_utils.provisioning_uri(totp_secret, account_name=username)
    qr_code_png_base64 = totp_utils.qr_code_png_base64(otpauth_uri)

    registration_token = secrets.token_urlsafe(32)
    _pending[registration_token] = PendingSubAdmin(
        username=username,
        master_admin_id=master_admin_id,
        encrypted_private_key=encrypted_private_key,
        admin_public_key=admin_public_key,
        totp_secret=totp_secret,
    )
    return registration_token, otpauth_uri, totp_secret, qr_code_png_base64


async def confirm(
    master_admin_id: str,
    master_unlocked_identity: UnlockedIdentity,
    registration_token: str,
    totp_code: str,
) -> tuple[str, int]:
    """Returns (new_admin_id, containers_granted_count)."""
    _sweep_expired()
    pending = _pending.get(registration_token)
    if pending is None or pending.master_admin_id != master_admin_id:
        # Wrong-master check is defense in depth: the token itself is unguessable,
        # but a session shouldn't be able to confirm a different master's pending
        # sub-admin even if it somehow got hold of the token.
        raise RegistrationNotFoundError("unknown or expired registration")

    if not totp_utils.verify_totp_code(pending.totp_secret, totp_code):
        raise ValueError("invalid TOTP code")

    new_admin_id = await admins_service.create(
        {
            "username": pending.username,
            "role": "sub",
            "status": "active",
            "key_provider": "local",
            "public_key_b64": base64.b64encode(pending.admin_public_key).decode("ascii"),
            "encrypted_private_key": pending.encrypted_private_key,
            "totp_secret_encrypted": totp_utils.encrypt_totp_secret(pending.totp_secret, get_app_totp_key()),
            "created_by": master_admin_id,
        }
    )
    del _pending[registration_token]

    granted = await _grant_retroactive_access(
        master_admin_id, master_unlocked_identity, new_admin_id, pending.admin_public_key
    )
    return new_admin_id, granted


async def _grant_retroactive_access(
    master_admin_id: str,
    master_unlocked_identity: UnlockedIdentity,
    new_admin_id: str,
    new_admin_public_key: bytes,
) -> int:
    """Re-wrap every existing container's DEK for the new admin too, and re-sign.
    Idempotent — skips any container that already has an entry for new_admin_id.
    Returns how many containers were updated."""
    sender_signing_key = admin_identity_service.load_sender_signing_key()
    updated = 0

    async for doc in db.containers_collection().find():
        wrapped_deks = doc["wrapped_deks"]
        if new_admin_id in wrapped_deks:
            continue

        master_wrapped_dek_b64 = wrapped_deks.get(master_admin_id)
        if master_wrapped_dek_b64 is None:
            continue  # master itself has no access to this record — skip defensively

        dek = master_unlocked_identity.unwrap_dek(master_wrapped_dek_b64)
        new_wrapped_dek_b64 = base64.b64encode(envelope.seal_dek(dek, new_admin_public_key)).decode("ascii")
        del dek

        wrapped_deks = {**wrapped_deks, new_admin_id: new_wrapped_dek_b64}
        payload = envelope.signing_payload(wrapped_deks, doc["sealed_number_b64"])
        new_signature_b64 = base64.b64encode(identity.sign(payload, sender_signing_key)).decode("ascii")

        await db.containers_collection().update_one(
            {"_id": doc["_id"]},
            {"$set": {"wrapped_deks": wrapped_deks, "signature_b64": new_signature_b64}},
        )
        updated += 1

    return updated


def reset() -> None:
    """Test-only: clear all pending sub-admin registrations. Not used by the app itself."""
    _pending.clear()
