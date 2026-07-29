"""
admin_registration_service.py
Web-based self-registration for the *first* admin ever (the "master") on
the local identity provider (the AWS KMS path stays CLI/ops-only via
scripts/bootstrap_admin.py). Once any admin exists at all, this permanently
refuses — every admin after the first is created by the master through
app/services/admin_management_service.py instead, gated by an authenticated
master session rather than the setup token.

Two-step flow, mirroring bootstrap_admin.py's interactive one:
  1. start(username, password): refuses if any admin already exists. Generates
     a fresh sender signing keypair (this becomes the server's one signing
     identity) and the master's own X25519 keypair and TOTP secret. Encrypts
     the private key with the submitted password immediately (so the
     plaintext password/private key are discarded right away, not held for
     the whole QR-scanning gap), and holds the rest as a short-lived pending
     registration keyed by a random token.
  2. confirm(registration_token, totp_code): verifies the code against the
     pending TOTP secret; on success, writes the sender signing key to disk
     and inserts the master admin document into MongoDB, then discards the
     pending state.

Pending registrations expire after PENDING_TTL_SECONDS so an abandoned
"start" call without a matching "confirm" doesn't linger in memory forever.
"""
import base64
import secrets
import time
from dataclasses import dataclass, field

from app.config import get_app_totp_key
from app.crypto import identity, password_utils, totp_utils
from app.crypto.password_utils import EncryptedPrivateKey
from app.services import admin_identity_service, admins_service

PENDING_TTL_SECONDS = 10 * 60
MIN_PASSWORD_LENGTH = 12
MIN_USERNAME_LENGTH = 3


class AlreadyRegisteredError(Exception):
    """Raised when an admin already exists (of any role)."""


class RegistrationNotFoundError(Exception):
    """Raised when a registration_token is unknown or has expired."""


class WeakPasswordError(Exception):
    """Raised when the submitted password is too short."""


class InvalidUsernameError(Exception):
    """Raised when the submitted username is too short."""


@dataclass
class PendingRegistration:
    username: str
    encrypted_private_key: EncryptedPrivateKey
    admin_public_key: bytes
    sender_signing_key: bytes
    totp_secret: str
    expires_at: float = field(default_factory=lambda: time.monotonic() + PENDING_TTL_SECONDS)

    def is_expired(self) -> bool:
        return time.monotonic() >= self.expires_at


_pending: dict[str, PendingRegistration] = {}


def _sweep_expired() -> None:
    expired = [token for token, p in _pending.items() if p.is_expired()]
    for token in expired:
        del _pending[token]


async def start(username: str, password: str) -> tuple[str, str, str, str]:
    """
    Returns (registration_token, otpauth_uri, manual_secret, qr_code_png_base64).
    Raises AlreadyRegisteredError, InvalidUsernameError, or WeakPasswordError.
    """
    if await admins_service.any_admin_exists():
        raise AlreadyRegisteredError("an admin already exists")
    if len(username) < MIN_USERNAME_LENGTH:
        raise InvalidUsernameError(f"username must be at least {MIN_USERNAME_LENGTH} characters")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")

    _sweep_expired()

    sender_signing_key, _sender_verify_key = identity.generate_signing_keypair()
    admin_private_key, admin_public_key = identity.generate_encryption_keypair()
    encrypted_private_key = password_utils.encrypt_private_key(admin_private_key, password)
    del admin_private_key  # discard immediately; only the encrypted blob is kept from here on

    totp_secret = totp_utils.generate_totp_secret()
    otpauth_uri = totp_utils.provisioning_uri(totp_secret, account_name=username)
    qr_code_png_base64 = totp_utils.qr_code_png_base64(otpauth_uri)

    registration_token = secrets.token_urlsafe(32)
    _pending[registration_token] = PendingRegistration(
        username=username,
        encrypted_private_key=encrypted_private_key,
        admin_public_key=admin_public_key,
        sender_signing_key=sender_signing_key,
        totp_secret=totp_secret,
    )

    return registration_token, otpauth_uri, totp_secret, qr_code_png_base64


async def confirm(registration_token: str, totp_code: str) -> str:
    """Returns the new master admin's id. Raises RegistrationNotFoundError,
    AlreadyRegisteredError, or ValueError (invalid TOTP code)."""
    if await admins_service.any_admin_exists():
        _pending.pop(registration_token, None)
        raise AlreadyRegisteredError("an admin already exists")

    _sweep_expired()
    pending = _pending.get(registration_token)
    if pending is None:
        raise RegistrationNotFoundError("unknown or expired registration")

    if not totp_utils.verify_totp_code(pending.totp_secret, totp_code):
        raise ValueError("invalid TOTP code")

    admin_identity_service.write_sender_signing_key(pending.sender_signing_key)

    admin_id = await admins_service.create(
        {
            "username": pending.username,
            "role": "master",
            "status": "active",
            "key_provider": "local",
            "public_key_b64": base64.b64encode(pending.admin_public_key).decode("ascii"),
            "encrypted_private_key": pending.encrypted_private_key,
            "totp_secret_encrypted": totp_utils.encrypt_totp_secret(pending.totp_secret, get_app_totp_key()),
            "created_by": None,
        }
    )
    del _pending[registration_token]
    return admin_id


def reset() -> None:
    """Test-only: clear all pending registrations. Not used by the app itself."""
    _pending.clear()
