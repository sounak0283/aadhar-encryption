"""
totp_utils.py
TOTP (RFC 6238) secret generation/verification for admin MFA, and encryption
of the TOTP secret at rest under a server-side application key — not the
admin's password, since TOTP is a second, independent factor checked before
the password-derived private-key unlock even begins.
"""
import base64
import io

import pyotp
import qrcode
from nacl.secret import SecretBox
from nacl.exceptions import CryptoError as _NaclCryptoError

from .exceptions import BadTagError


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _ub64(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def generate_totp_secret() -> str:
    """Generate a new random base32 TOTP secret."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, account_name: str, issuer: str = "Secure Aadhaar System") -> str:
    """Build an otpauth:// URI for scanning into an authenticator app."""
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=issuer)


def qr_code_png_base64(uri: str) -> str:
    """Render a provisioning URI as a base64-encoded PNG, for the browser to show directly
    as <img src={`data:image/png;base64,${value}`} /> — no QR library needed on the frontend.

    Uses qrcode's dependency-free PyPNGImage backend (no Pillow installed), whose
    save() always writes PNG and doesn't accept a format= kwarg the way PIL-backed
    images do.
    """
    buffer = io.BytesIO()
    qrcode.make(uri).save(buffer)
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def verify_totp_code(secret: str, code: str) -> bool:
    """Check a 6-digit TOTP code against the secret, allowing one 30s step of clock drift."""
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def encrypt_totp_secret(secret: str, app_key: bytes) -> str:
    """Encrypt the TOTP secret at rest under the server's application key."""
    sealed = SecretBox(app_key).encrypt(secret.encode("utf-8"))
    return _b64(sealed)


def decrypt_totp_secret(sealed_b64: str, app_key: bytes) -> str:
    """Decrypt the TOTP secret. Raises BadTagError if app_key is wrong or the data was tampered."""
    try:
        return SecretBox(app_key).decrypt(_ub64(sealed_b64)).decode("utf-8")
    except _NaclCryptoError as exc:
        raise BadTagError("failed to decrypt TOTP secret: wrong app key or tampered data") from exc
