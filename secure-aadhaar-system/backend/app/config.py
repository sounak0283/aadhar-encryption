"""
config.py
Minimal environment configuration. Expanded in later phases (Mongo URI, etc.)
"""
import base64
import os

from dotenv import load_dotenv

load_dotenv()


def get_app_totp_key() -> bytes:
    """32-byte key used to encrypt/decrypt the admin's TOTP secret at rest.

    This is a server-side operational secret (like the sender signing key),
    not derived from the admin's password — TOTP verification happens
    independently of, and before, the password-derived private-key unlock.
    """
    raw = os.getenv("APP_TOTP_KEY")
    if raw is None:
        raise EnvironmentError(
            "APP_TOTP_KEY not set. Create a .env file with APP_TOTP_KEY=<32-byte base64 key> "
            "(generate one with: python -c \"import nacl.utils, base64; "
            "print(base64.b64encode(nacl.utils.random(32)).decode())\")"
        )
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise EnvironmentError("APP_TOTP_KEY must be valid base64.") from exc
    if len(key) != 32:
        raise EnvironmentError("APP_TOTP_KEY must decode to exactly 32 bytes.")
    return key


def get_mongo_uri() -> str:
    return os.getenv("MONGO_URI", "mongodb://localhost:27017")


def get_mongo_db_name() -> str:
    return os.getenv("MONGO_DB_NAME", "secure_aadhaar")


def get_frontend_origin() -> str:
    return os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")


def get_admin_key_provider() -> str:
    """Which kind of admin identity bootstrap tooling should create: "local" or "aws-kms".

    Not read by the running API itself — the runtime always defers to the
    "key_provider" field already stored in admin_identity.json (see
    app/providers/identity_provider.py). This is only a bootstrap-time input.
    """
    return os.getenv("ADMIN_KEY_PROVIDER", "local")


def get_aws_kms_key_id() -> str | None:
    """ARN or key ID of the admin identity's AWS KMS key, if ADMIN_KEY_PROVIDER=aws-kms.

    Only used by bootstrap tooling. AWS auth/region are read directly by
    boto3/botocore from the standard AWS_* environment variables or an
    AWS_PROFILE — this project does not wrap or re-derive them.
    """
    return os.getenv("AWS_KMS_KEY_ID") or None


def get_admin_setup_token() -> str:
    """
    Shared secret required to start admin self-registration via the web UI
    (POST /api/admin/register/start). Without this, anyone who reaches an
    unconfigured deployment before the real operator does could register
    themselves as the permanent admin — this closes that race. Not needed
    for scripts/bootstrap_admin.py, which already requires shell access.
    """
    token = os.getenv("ADMIN_SETUP_TOKEN")
    if not token:
        raise EnvironmentError(
            "ADMIN_SETUP_TOKEN not set. Required before the web admin-registration endpoint "
            "can be used. Create a .env file with ADMIN_SETUP_TOKEN=<a long random string> "
            "(generate one with: python -c \"import secrets; print(secrets.token_urlsafe(32))\")"
        )
    return token
