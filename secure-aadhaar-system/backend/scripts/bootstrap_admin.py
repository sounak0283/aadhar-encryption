"""
bootstrap_admin.py
One-time setup script: generates the sender signing identity and the first
("master") admin, sets their username + password, and sets up TOTP MFA.
Which kind of admin identity gets created is controlled by ADMIN_KEY_PROVIDER
in .env ("local" or "aws-kms") — see .env.example.

The master admin is written into MongoDB's `admins` collection (via sync
pymongo — this script has no async runtime of its own). Every admin after
the master is created through the web UI's "create sub-admin" flow by a
logged-in master, not through this script — see
app/services/admin_management_service.py.

Run once, before the API server starts. Refuses to run at all if any admin
already exists — there is deliberately no --force here, since a second
master would need real thought (see scripts/migrate_to_multi_admin.py for
the one-time migration path from the old single-file model instead).

Usage:
    python scripts/bootstrap_admin.py
"""
import base64
import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_admin_key_provider, get_app_totp_key, get_aws_kms_key_id, get_mongo_db_name, get_mongo_uri  # noqa: E402
from app.crypto import identity, password_utils, totp_utils  # noqa: E402
from app.services import admin_identity_service  # noqa: E402

MIN_PASSWORD_LENGTH = 12
MIN_USERNAME_LENGTH = 3


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _prompt_username(admins_collection) -> str:
    while True:
        # .strip("﻿") too: piping input on Windows can prepend a UTF-8 BOM that
        # plain .strip() doesn't remove.
        username = input(f"Set admin username (min {MIN_USERNAME_LENGTH} characters): ").strip().strip("﻿")
        if len(username) < MIN_USERNAME_LENGTH:
            print(f"  Username must be at least {MIN_USERNAME_LENGTH} characters.")
            continue
        if admins_collection.find_one({"username": username}) is not None:
            print("  That username is already taken.")
            continue
        return username


def _prompt_password() -> str:
    while True:
        password = getpass.getpass(f"Set admin password (min {MIN_PASSWORD_LENGTH} characters): ")
        if len(password) < MIN_PASSWORD_LENGTH:
            print(f"  Password must be at least {MIN_PASSWORD_LENGTH} characters.")
            continue
        confirm = getpass.getpass("Confirm password: ")
        if password != confirm:
            print("  Passwords did not match, try again.")
            continue
        return password


def _prompt_totp_confirmation(secret: str, username: str) -> None:
    uri = totp_utils.provisioning_uri(secret, account_name=username)
    print("\nScan this into an authenticator app (Google Authenticator, 1Password, etc.):")
    print(f"  {uri}\n")
    try:
        import qrcode

        qr = qrcode.QRCode(border=1)
        qr.add_data(uri)
        qr.make()
        qr.print_ascii(invert=True)
    except Exception:
        print("  (QR rendering unavailable in this terminal — use the URI/secret below instead.)")
    print(f"  Manual entry secret: {secret}\n")

    while True:
        code = input("Enter the 6-digit code from your authenticator app to confirm setup: ").strip()
        if totp_utils.verify_totp_code(secret, code):
            print("  TOTP confirmed.\n")
            return
        print("  Code did not match, try again (check your device's clock is in sync).")


def _bootstrap_local(password: str) -> dict:
    print("Generating admin encryption identity (X25519, local provider)...")
    admin_private_key, admin_public_key = identity.generate_encryption_keypair()
    encrypted_private_key = password_utils.encrypt_private_key(admin_private_key, password)
    del admin_private_key
    return {
        "key_provider": "local",
        "public_key_b64": _b64(admin_public_key),
        "encrypted_private_key": encrypted_private_key,
    }


def _bootstrap_aws_kms(password: str) -> dict:
    """
    References an *existing* KMS key (ECC_NIST_P256, KeyUsage=KEY_AGREEMENT) —
    this script does not create one. See README / chat history for the
    `aws kms create-key` command. NOT YET VERIFIED against a real KMS
    endpoint; see app/crypto/kms_provider.py's module docstring.
    """
    key_id = get_aws_kms_key_id()
    if not key_id:
        print("ADMIN_KEY_PROVIDER=aws-kms requires AWS_KMS_KEY_ID to be set (see .env.example).")
        raise SystemExit(1)

    import boto3  # local import: no hard boto3 dependency for local-only bootstraps

    print(f"Connecting to AWS KMS key {key_id}...")
    kms = boto3.client("kms")
    metadata = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    if metadata.get("KeySpec") != "ECC_NIST_P256" or metadata.get("KeyUsage") != "KEY_AGREEMENT":
        print(
            f"KMS key {key_id} must be KeySpec=ECC_NIST_P256, KeyUsage=KEY_AGREEMENT "
            f"(found KeySpec={metadata.get('KeySpec')!r}, KeyUsage={metadata.get('KeyUsage')!r})."
        )
        raise SystemExit(1)

    public_key_der = kms.get_public_key(KeyId=key_id)["PublicKey"]
    print("KMS key verified — the private key never leaves AWS KMS.")

    return {
        "key_provider": "aws-kms",
        "public_key_b64": _b64(public_key_der),
        "kms_key_arn": metadata["Arn"],
        "password_hash": password_utils.hash_password(password),
    }


def main() -> None:
    import pymongo

    client = pymongo.MongoClient(get_mongo_uri())
    admins_collection = client[get_mongo_db_name()]["admins"]

    if admins_collection.find_one({}) is not None:
        print("An admin already exists in the database. This script only ever creates the first (master) admin.")
        print("To add another admin, log in as master and use the web UI's \"create sub-admin\" flow instead.")
        raise SystemExit(1)

    # Fail fast, before generating any key material, if the server secret isn't configured.
    app_totp_key = get_app_totp_key()
    key_provider = get_admin_key_provider()
    if key_provider not in ("local", "aws-kms"):
        print(f"Unknown ADMIN_KEY_PROVIDER={key_provider!r}; expected 'local' or 'aws-kms'.")
        raise SystemExit(1)

    print("Generating sender signing identity (Ed25519)...")
    sender_signing_key, _sender_verify_key = identity.generate_signing_keypair()

    username = _prompt_username(admins_collection)
    password = _prompt_password()
    admin_doc = _bootstrap_local(password) if key_provider == "local" else _bootstrap_aws_kms(password)
    del password

    admin_doc["username"] = username
    admin_doc["role"] = "master"
    admin_doc["status"] = "active"
    admin_doc["created_by"] = None

    print("\nSetting up TOTP (MFA)...")
    totp_secret = totp_utils.generate_totp_secret()
    _prompt_totp_confirmation(totp_secret, username)
    admin_doc["totp_secret_encrypted"] = totp_utils.encrypt_totp_secret(totp_secret, app_totp_key)
    del totp_secret

    admin_identity_service.write_sender_signing_key(sender_signing_key)
    del sender_signing_key

    admin_doc["created_at"] = datetime.now(timezone.utc)
    result = admins_collection.insert_one(admin_doc)

    print(f"Wrote sender signing key to {admin_identity_service.SENDER_KEY_PATH}")
    print(f"Created master admin {username!r} (id {result.inserted_id}) in MongoDB.")
    print(
        "\nIMPORTANT: sender_signing_key.b64 is a server secret, not an admin secret. "
        "In production, move it into a secrets manager / env var and delete it from disk — "
        "it must never be committed to version control (see backend/.gitignore)."
    )
    print("Bootstrap complete.\n")


if __name__ == "__main__":
    main()
