"""
migrate_to_multi_admin.py
One-time migration from the old single-file admin model (backend/secrets/
admin_identity.json, one admin, container docs with a single wrapped_dek_b64)
to the new multi-admin model (MongoDB `admins` collection, container docs
with a wrapped_deks map keyed by admin id).

What it does, in order:
  1. Refuses if the `admins` collection already has anything in it (safety —
     this migration is meant to run exactly once, against a database that
     predates multi-admin support).
  2. Reads the existing admin_identity.json, asks for a username to attach
     to it, and inserts it into `admins` as the master admin. The file
     itself is left untouched on disk — this is purely additive.
  3. Finds every container document still in the old shape (a top-level
     "wrapped_dek_b64" string field instead of "wrapped_deks") and rewrites
     it: the single wrapped key becomes a one-entry wrapped_deks map keyed
     by the new master admin's id, alg is bumped to the current version,
     and the signature is recomputed (it now covers wrapped_deks instead of
     wrapped_dek_b64) using the existing sender signing key — no admin
     password or private key is needed for this step, since the wrapped
     ciphertext itself doesn't change, only how it's addressed and signed.

Usage:
    python scripts/migrate_to_multi_admin.py
"""
import base64
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import get_mongo_db_name, get_mongo_uri  # noqa: E402
from app.crypto import envelope, identity  # noqa: E402
from app.services import admin_identity_service  # noqa: E402

OLD_IDENTITY_PATH = Path(__file__).resolve().parent.parent / "secrets" / "admin_identity.json"


def main() -> None:
    import pymongo

    client = pymongo.MongoClient(get_mongo_uri())
    db = client[get_mongo_db_name()]
    admins_collection = db["admins"]
    containers_collection = db["containers"]

    if admins_collection.find_one({}) is not None:
        print("The `admins` collection already has entries — this migration has already run (or multi-admin")
        print("was set up fresh). Refusing to run again to avoid creating a duplicate admin.")
        raise SystemExit(1)

    if not OLD_IDENTITY_PATH.exists():
        print(f"No old-format identity found at {OLD_IDENTITY_PATH} — nothing to migrate.")
        raise SystemExit(1)

    old_identity = json.loads(OLD_IDENTITY_PATH.read_text())
    if old_identity.get("key_provider") != "local":
        print(f"Only the local provider is supported by this migration (found {old_identity.get('key_provider')!r}).")
        raise SystemExit(1)

    print(f"Found existing admin identity at {OLD_IDENTITY_PATH}.")
    while True:
        # .strip("﻿") too: piping input on Windows (e.g. `"admin" | python script.py`)
        # can prepend a UTF-8 BOM to the first line, which plain .strip() doesn't remove.
        username = input("Username to assign to this existing admin (min 3 characters): ").strip().strip("﻿")
        if len(username) >= 3:
            break
        print("  Too short, try again.")

    admin_doc = {
        "username": username,
        "role": "master",
        "status": "active",
        "key_provider": "local",
        "public_key_b64": old_identity["public_key_b64"],
        "encrypted_private_key": old_identity["encrypted_private_key"],
        "totp_secret_encrypted": old_identity["totp_secret_encrypted"],
        "created_by": None,
        "created_at": datetime.now(timezone.utc),
    }
    result = admins_collection.insert_one(admin_doc)
    admin_id = str(result.inserted_id)
    print(f"Created master admin {username!r} (id {admin_id}).")

    sender_signing_key = admin_identity_service.load_sender_signing_key()

    migrated = 0
    skipped = 0
    for doc in containers_collection.find({"wrapped_dek_b64": {"$exists": True}}):
        wrapped_deks = {admin_id: doc["wrapped_dek_b64"]}
        payload = envelope.signing_payload(wrapped_deks, doc["sealed_number_b64"])
        new_signature_b64 = base64.b64encode(identity.sign(payload, sender_signing_key)).decode("ascii")

        containers_collection.update_one(
            {"_id": doc["_id"]},
            {
                "$set": {"alg": envelope.ALG, "wrapped_deks": wrapped_deks, "signature_b64": new_signature_b64},
                "$unset": {"wrapped_dek_b64": ""},
            },
        )
        migrated += 1

    already_new = containers_collection.count_documents({"wrapped_deks": {"$exists": True}}) - migrated
    if already_new:
        skipped = already_new

    print(f"Migrated {migrated} container(s) to the new wrapped_deks format.")
    if skipped:
        print(f"({skipped} container(s) were already in the new format — left untouched.)")
    print(
        f"\n{OLD_IDENTITY_PATH} was left on disk untouched as a backup — "
        "safe to delete once you've confirmed login works with the new username."
    )
    print("Migration complete.\n")


if __name__ == "__main__":
    main()
