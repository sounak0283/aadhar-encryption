"""
admins_service.py
Multi-admin directory backed by MongoDB's `admins` collection. Replaces the
old single-file admin_identity.json model — every admin (master or sub) is
a document here, keyed by a unique username:

{
  "_id": ObjectId,
  "username": str,
  "role": "master" | "sub",
  "status": "active" | "disabled",
  "public_key_b64": str,
  "encrypted_private_key": {...},   # local provider Argon2id blob
  "totp_secret_encrypted": str,
  "created_at": datetime,
  "created_by": str | None,          # creator's admin id, None for the master
}

The sender's Ed25519 signing identity is *not* stored here — it's one
server-wide identity, unrelated to how many admin accounts exist (see
app/services/admin_identity_service.py).
"""
from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId

from app import db


class UsernameTakenError(Exception):
    """Raised when the requested username is already in use."""


async def get_by_username(username: str) -> dict | None:
    return await db.admins_collection().find_one({"username": username})


async def get_by_id(admin_id: str) -> dict | None:
    try:
        object_id = ObjectId(admin_id)
    except InvalidId:
        return None
    return await db.admins_collection().find_one({"_id": object_id})


async def list_all() -> list[dict]:
    docs = []
    async for doc in db.admins_collection().find().sort("created_at", 1):
        docs.append(doc)
    return docs


async def list_active() -> list[dict]:
    """Full documents for every active admin — what submission_service needs so it
    can wrap a new DEK through *each admin's own* identity provider (local vs
    KMS wrap differently; a plain {admin_id: public_key} map would lose that)."""
    docs = []
    async for doc in db.admins_collection().find({"status": "active"}):
        docs.append(doc)
    return docs


async def create(doc: dict) -> str:
    """Raises UsernameTakenError if the username is already in use."""
    if await get_by_username(doc["username"]) is not None:
        raise UsernameTakenError(doc["username"])
    full_doc = {**doc, "created_at": datetime.now(timezone.utc)}
    result = await db.admins_collection().insert_one(full_doc)
    return str(result.inserted_id)


async def any_admin_exists() -> bool:
    return await db.admins_collection().find_one({}) is not None
