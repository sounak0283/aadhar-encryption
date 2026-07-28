"""
users_service.py
Regular (non-admin) user accounts backed by MongoDB's `users` collection —
the people submitting Aadhaar numbers, not the admins who decrypt them.
Completely separate from app/services/admins_service.py: a user here holds
no encryption keys and has no decrypt capability at all, so this is just a
plain username/password account:

{
  "_id": ObjectId,
  "username": str,
  "password_hash": str,   # Argon2id verifier, app.crypto.password_utils.hash_password
  "status": "active",
  "created_at": datetime,
}
"""
from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId

from app import db


class UsernameTakenError(Exception):
    """Raised when the requested username is already in use."""


async def get_by_username(username: str) -> dict | None:
    return await db.users_collection().find_one({"username": username})


async def get_by_id(user_id: str) -> dict | None:
    try:
        object_id = ObjectId(user_id)
    except InvalidId:
        return None
    return await db.users_collection().find_one({"_id": object_id})


async def create(username: str, password_hash: str) -> str:
    """Raises UsernameTakenError if the username is already in use."""
    if await get_by_username(username) is not None:
        raise UsernameTakenError(username)
    doc = {
        "username": username,
        "password_hash": password_hash,
        "status": "active",
        "created_at": datetime.now(timezone.utc),
    }
    result = await db.users_collection().insert_one(doc)
    return str(result.inserted_id)
