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
  "unique_reference_no": str,   # short per-PERSON audit code, distinct from a
                                 # container's reference_id (which is per-Aadhaar-
                                 # number). Assigned once, at signup, permanent.
}
"""
import secrets
import string
from datetime import datetime, timezone

from bson import ObjectId
from bson.errors import InvalidId

from app import db

_REF_NO_ALPHABET = "".join(c for c in string.ascii_uppercase + string.digits if c not in "0O1I")
_REF_NO_LENGTH = 8


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


async def _generate_unique_reference_no() -> str:
    """Short, human-readable, per-person audit code (e.g. "ABC1XY9Z").
    Excludes visually ambiguous characters (0/O, 1/I). Collisions are
    astronomically unlikely at 32^8, but checked and retried anyway since
    this is used as an audit identifier, not a cryptographic key."""
    while True:
        candidate = "".join(secrets.choice(_REF_NO_ALPHABET) for _ in range(_REF_NO_LENGTH))
        if await db.users_collection().find_one({"unique_reference_no": candidate}) is None:
            return candidate


async def create(username: str, password_hash: str) -> str:
    """Raises UsernameTakenError if the username is already in use."""
    if await get_by_username(username) is not None:
        raise UsernameTakenError(username)
    doc = {
        "username": username,
        "password_hash": password_hash,
        "status": "active",
        "created_at": datetime.now(timezone.utc),
        "unique_reference_no": await _generate_unique_reference_no(),
    }
    result = await db.users_collection().insert_one(doc)
    return str(result.inserted_id)
