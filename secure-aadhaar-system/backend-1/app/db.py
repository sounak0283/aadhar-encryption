"""
db.py
Async MongoDB client (Motor) and collection accessors. Tests monkeypatch
these collection functions directly rather than requiring a real MongoDB
instance or a third-party async mock.
"""
from datetime import datetime, timezone

from motor.motor_asyncio import AsyncIOMotorClient

from app.config import get_mongo_db_name, get_mongo_uri

_client: AsyncIOMotorClient | None = None


def get_client() -> AsyncIOMotorClient:
    global _client
    if _client is None:
        _client = AsyncIOMotorClient(get_mongo_uri())
    return _client


def get_db():
    return get_client()[get_mongo_db_name()]


def containers_collection():
    return get_db()["containers"]


def audit_log_collection():
    return get_db()["audit_log"]


def admins_collection():
    return get_db()["admins"]


def users_collection():
    return get_db()["users"]


def as_utc(dt: datetime) -> datetime:
    """MongoDB always stores datetimes as UTC internally, but PyMongo/Motor
    return them *naive* (no tzinfo) on read. Reattach UTC explicitly before
    this reaches a Pydantic response model — otherwise it serializes to JSON
    with no offset/Z suffix, and the browser's `new Date(...)` misinterprets
    a timezone-less ISO string as local time instead of UTC."""
    return dt.replace(tzinfo=timezone.utc)
