"""
audit_service.py
Records who/when/what for every security-relevant action — admin and user
logins/logouts, Aadhaar submissions, and admin decrypt attempts — never the
plaintext Aadhaar number itself. Phase 3: plain append-only entries. Phase 4
adds hash-chaining on top of this for tamper-evidence.
"""
from datetime import date, datetime, time, timezone

from app import db


async def _record(action: str, result: str, username: str | None, container_id: str | None = None) -> None:
    await db.audit_log_collection().insert_one(
        {
            "ts": datetime.now(timezone.utc),
            "action": action,
            "result": result,
            "username": username,
            "container_id": container_id,
        }
    )


async def record_decrypt(container_id: str, result: str, admin_username: str) -> None:
    # Keeps the historical "admin_username" key (asserted on directly by
    # existing tests) alongside the common "username" key the other event
    # types use, so a single audit_log query can list everything uniformly.
    await db.audit_log_collection().insert_one(
        {
            "ts": datetime.now(timezone.utc),
            "container_id": container_id,
            "action": "decrypt",
            "result": result,
            "admin_username": admin_username,
            "username": admin_username,
        }
    )


async def record_admin_login(username: str, result: str) -> None:
    await _record("admin_login", result, username)


async def record_admin_logout(username: str) -> None:
    await _record("admin_logout", "success", username)


async def record_user_login(username: str, result: str) -> None:
    await _record("user_login", result, username)


async def record_user_logout(username: str) -> None:
    await _record("user_logout", "success", username)


async def record_submit(username: str, result: str, container_id: str | None = None) -> None:
    await _record("submit", result, username, container_id)


async def list_events(from_date: date, to_date: date) -> list[dict]:
    """All audit-log events with a timestamp within [from_date, to_date] (inclusive,
    UTC calendar days), newest first."""
    range_start = datetime.combine(from_date, time.min, tzinfo=timezone.utc)
    range_end = datetime.combine(to_date, time.max, tzinfo=timezone.utc)

    events = [
        {
            "ts": db.as_utc(doc["ts"]),
            "action": doc["action"],
            "result": doc["result"],
            "username": doc.get("username"),
            "container_id": doc.get("container_id"),
        }
        async for doc in db.audit_log_collection().find({"ts": {"$gte": range_start, "$lte": range_end}})
    ]
    events.sort(key=lambda event: event["ts"], reverse=True)
    return events
