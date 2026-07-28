"""
audit_service.py
Records who/when/what-happened for every admin decrypt action — never the
plaintext itself. Phase 3: plain append-only entries. Phase 4 adds
hash-chaining on top of this for tamper-evidence.
"""
from datetime import datetime, timezone

from app import db


async def record_decrypt(container_id: str, result: str, admin_username: str) -> None:
    await db.audit_log_collection().insert_one(
        {
            "ts": datetime.now(timezone.utc),
            "container_id": container_id,
            "action": "decrypt",
            "result": result,
            "admin_username": admin_username,
        }
    )
