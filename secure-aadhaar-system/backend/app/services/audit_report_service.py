"""
audit_report_service.py
Date-range audit report for admins: one row per *hit* on an Aadhaar
record — every submit and every decrypt attempt against it, each with its
own real timestamp — within [from_date, to_date], PLUS one placeholder row
for every date in that range with zero hits, so a reviewer can see there's
no gap in coverage, not just an absence of rows. Sourced from audit_log
(app.services.audit_service), not just each container's one-time
created_at, so a record that's later decrypted five times shows five rows,
not one. Every field here is already-masked/non-secret metadata
(masked_aadhaar_no, reference_id, timestamps) — this never touches
wrapped_deks, sealed_number_b64, or any key material.
"""
from collections import defaultdict
from datetime import date, datetime, time, timedelta, timezone

from app import db

_REPORTABLE_ACTIONS = ("submit", "decrypt")


class InvalidDateRangeError(Exception):
    """Raised when from_date is after to_date."""


async def generate_report(from_date: date, to_date: date) -> list[dict]:
    if from_date > to_date:
        raise InvalidDateRangeError(f"from_date {from_date} is after to_date {to_date}")

    range_start = datetime.combine(from_date, time.min, tzinfo=timezone.utc)
    range_end = datetime.combine(to_date, time.max, tzinfo=timezone.utc)

    events = [
        doc
        async for doc in db.audit_log_collection().find({"ts": {"$gte": range_start, "$lte": range_end}})
    ]
    events = [e for e in events if e.get("action") in _REPORTABLE_ACTIONS and e.get("container_id")]
    events.sort(key=lambda e: db.as_utc(e["ts"]))

    masked_preview_by_ref: dict[str, str | None] = {}
    for reference_id in {e["container_id"] for e in events}:
        container = await db.containers_collection().find_one({"reference_id": reference_id})
        masked_preview_by_ref[reference_id] = container["masked_preview"] if container else None

    by_date: dict[date, list[dict]] = defaultdict(list)
    for event in events:
        ts = db.as_utc(event["ts"])
        by_date[ts.date()].append(event)

    rows: list[dict] = []
    current = from_date
    while current <= to_date:
        entries = by_date.get(current, [])
        if not entries:
            rows.append(
                {
                    "date": current.isoformat(),
                    "reference_id": None,
                    "masked_aadhaar_no": None,
                    "request_datetime": None,
                }
            )
        else:
            for event in entries:
                reference_id = event["container_id"]
                rows.append(
                    {
                        "date": current.isoformat(),
                        "reference_id": reference_id,
                        "masked_aadhaar_no": masked_preview_by_ref.get(reference_id),
                        "request_datetime": db.as_utc(event["ts"]),
                    }
                )
        current += timedelta(days=1)

    return rows
