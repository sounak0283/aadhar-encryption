"""
audit_report_service.py
Date-range submission audit report for admins: one row per submission within
[from_date, to_date], PLUS one placeholder row for every date in that range
that had zero submissions — so a reviewer can see there's no gap in coverage,
not just an absence of rows. Every field here is already-masked/non-secret
metadata (masked_aadhaar_no, reference_id, unique_reference_no, timestamps) —
this never touches wrapped_deks, sealed_number_b64, or any key material.
"""
from collections import defaultdict
from datetime import date, datetime, time, timedelta, timezone

from app import db


class InvalidDateRangeError(Exception):
    """Raised when from_date is after to_date."""


async def generate_report(from_date: date, to_date: date) -> list[dict]:
    if from_date > to_date:
        raise InvalidDateRangeError(f"from_date {from_date} is after to_date {to_date}")

    range_start = datetime.combine(from_date, time.min, tzinfo=timezone.utc)
    range_end = datetime.combine(to_date, time.max, tzinfo=timezone.utc)

    by_date: dict[date, list[dict]] = defaultdict(list)
    async for doc in (
        db.containers_collection().find({"created_at": {"$gte": range_start, "$lte": range_end}}).sort("created_at", 1)
    ):
        created_at = db.as_utc(doc["created_at"])
        by_date[created_at.date()].append(doc)

    rows: list[dict] = []
    current = from_date
    while current <= to_date:
        entries = by_date.get(current, [])
        if not entries:
            rows.append(
                {
                    "date": current.isoformat(),
                    "unique_reference_no": None,
                    "reference_id": None,
                    "masked_aadhaar_no": None,
                    "request_datetime": None,
                }
            )
        else:
            for doc in entries:
                rows.append(
                    {
                        "date": current.isoformat(),
                        "unique_reference_no": doc.get("unique_reference_no"),
                        "reference_id": str(doc["_id"]),
                        "masked_aadhaar_no": doc["masked_preview"],
                        "request_datetime": db.as_utc(doc["created_at"]),
                    }
                )
        current += timedelta(days=1)

    return rows
