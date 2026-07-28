"""
Unit test for app.db.as_utc — guards against a real pymongo quirk our fake
test collections don't naturally reproduce: MongoDB always stores datetimes
as UTC, but PyMongo/Motor return them *naive* (no tzinfo) on read. Without
reattaching UTC explicitly, the API would serialize a timezone-less ISO
timestamp, which browsers misinterpret as local time instead of UTC.
"""
from datetime import datetime, timezone

from app.db import as_utc


def test_as_utc_attaches_utc_tzinfo_to_naive_datetime():
    naive = datetime(2026, 7, 22, 10, 45, 21, 845000)
    fixed = as_utc(naive)
    assert fixed.tzinfo == timezone.utc
    assert fixed.isoformat() == "2026-07-22T10:45:21.845000+00:00"


def test_as_utc_serializes_with_explicit_offset():
    """The whole point: JSON output must include a Z/offset so `new Date(...)`
    in the browser parses it as UTC, not local time."""
    from app.models.container import SubmissionListItem

    naive = datetime(2026, 7, 22, 10, 45, 21, 845000)
    item = SubmissionListItem(id="x", created_at=as_utc(naive), masked_preview="XXXX-XXXX-5615")
    assert "Z" in item.model_dump_json() or "+00:00" in item.model_dump_json()
