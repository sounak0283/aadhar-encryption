"""Unit tests for app.services.audit_pdf_service."""
from datetime import date, datetime, timezone

import pytest
from bson import ObjectId

from app.services import audit_pdf_service, audit_report_service


def test_fmt_datetime_converts_utc_to_ist():
    # 06:49:05 UTC -> 12:19:05 IST (+5:30) -- this is the bug: the PDF used to
    # print the raw UTC value with no conversion, which read 5.5 hours "wrong"
    # to any admin comparing it against their own (Indian) wall clock.
    utc_value = datetime(2026, 7, 28, 6, 49, 5, tzinfo=timezone.utc)
    assert audit_pdf_service._fmt_datetime(utc_value) == "28-07-2026 12:19:05"


def test_fmt_datetime_handles_none():
    assert audit_pdf_service._fmt_datetime(None) == ""


async def test_generate_pdf_with_no_submissions(fake_containers):
    pdf_bytes = await audit_pdf_service.generate_pdf(date(2026, 7, 1), date(2026, 7, 3))
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 200


async def test_generate_pdf_with_submissions(fake_containers, fake_audit_log):
    from datetime import datetime, timezone

    _id = ObjectId()
    fake_containers._docs[_id] = {
        "_id": _id,
        "alg": "sealedbox-x25519+secretbox-xsalsa20poly1305+ed25519-v3",
        "wrapped_deks": {},
        "sealed_number_b64": "",
        "signature_b64": "",
        "created_at": datetime(2026, 7, 2, 9, 30, tzinfo=timezone.utc),
        "masked_preview": "XXXX-XXXX-5678",
        "submitted_by": "some-user-id",
        "lookup_tag": "tag-1",
        "reference_id": "ABCDEF012345",
    }
    event_id = ObjectId()
    fake_audit_log._docs[event_id] = {
        "_id": event_id,
        "ts": datetime(2026, 7, 2, 9, 30, tzinfo=timezone.utc),
        "action": "submit",
        "result": "success",
        "username": "alice",
        "container_id": "ABCDEF012345",
    }

    pdf_bytes = await audit_pdf_service.generate_pdf(date(2026, 7, 1), date(2026, 7, 3))
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 500


async def test_generate_pdf_rejects_invalid_range(fake_containers):
    with pytest.raises(audit_report_service.InvalidDateRangeError):
        await audit_pdf_service.generate_pdf(date(2026, 7, 5), date(2026, 7, 1))


async def test_generate_pdf_with_column_subset(fake_containers):
    pdf_bytes = await audit_pdf_service.generate_pdf(
        date(2026, 7, 1), date(2026, 7, 3), columns=["date", "masked_aadhaar_no"]
    )
    assert pdf_bytes.startswith(b"%PDF")


async def test_generate_pdf_rejects_unknown_column(fake_containers):
    with pytest.raises(audit_pdf_service.InvalidColumnError):
        await audit_pdf_service.generate_pdf(date(2026, 7, 1), date(2026, 7, 3), columns=["unique_reference_no"])


async def test_generate_pdf_rejects_empty_column_list(fake_containers):
    with pytest.raises(audit_pdf_service.InvalidColumnError):
        await audit_pdf_service.generate_pdf(date(2026, 7, 1), date(2026, 7, 3), columns=[])
