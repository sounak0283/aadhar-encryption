"""Integration tests for GET /api/admin/audit-report (app.routers.admin).

The report is sourced from audit_log (submit/decrypt events), not just each
container's one-time created_at — every hit on a record gets its own row.
"""
from datetime import datetime, timezone

from bson import ObjectId


def _login(client, admin):
    return client.post(
        "/api/admin/login",
        json={"username": admin["username"], "password": admin["password"], "totp_code": admin["totp_code"]()},
    )


def _insert_container(fake_containers, *, reference_id: str, masked_preview: str):
    """Directly inserts a container doc, bypassing the real submission flow —
    the report only needs it for the masked_preview lookup, since the actual
    row data now comes from audit_log events."""
    _id = ObjectId()
    doc = {
        "_id": _id,
        "alg": "sealedbox-x25519+secretbox-xsalsa20poly1305+ed25519-v3",
        "wrapped_deks": {},
        "sealed_number_b64": "",
        "signature_b64": "",
        "created_at": datetime.now(timezone.utc),
        "masked_preview": masked_preview,
        "submitted_by": "some-user-id",
        "lookup_tag": f"tag-{_id}",
        "reference_id": reference_id,
    }
    fake_containers._docs[_id] = doc
    return reference_id


def _insert_event(fake_audit_log, *, day: str, action: str, reference_id: str, hour: int = 12, result: str = "success"):
    """Directly inserts an audit_log event with a fixed ts date, bypassing the
    real endpoints — enough to test the report's date-grouping/per-hit logic
    in isolation."""
    _id = ObjectId()
    fake_audit_log._docs[_id] = {
        "_id": _id,
        "ts": datetime.fromisoformat(f"{day}T{hour:02d}:00:00+00:00"),
        "action": action,
        "result": result,
        "username": "some-admin",
        "container_id": reference_id,
    }


def test_audit_report_requires_admin_session(client, fake_containers):
    resp = client.get("/api/admin/audit-report", params={"from_date": "2026-07-01", "to_date": "2026-07-03"})
    assert resp.status_code == 401


def test_audit_report_rejects_invalid_range(client, fake_containers, master_admin):
    assert _login(client, master_admin).status_code == 200
    resp = client.get("/api/admin/audit-report", params={"from_date": "2026-07-05", "to_date": "2026-07-01"})
    assert resp.status_code == 400


def test_audit_report_includes_empty_dates_and_one_entry(client, fake_containers, fake_audit_log, master_admin):
    assert _login(client, master_admin).status_code == 200
    ref = _insert_container(fake_containers, reference_id="REF00000001", masked_preview="XXXX-XXXX-1234")
    _insert_event(fake_audit_log, day="2026-07-02", action="submit", reference_id=ref)

    resp = client.get("/api/admin/audit-report", params={"from_date": "2026-07-01", "to_date": "2026-07-03"})
    assert resp.status_code == 200
    rows = resp.json()
    assert [row["date"] for row in rows] == ["2026-07-01", "2026-07-02", "2026-07-03"]

    day1, day2, day3 = rows
    assert day1["reference_id"] is None
    assert day1["masked_aadhaar_no"] is None
    assert day3["reference_id"] is None

    assert day2["masked_aadhaar_no"] == "XXXX-XXXX-1234"
    assert "unique_reference_no" not in day2
    assert day2["reference_id"] == ref
    assert day2["request_datetime"] is not None


def test_audit_report_multiple_entries_same_date(client, fake_containers, fake_audit_log, master_admin):
    assert _login(client, master_admin).status_code == 200
    ref1 = _insert_container(fake_containers, reference_id="REF00000001", masked_preview="XXXX-XXXX-1111")
    ref2 = _insert_container(fake_containers, reference_id="REF00000002", masked_preview="XXXX-XXXX-2222")
    _insert_event(fake_audit_log, day="2026-07-02", action="submit", reference_id=ref1)
    _insert_event(fake_audit_log, day="2026-07-02", action="submit", reference_id=ref2)

    resp = client.get("/api/admin/audit-report", params={"from_date": "2026-07-02", "to_date": "2026-07-02"})
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 2
    assert {row["masked_aadhaar_no"] for row in rows} == {"XXXX-XXXX-1111", "XXXX-XXXX-2222"}
    assert all(row["date"] == "2026-07-02" for row in rows)


def test_audit_report_excludes_out_of_range_entries(client, fake_containers, fake_audit_log, master_admin):
    assert _login(client, master_admin).status_code == 200
    ref = _insert_container(fake_containers, reference_id="REF00000001", masked_preview="XXXX-XXXX-9999")
    _insert_event(fake_audit_log, day="2026-06-15", action="submit", reference_id=ref)

    resp = client.get("/api/admin/audit-report", params={"from_date": "2026-07-01", "to_date": "2026-07-03"})
    assert resp.status_code == 200
    rows = resp.json()
    assert all(row["masked_aadhaar_no"] != "XXXX-XXXX-9999" for row in rows)


def test_audit_report_records_every_hit_not_just_the_first(client, fake_containers, fake_audit_log, master_admin):
    """The core fix: the same Aadhaar record submitted once and then decrypted
    twice must show up as three separate rows, each with its own timestamp —
    not one row frozen at the original submission time."""
    assert _login(client, master_admin).status_code == 200
    ref = _insert_container(fake_containers, reference_id="REF00000001", masked_preview="XXXX-XXXX-1234")
    _insert_event(fake_audit_log, day="2026-07-02", action="submit", reference_id=ref, hour=9)
    _insert_event(fake_audit_log, day="2026-07-02", action="decrypt", reference_id=ref, hour=14)
    _insert_event(fake_audit_log, day="2026-07-03", action="decrypt", reference_id=ref, hour=8)

    resp = client.get("/api/admin/audit-report", params={"from_date": "2026-07-02", "to_date": "2026-07-03"})
    assert resp.status_code == 200
    rows = [row for row in resp.json() if row["reference_id"] is not None]
    assert len(rows) == 3
    assert all(row["reference_id"] == ref for row in rows)
    timestamps = [row["request_datetime"] for row in rows]
    assert len(set(timestamps)) == 3  # each hit has its own distinct timestamp


def test_audit_report_ignores_login_events(client, fake_containers, fake_audit_log, master_admin):
    """Login/logout events have no container_id and aren't submission hits —
    they belong in /api/admin/audit-log, not this per-record report."""
    assert _login(client, master_admin).status_code == 200
    _id = ObjectId()
    fake_audit_log._docs[_id] = {
        "_id": _id,
        "ts": datetime.fromisoformat("2026-07-02T09:00:00+00:00"),
        "action": "admin_login",
        "result": "success",
        "username": "admin",
        "container_id": None,
    }

    resp = client.get("/api/admin/audit-report", params={"from_date": "2026-07-01", "to_date": "2026-07-03"})
    assert resp.status_code == 200
    rows = resp.json()
    assert all(row["reference_id"] is None for row in rows)


# --- PDF export ----------------------------------------------------------


def test_audit_report_pdf_requires_admin_session(client, fake_containers):
    resp = client.get("/api/admin/audit-report/pdf", params={"from_date": "2026-07-01", "to_date": "2026-07-03"})
    assert resp.status_code == 401


def test_audit_report_pdf_rejects_invalid_range(client, fake_containers, master_admin):
    assert _login(client, master_admin).status_code == 200
    resp = client.get("/api/admin/audit-report/pdf", params={"from_date": "2026-07-05", "to_date": "2026-07-01"})
    assert resp.status_code == 400


def test_audit_report_pdf_returns_a_real_pdf(client, fake_containers, fake_audit_log, master_admin):
    assert _login(client, master_admin).status_code == 200
    ref = _insert_container(fake_containers, reference_id="REF00000001", masked_preview="XXXX-XXXX-1234")
    _insert_event(fake_audit_log, day="2026-07-02", action="submit", reference_id=ref)

    resp = client.get("/api/admin/audit-report/pdf", params={"from_date": "2026-07-01", "to_date": "2026-07-03"})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert "attachment" in resp.headers["content-disposition"]
    assert "audit-report_2026-07-01_2026-07-03.pdf" in resp.headers["content-disposition"]
    assert resp.content.startswith(b"%PDF")
    assert len(resp.content) > 500  # a real rendered document, not an empty stub


def test_audit_report_pdf_with_column_selection(client, fake_containers, fake_audit_log, master_admin):
    assert _login(client, master_admin).status_code == 200
    ref = _insert_container(fake_containers, reference_id="REF00000001", masked_preview="XXXX-XXXX-1234")
    _insert_event(fake_audit_log, day="2026-07-02", action="submit", reference_id=ref)

    resp = client.get(
        "/api/admin/audit-report/pdf",
        params={"from_date": "2026-07-01", "to_date": "2026-07-03", "columns": "date,masked_aadhaar_no"},
    )
    assert resp.status_code == 200
    assert resp.content.startswith(b"%PDF")


def test_audit_report_pdf_rejects_unknown_column(client, fake_containers, master_admin):
    assert _login(client, master_admin).status_code == 200
    resp = client.get(
        "/api/admin/audit-report/pdf",
        params={"from_date": "2026-07-01", "to_date": "2026-07-03", "columns": "unique_reference_no"},
    )
    assert resp.status_code == 400
