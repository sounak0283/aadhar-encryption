"""Integration tests for GET /api/admin/audit-report (app.routers.admin)."""
from datetime import datetime, timezone

from bson import ObjectId


def _login(client, admin):
    return client.post(
        "/api/admin/login",
        json={"username": admin["username"], "password": admin["password"], "totp_code": admin["totp_code"]()},
    )


def _insert_container(fake_containers, *, day: str, masked_preview: str, unique_reference_no: str):
    """Directly inserts a container doc with a fixed created_at date, bypassing
    the real submission flow — the audit report only reads already-masked
    metadata, so this is enough to test its date-grouping logic in isolation."""
    _id = ObjectId()
    doc = {
        "_id": _id,
        "alg": "sealedbox-x25519+secretbox-xsalsa20poly1305+ed25519-v3",
        "wrapped_deks": {},
        "sealed_number_b64": "",
        "signature_b64": "",
        "created_at": datetime.fromisoformat(f"{day}T12:00:00+00:00"),
        "masked_preview": masked_preview,
        "submitted_by": "some-user-id",
        "lookup_tag": f"tag-{_id}",
        "unique_reference_no": unique_reference_no,
    }
    fake_containers._docs[_id] = doc
    return str(_id)


def test_audit_report_requires_admin_session(client, fake_containers):
    resp = client.get("/api/admin/audit-report", params={"from_date": "2026-07-01", "to_date": "2026-07-03"})
    assert resp.status_code == 401


def test_audit_report_rejects_invalid_range(client, fake_containers, master_admin):
    assert _login(client, master_admin).status_code == 200
    resp = client.get("/api/admin/audit-report", params={"from_date": "2026-07-05", "to_date": "2026-07-01"})
    assert resp.status_code == 400


def test_audit_report_includes_empty_dates_and_one_entry(client, fake_containers, master_admin):
    assert _login(client, master_admin).status_code == 200
    _insert_container(fake_containers, day="2026-07-02", masked_preview="XXXX-XXXX-1234", unique_reference_no="ABC12345")

    resp = client.get("/api/admin/audit-report", params={"from_date": "2026-07-01", "to_date": "2026-07-03"})
    assert resp.status_code == 200
    rows = resp.json()
    assert [row["date"] for row in rows] == ["2026-07-01", "2026-07-02", "2026-07-03"]

    day1, day2, day3 = rows
    assert day1["reference_id"] is None
    assert day1["masked_aadhaar_no"] is None
    assert day3["reference_id"] is None

    assert day2["masked_aadhaar_no"] == "XXXX-XXXX-1234"
    assert day2["unique_reference_no"] == "ABC12345"
    assert day2["reference_id"] is not None
    assert day2["request_datetime"] is not None


def test_audit_report_multiple_entries_same_date(client, fake_containers, master_admin):
    assert _login(client, master_admin).status_code == 200
    _insert_container(fake_containers, day="2026-07-02", masked_preview="XXXX-XXXX-1111", unique_reference_no="AAAA1111")
    _insert_container(fake_containers, day="2026-07-02", masked_preview="XXXX-XXXX-2222", unique_reference_no="BBBB2222")

    resp = client.get("/api/admin/audit-report", params={"from_date": "2026-07-02", "to_date": "2026-07-02"})
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 2
    assert {row["masked_aadhaar_no"] for row in rows} == {"XXXX-XXXX-1111", "XXXX-XXXX-2222"}
    assert all(row["date"] == "2026-07-02" for row in rows)


def test_audit_report_excludes_out_of_range_entries(client, fake_containers, master_admin):
    assert _login(client, master_admin).status_code == 200
    _insert_container(fake_containers, day="2026-06-15", masked_preview="XXXX-XXXX-9999", unique_reference_no="ZZZZ9999")

    resp = client.get("/api/admin/audit-report", params={"from_date": "2026-07-01", "to_date": "2026-07-03"})
    assert resp.status_code == 200
    rows = resp.json()
    assert all(row["masked_aadhaar_no"] != "XXXX-XXXX-9999" for row in rows)
