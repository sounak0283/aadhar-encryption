"""Integration tests for POST /api/aadhaar (app.routers.public) — now requires a logged-in user."""
from datetime import datetime, timedelta, timezone

from app.validation import generate_synthetic_aadhaar


def _payload(number: str, *, consent: bool = True, ts: datetime | None = None) -> dict:
    if ts is None:
        ts = datetime.now(timezone.utc)
    return {"aadhaar_number": number, "consent": consent, "ts": ts.isoformat()}


def test_submit_without_login_returns_401(client, fake_containers, master_admin):
    number = generate_synthetic_aadhaar("12345678901")
    resp = client.post("/api/aadhaar", json=_payload(number))
    assert resp.status_code == 401


def test_submit_with_no_admins_returns_503(logged_in_client, fake_containers, fake_admins):
    number = generate_synthetic_aadhaar("12345678901")
    resp = logged_in_client.post("/api/aadhaar", json=_payload(number))
    assert resp.status_code == 503


def test_submit_valid_number_succeeds(logged_in_client, fake_containers, master_admin):
    number = generate_synthetic_aadhaar("12345678901")
    resp = logged_in_client.post("/api/aadhaar", json=_payload(number))
    assert resp.status_code == 200
    body = resp.json()
    assert "reference_id" in body
    assert body["masked_preview"] == f"XXXX-XXXX-{number[-4:]}"
    assert len(fake_containers._docs) == 1


def test_submit_rejects_bad_checksum(logged_in_client, fake_containers, master_admin):
    number = generate_synthetic_aadhaar("12345678901")
    tampered = number[:-1] + str((int(number[-1]) + 1) % 10)
    resp = logged_in_client.post("/api/aadhaar", json=_payload(tampered))
    assert resp.status_code == 400
    assert len(fake_containers._docs) == 0


def test_submit_rejects_wrong_length(logged_in_client, fake_containers, master_admin):
    resp = logged_in_client.post("/api/aadhaar", json=_payload("12345"))
    assert resp.status_code == 422  # pydantic field validation


def test_stored_container_does_not_contain_plaintext(logged_in_client, fake_containers, master_admin, regular_user):
    number = generate_synthetic_aadhaar("98765432101")
    logged_in_client.post("/api/aadhaar", json=_payload(number))
    stored = next(iter(fake_containers._docs.values()))
    assert number not in str(stored)
    assert stored["masked_preview"].endswith(number[-4:])
    assert master_admin["id"] in stored["wrapped_deks"]
    assert stored["submitted_by"] == regular_user["id"]
    assert stored["unique_reference_no"] == regular_user["unique_reference_no"]


# --- UIDAI-norms-aligned behavior specific to backend-1 -----------------------


def test_submit_without_consent_is_rejected(logged_in_client, fake_containers, master_admin):
    number = generate_synthetic_aadhaar("12345678901")
    resp = logged_in_client.post("/api/aadhaar", json=_payload(number, consent=False))
    assert resp.status_code == 422
    assert len(fake_containers._docs) == 0


def test_submit_missing_consent_field_is_rejected(logged_in_client, fake_containers, master_admin):
    number = generate_synthetic_aadhaar("12345678901")
    body = _payload(number)
    del body["consent"]
    resp = logged_in_client.post("/api/aadhaar", json=body)
    assert resp.status_code == 422


def test_submit_with_stale_timestamp_is_rejected(logged_in_client, fake_containers, master_admin):
    number = generate_synthetic_aadhaar("12345678901")
    stale_ts = datetime.now(timezone.utc) - timedelta(minutes=10)
    resp = logged_in_client.post("/api/aadhaar", json=_payload(number, ts=stale_ts))
    assert resp.status_code == 400
    assert resp.json()["detail"] == "request_expired"
    assert len(fake_containers._docs) == 0


def test_submit_with_future_timestamp_is_rejected(logged_in_client, fake_containers, master_admin):
    number = generate_synthetic_aadhaar("12345678901")
    future_ts = datetime.now(timezone.utc) + timedelta(minutes=10)
    resp = logged_in_client.post("/api/aadhaar", json=_payload(number, ts=future_ts))
    assert resp.status_code == 400
    assert resp.json()["detail"] == "timestamp_in_future"
    assert len(fake_containers._docs) == 0


def test_submit_with_naive_timestamp_is_rejected(logged_in_client, fake_containers, master_admin):
    number = generate_synthetic_aadhaar("12345678901")
    body = {"aadhaar_number": number, "consent": True, "ts": "2026-07-28T10:00:00"}  # no offset/Z
    resp = logged_in_client.post("/api/aadhaar", json=body)
    assert resp.status_code == 422


def test_resubmitting_same_number_returns_same_reference_id(logged_in_client, fake_containers, master_admin):
    number = generate_synthetic_aadhaar("55566677788")
    first = logged_in_client.post("/api/aadhaar", json=_payload(number))
    second = logged_in_client.post("/api/aadhaar", json=_payload(number))
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["reference_id"] == second.json()["reference_id"]
    assert first.json()["masked_preview"] == second.json()["masked_preview"]
    # Only one container was ever written — the second call was a pure lookup.
    assert len(fake_containers._docs) == 1


def test_different_numbers_get_different_reference_ids(logged_in_client, fake_containers, master_admin):
    number_a = generate_synthetic_aadhaar("11122233344")
    number_b = generate_synthetic_aadhaar("99988877766")
    resp_a = logged_in_client.post("/api/aadhaar", json=_payload(number_a))
    resp_b = logged_in_client.post("/api/aadhaar", json=_payload(number_b))
    assert resp_a.json()["reference_id"] != resp_b.json()["reference_id"]
    assert len(fake_containers._docs) == 2


def test_stored_container_does_not_leak_number_via_lookup_tag(logged_in_client, fake_containers, master_admin):
    number = generate_synthetic_aadhaar("12312312312")
    logged_in_client.post("/api/aadhaar", json=_payload(number))
    stored = next(iter(fake_containers._docs.values()))
    assert "lookup_tag" in stored
    assert number not in stored["lookup_tag"]
    assert len(stored["lookup_tag"]) == 64  # hex-encoded SHA-256
