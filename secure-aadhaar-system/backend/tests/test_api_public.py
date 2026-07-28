"""Integration tests for POST /api/aadhaar (app.routers.public) — now requires a logged-in user."""
from app.validation import generate_synthetic_aadhaar


def test_submit_without_login_returns_401(client, fake_containers, master_admin):
    number = generate_synthetic_aadhaar("12345678901")
    resp = client.post("/api/aadhaar", json={"aadhaar_number": number})
    assert resp.status_code == 401


def test_submit_with_no_admins_returns_503(logged_in_client, fake_containers, fake_admins):
    number = generate_synthetic_aadhaar("12345678901")
    resp = logged_in_client.post("/api/aadhaar", json={"aadhaar_number": number})
    assert resp.status_code == 503


def test_submit_valid_number_succeeds(logged_in_client, fake_containers, master_admin):
    number = generate_synthetic_aadhaar("12345678901")
    resp = logged_in_client.post("/api/aadhaar", json={"aadhaar_number": number})
    assert resp.status_code == 200
    body = resp.json()
    assert "reference_id" in body
    assert body["masked_preview"] == f"XXXX-XXXX-{number[-4:]}"
    assert len(fake_containers._docs) == 1


def test_submit_rejects_bad_checksum(logged_in_client, fake_containers, master_admin):
    number = generate_synthetic_aadhaar("12345678901")
    tampered = number[:-1] + str((int(number[-1]) + 1) % 10)
    resp = logged_in_client.post("/api/aadhaar", json={"aadhaar_number": tampered})
    assert resp.status_code == 400
    assert len(fake_containers._docs) == 0


def test_submit_rejects_wrong_length(logged_in_client, fake_containers, master_admin):
    resp = logged_in_client.post("/api/aadhaar", json={"aadhaar_number": "12345"})
    assert resp.status_code == 422  # pydantic field validation


def test_stored_container_does_not_contain_plaintext(logged_in_client, fake_containers, master_admin, regular_user):
    number = generate_synthetic_aadhaar("98765432101")
    logged_in_client.post("/api/aadhaar", json={"aadhaar_number": number})
    stored = next(iter(fake_containers._docs.values()))
    assert number not in str(stored)
    assert stored["masked_preview"].endswith(number[-4:])
    assert master_admin["id"] in stored["wrapped_deks"]
    assert stored["submitted_by"] == regular_user["id"]
