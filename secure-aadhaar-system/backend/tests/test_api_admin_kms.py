"""
Integration test proving the full submit -> login -> list -> decrypt flow
works end-to-end through the real routers/services when the admin identity
uses the AWS KMS provider (key_provider="aws-kms"), not just local. The KMS
client itself is mocked (see tests/test_kms_provider.py's module docstring).
"""
from app.providers.identity_provider import KMS_ALG
from app.validation import generate_synthetic_aadhaar


def test_full_flow_with_kms_provider(logged_in_client, fake_containers, fake_audit_log, kms_master_admin):
    client = logged_in_client
    number = generate_synthetic_aadhaar("12345678901")

    submit_resp = client.post("/api/aadhaar", json={"aadhaar_number": number})
    assert submit_resp.status_code == 200
    reference_id = submit_resp.json()["reference_id"]

    stored = next(iter(fake_containers._docs.values()))
    assert stored["alg"] == KMS_ALG

    login_resp = client.post(
        "/api/admin/login",
        json={
            "username": kms_master_admin["username"],
            "password": kms_master_admin["password"],
            "totp_code": kms_master_admin["totp_code"](),
        },
    )
    assert login_resp.status_code == 200

    list_resp = client.get("/api/admin/submissions")
    assert list_resp.status_code == 200
    assert list_resp.json()[0]["id"] == reference_id

    decrypt_resp = client.post(f"/api/admin/submissions/{reference_id}/decrypt")
    assert decrypt_resp.status_code == 200
    assert decrypt_resp.json()["aadhaar_number"] == number
