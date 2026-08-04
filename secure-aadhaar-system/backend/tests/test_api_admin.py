"""Integration tests for /api/admin/* (app.routers.admin)."""
from datetime import datetime, timezone

from app.validation import generate_synthetic_aadhaar


def _login(client, admin):
    return client.post(
        "/api/admin/login",
        json={"username": admin["username"], "password": admin["password"], "totp_code": admin["totp_code"]()},
    )


def _submit(client, number):
    """Submitting now requires a logged-in regular user — self-contained here
    (signs up + logs in a throwaway user) so callers don't need to thread the
    regular_user fixture through every test. Admin and user sessions use
    different cookie names, so this doesn't disturb any admin login already
    on the same client."""
    import uuid

    username = f"submitter-{uuid.uuid4().hex[:8]}"
    password = "throwaway-password-123"
    assert client.post("/api/auth/signup", json={"username": username, "password": password}).status_code == 200
    assert client.post("/api/auth/login", json={"username": username, "password": password}).status_code == 200

    resp = client.post(
        "/api/aadhaar",
        json={"aadhaar_number": number, "consent": True, "ts": datetime.now(timezone.utc).isoformat()},
    )
    assert resp.status_code == 200
    return resp.json()["reference_id"]


def test_login_with_correct_credentials_succeeds(client, master_admin):
    resp = _login(client, master_admin)
    assert resp.status_code == 200
    assert "admin_session" in resp.cookies


def test_login_with_wrong_password_fails(client, master_admin):
    resp = client.post(
        "/api/admin/login",
        json={"username": master_admin["username"], "password": "wrong password", "totp_code": master_admin["totp_code"]()},
    )
    assert resp.status_code == 401


def test_login_with_wrong_totp_fails(client, master_admin):
    resp = client.post(
        "/api/admin/login",
        json={"username": master_admin["username"], "password": master_admin["password"], "totp_code": "000000"},
    )
    assert resp.status_code == 401


def test_login_with_unknown_username_fails(client, master_admin):
    resp = client.post(
        "/api/admin/login",
        json={"username": "nobody", "password": master_admin["password"], "totp_code": master_admin["totp_code"]()},
    )
    assert resp.status_code == 401


def test_submissions_require_session(client, fake_containers, master_admin):
    resp = client.get("/api/admin/submissions")
    assert resp.status_code == 401


def test_me_returns_current_admin(client, master_admin):
    _login(client, master_admin)
    resp = client.get("/api/admin/me")
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == master_admin["username"]
    assert body["role"] == "master"


def test_full_submit_login_list_decrypt_flow(client, fake_containers, fake_audit_log, master_admin):
    number = generate_synthetic_aadhaar("12345678901")
    reference_id = _submit(client, number)

    assert _login(client, master_admin).status_code == 200

    list_resp = client.get("/api/admin/submissions")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert len(items) == 1
    assert items[0]["id"] == reference_id
    assert number not in str(items)

    decrypt_resp = client.post(f"/api/admin/submissions/{reference_id}/decrypt")
    assert decrypt_resp.status_code == 200
    assert decrypt_resp.json()["aadhaar_number"] == number
    assert decrypt_resp.headers["cache-control"] == "no-store"

    decrypt_entries = [doc for doc in fake_audit_log._docs.values() if doc["action"] == "decrypt"]
    assert len(decrypt_entries) == 1
    audit_entry = decrypt_entries[0]
    assert audit_entry["result"] == "success"
    assert audit_entry["admin_username"] == master_admin["username"]
    assert number not in str(audit_entry)


def test_decrypt_unknown_id_returns_404(client, fake_containers, fake_audit_log, master_admin):
    _login(client, master_admin)
    resp = client.post("/api/admin/submissions/000000000000000000000000/decrypt")
    assert resp.status_code == 404


def test_decrypt_without_session_fails(client, fake_containers, master_admin):
    resp = client.post("/api/admin/submissions/000000000000000000000000/decrypt")
    assert resp.status_code == 401


def test_logout_destroys_session(client, fake_containers, master_admin):
    _login(client, master_admin)
    logout_resp = client.post("/api/admin/logout")
    assert logout_resp.status_code == 200

    list_resp = client.get("/api/admin/submissions")
    assert list_resp.status_code == 401


# ============================================================================
# Multi-admin: creating a sub-admin and confirming they can decrypt
# ============================================================================


def _create_sub_admin(client, username, password):
    import pyotp

    start_resp = client.post("/api/admin/admins/start", json={"username": username, "password": password})
    assert start_resp.status_code == 200
    body = start_resp.json()
    code = pyotp.TOTP(body["manual_secret"]).now()
    confirm_resp = client.post(
        "/api/admin/admins/confirm", json={"registration_token": body["registration_token"], "totp_code": code}
    )
    assert confirm_resp.status_code == 200
    return confirm_resp.json()


def _login_by_username(client, fake_admins, username, password):
    """Log in for real through the actual login endpoint, decrypting that admin's
    TOTP secret from the fake admins collection the same way the server would."""
    import pyotp
    from bson import ObjectId

    from app.config import get_app_totp_key
    from app.crypto import totp_utils

    admin_doc = next(d for d in fake_admins._docs.values() if d["username"] == username)
    totp_secret = totp_utils.decrypt_totp_secret(admin_doc["totp_secret_encrypted"], get_app_totp_key())
    resp = client.post(
        "/api/admin/login",
        json={"username": username, "password": password, "totp_code": pyotp.TOTP(totp_secret).now()},
    )
    assert resp.status_code == 200
    return str(ObjectId(admin_doc["_id"]))


def test_master_can_list_admins(client, fake_containers, fake_admins, master_admin):
    _login(client, master_admin)
    _create_sub_admin(client, "sub-b", "sub-admin-password-123")

    resp = client.get("/api/admin/admins")
    assert resp.status_code == 200
    usernames = {a["username"] for a in resp.json()}
    assert usernames == {master_admin["username"], "sub-b"}


def test_sub_admin_cannot_list_or_create_admins(client, fake_containers, fake_admins, master_admin):
    _login(client, master_admin)
    _create_sub_admin(client, "sub-a", "sub-admin-password-123")
    client.post("/api/admin/logout")

    _login_by_username(client, fake_admins, "sub-a", "sub-admin-password-123")

    assert client.get("/api/admin/admins").status_code == 403
    assert (
        client.post("/api/admin/admins/start", json={"username": "sub-d", "password": "another-password-123"}).status_code
        == 403
    )


def test_sub_admin_can_decrypt_record_created_before_they_existed(client, fake_containers, fake_admins, master_admin):
    number = generate_synthetic_aadhaar("12345678901")
    reference_id = _submit(client, number)

    _login(client, master_admin)
    sub_result = _create_sub_admin(client, "sub-c", "sub-admin-password-123")
    assert sub_result["containers_granted"] == 1
    client.post("/api/admin/logout")

    _login_by_username(client, fake_admins, "sub-c", "sub-admin-password-123")

    decrypt_resp = client.post(f"/api/admin/submissions/{reference_id}/decrypt")
    assert decrypt_resp.status_code == 200
    assert decrypt_resp.json()["aadhaar_number"] == number
