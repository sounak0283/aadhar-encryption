"""
Integration tests for /api/admin/register/* (app.routers.admin) — the
first-admin (master) self-registration flow, through the real router/service
wiring against fake_admins (never a real database).
"""
from datetime import datetime, timezone

import pyotp

SETUP_TOKEN = "test-setup-token-abc123"
USERNAME = "master"
PASSWORD = "a-strong-registration-password"


def _set_setup_token(monkeypatch):
    monkeypatch.setenv("ADMIN_SETUP_TOKEN", SETUP_TOKEN)


def test_status_reports_not_registered(client, fake_admins):
    resp = client.get("/api/admin/register/status")
    assert resp.status_code == 200
    assert resp.json() == {"registered": False}


def test_start_without_setup_token_configured_returns_503(client, fake_admins, monkeypatch):
    monkeypatch.delenv("ADMIN_SETUP_TOKEN", raising=False)
    resp = client.post(
        "/api/admin/register/start", json={"setup_token": "anything", "username": USERNAME, "password": PASSWORD}
    )
    assert resp.status_code == 503


def test_start_with_wrong_setup_token_returns_403(client, fake_admins, monkeypatch):
    _set_setup_token(monkeypatch)
    resp = client.post(
        "/api/admin/register/start", json={"setup_token": "wrong-token", "username": USERNAME, "password": PASSWORD}
    )
    assert resp.status_code == 403


def test_start_with_weak_password_rejected(client, fake_admins, monkeypatch):
    _set_setup_token(monkeypatch)
    resp = client.post(
        "/api/admin/register/start", json={"setup_token": SETUP_TOKEN, "username": USERNAME, "password": "short"}
    )
    # Pydantic's Field(min_length=12) on RegisterStartRequest catches this before
    # the handler runs at all — 422 (schema validation), not a service-level 400.
    assert resp.status_code == 422


def test_start_with_short_username_rejected(client, fake_admins, monkeypatch):
    _set_setup_token(monkeypatch)
    resp = client.post(
        "/api/admin/register/start", json={"setup_token": SETUP_TOKEN, "username": "ab", "password": PASSWORD}
    )
    assert resp.status_code == 422


def test_full_register_flow_then_login_and_decrypt(client, fake_admins, fake_containers, monkeypatch):
    _set_setup_token(monkeypatch)

    start_resp = client.post(
        "/api/admin/register/start", json={"setup_token": SETUP_TOKEN, "username": USERNAME, "password": PASSWORD}
    )
    assert start_resp.status_code == 200
    body = start_resp.json()
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    assert len(body["qr_code_png_base64"]) > 0

    code = pyotp.TOTP(body["manual_secret"]).now()
    confirm_resp = client.post(
        "/api/admin/register/confirm",
        json={"registration_token": body["registration_token"], "totp_code": code},
    )
    assert confirm_resp.status_code == 200

    status_resp = client.get("/api/admin/register/status")
    assert status_resp.json() == {"registered": True}

    # The freshly registered admin can now actually log in and use the app —
    # proves the new admin is immediately queryable, no server restart needed.
    login_resp = client.post(
        "/api/admin/login",
        json={"username": USERNAME, "password": PASSWORD, "totp_code": pyotp.TOTP(body["manual_secret"]).now()},
    )
    assert login_resp.status_code == 200

    # Submitting requires a logged-in regular user (separate from the admin
    # session above — different cookie names, so both coexist on one client).
    assert (
        client.post("/api/auth/signup", json={"username": "submitter", "password": "throwaway-password-123"}).status_code
        == 200
    )
    assert (
        client.post("/api/auth/login", json={"username": "submitter", "password": "throwaway-password-123"}).status_code
        == 200
    )

    submit_resp = client.post(
        "/api/aadhaar",
        json={"aadhaar_number": "123456789010", "consent": True, "ts": datetime.now(timezone.utc).isoformat()},
    )
    assert submit_resp.status_code == 200
    reference_id = submit_resp.json()["reference_id"]

    decrypt_resp = client.post(f"/api/admin/submissions/{reference_id}/decrypt")
    assert decrypt_resp.status_code == 200
    assert decrypt_resp.json()["aadhaar_number"] == "123456789010"


def test_register_start_refuses_once_already_registered(client, fake_admins, monkeypatch):
    _set_setup_token(monkeypatch)
    start_resp = client.post(
        "/api/admin/register/start", json={"setup_token": SETUP_TOKEN, "username": USERNAME, "password": PASSWORD}
    )
    body = start_resp.json()
    client.post(
        "/api/admin/register/confirm",
        json={"registration_token": body["registration_token"], "totp_code": pyotp.TOTP(body["manual_secret"]).now()},
    )

    second_start = client.post(
        "/api/admin/register/start",
        json={"setup_token": SETUP_TOKEN, "username": "someone-else", "password": "another-password-123"},
    )
    assert second_start.status_code == 409


def test_register_confirm_wrong_code_returns_401(client, fake_admins, monkeypatch):
    _set_setup_token(monkeypatch)
    start_resp = client.post(
        "/api/admin/register/start", json={"setup_token": SETUP_TOKEN, "username": USERNAME, "password": PASSWORD}
    )
    body = start_resp.json()

    resp = client.post(
        "/api/admin/register/confirm",
        json={"registration_token": body["registration_token"], "totp_code": "000000"},
    )
    assert resp.status_code == 401


def test_register_confirm_unknown_token_returns_404(client, fake_admins, monkeypatch):
    _set_setup_token(monkeypatch)
    resp = client.post(
        "/api/admin/register/confirm",
        json={"registration_token": "nonexistent", "totp_code": "123456"},
    )
    assert resp.status_code == 404
