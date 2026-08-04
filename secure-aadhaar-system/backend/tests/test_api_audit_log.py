"""Integration tests for GET /api/admin/audit-log and the event-recording it
depends on (admin login/logout, user login/logout, submit, decrypt)."""
import uuid
from datetime import datetime, timezone

from app.validation import generate_synthetic_aadhaar


def _today_range():
    today = datetime.now(timezone.utc).date().isoformat()
    return {"from_date": today, "to_date": today}


def _admin_login(client, admin, *, totp_code=None):
    return client.post(
        "/api/admin/login",
        json={
            "username": admin["username"],
            "password": admin["password"],
            "totp_code": totp_code if totp_code is not None else admin["totp_code"](),
        },
    )


def test_audit_log_requires_admin_session(client, fake_containers, fake_audit_log):
    resp = client.get("/api/admin/audit-log", params=_today_range())
    assert resp.status_code == 401


def test_audit_log_rejects_invalid_range(client, fake_containers, fake_audit_log, master_admin):
    assert _admin_login(client, master_admin).status_code == 200
    resp = client.get("/api/admin/audit-log", params={"from_date": "2026-07-05", "to_date": "2026-07-01"})
    assert resp.status_code == 400


def test_admin_login_success_is_recorded(client, fake_containers, fake_audit_log, master_admin):
    assert _admin_login(client, master_admin).status_code == 200

    resp = client.get("/api/admin/audit-log", params=_today_range())
    assert resp.status_code == 200
    logins = [e for e in resp.json() if e["action"] == "admin_login"]
    assert len(logins) == 1
    assert logins[0]["result"] == "success"
    assert logins[0]["username"] == master_admin["username"]


def test_admin_login_failure_is_recorded(client, fake_containers, fake_audit_log, master_admin):
    assert _admin_login(client, master_admin, totp_code="000000").status_code == 401
    assert _admin_login(client, master_admin).status_code == 200  # log in for real to read the log

    resp = client.get("/api/admin/audit-log", params=_today_range())
    logins = [e for e in resp.json() if e["action"] == "admin_login"]
    assert any(e["result"] == "invalid_credentials" for e in logins)
    assert any(e["result"] == "success" for e in logins)


def test_admin_logout_is_recorded(client, fake_containers, fake_audit_log, master_admin):
    assert _admin_login(client, master_admin).status_code == 200
    assert client.post("/api/admin/logout").status_code == 200
    assert _admin_login(client, master_admin).status_code == 200

    resp = client.get("/api/admin/audit-log", params=_today_range())
    events = resp.json()
    assert any(e["action"] == "admin_logout" and e["username"] == master_admin["username"] for e in events)


def test_user_login_submit_and_logout_are_recorded(client, fake_containers, fake_audit_log, master_admin):
    username = f"submitter-{uuid.uuid4().hex[:8]}"
    password = "throwaway-password-123"
    assert client.post("/api/auth/signup", json={"username": username, "password": password}).status_code == 200
    assert client.post("/api/auth/login", json={"username": username, "password": password}).status_code == 200

    number = generate_synthetic_aadhaar("12345678901")
    submit_resp = client.post(
        "/api/aadhaar",
        json={"aadhaar_number": number, "consent": True, "ts": datetime.now(timezone.utc).isoformat()},
    )
    assert submit_resp.status_code == 200

    assert client.post("/api/auth/logout").status_code == 200

    assert _admin_login(client, master_admin).status_code == 200
    resp = client.get("/api/admin/audit-log", params=_today_range())
    events = resp.json()

    user_logins = [e for e in events if e["action"] == "user_login" and e["username"] == username]
    assert len(user_logins) == 1
    assert user_logins[0]["result"] == "success"

    submits = [e for e in events if e["action"] == "submit" and e["username"] == username]
    assert len(submits) == 1
    assert submits[0]["result"] == "success"
    assert submits[0]["container_id"] == submit_resp.json()["reference_id"]

    user_logouts = [e for e in events if e["action"] == "user_logout" and e["username"] == username]
    assert len(user_logouts) == 1


def test_user_login_failure_is_recorded(client, fake_containers, fake_audit_log, master_admin):
    resp = client.post("/api/auth/login", json={"username": "nobody", "password": "whatever12345"})
    assert resp.status_code == 401

    assert _admin_login(client, master_admin).status_code == 200
    resp = client.get("/api/admin/audit-log", params=_today_range())
    events = resp.json()
    assert any(
        e["action"] == "user_login" and e["username"] == "nobody" and e["result"] == "invalid_credentials"
        for e in events
    )


def test_audit_log_events_sorted_newest_first(client, fake_containers, fake_audit_log, master_admin):
    assert _admin_login(client, master_admin).status_code == 200
    assert client.post("/api/admin/logout").status_code == 200
    assert _admin_login(client, master_admin).status_code == 200

    resp = client.get("/api/admin/audit-log", params=_today_range())
    events = resp.json()
    timestamps = [e["ts"] for e in events]
    assert timestamps == sorted(timestamps, reverse=True)
