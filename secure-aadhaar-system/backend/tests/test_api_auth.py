"""Integration tests for /api/auth/* (app.routers.auth) — regular user signup/login/logout/me."""
from app.validation import generate_synthetic_aadhaar

USERNAME = "alice"
PASSWORD = "a-strong-user-password"


def test_signup_succeeds(client, fake_users):
    resp = client.post("/api/auth/signup", json={"username": USERNAME, "password": PASSWORD})
    assert resp.status_code == 200


def test_signup_rejects_duplicate_username(client, fake_users):
    client.post("/api/auth/signup", json={"username": USERNAME, "password": PASSWORD})
    resp = client.post("/api/auth/signup", json={"username": USERNAME, "password": "another-password-123"})
    assert resp.status_code == 409


def test_signup_rejects_short_password(client, fake_users):
    resp = client.post("/api/auth/signup", json={"username": "bob", "password": "short"})
    assert resp.status_code == 422


def test_login_succeeds_after_signup(client, fake_users):
    client.post("/api/auth/signup", json={"username": USERNAME, "password": PASSWORD})
    resp = client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
    assert resp.status_code == 200
    assert "user_session" in resp.cookies


def test_login_wrong_password_fails(client, fake_users):
    client.post("/api/auth/signup", json={"username": USERNAME, "password": PASSWORD})
    resp = client.post("/api/auth/login", json={"username": USERNAME, "password": "wrong-password"})
    assert resp.status_code == 401


def test_login_unknown_username_fails(client, fake_users):
    resp = client.post("/api/auth/login", json={"username": "nobody", "password": PASSWORD})
    assert resp.status_code == 401


def test_me_requires_session(client, fake_users):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_me_returns_current_user(client, fake_users):
    client.post("/api/auth/signup", json={"username": USERNAME, "password": PASSWORD})
    client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
    resp = client.get("/api/auth/me")
    assert resp.status_code == 200
    assert resp.json()["username"] == USERNAME


def test_logout_destroys_session(client, fake_users):
    client.post("/api/auth/signup", json={"username": USERNAME, "password": PASSWORD})
    client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_admin_and_user_sessions_coexist_on_one_client(client, fake_users, master_admin):
    """Different cookie names for admin_session vs user_session — logging in as
    both on the same browser/client shouldn't clobber either session."""
    client.post("/api/auth/signup", json={"username": USERNAME, "password": PASSWORD})
    assert client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD}).status_code == 200
    assert (
        client.post(
            "/api/admin/login",
            json={"username": master_admin["username"], "password": master_admin["password"], "totp_code": master_admin["totp_code"]()},
        ).status_code
        == 200
    )

    assert client.get("/api/auth/me").status_code == 200
    assert client.get("/api/admin/me").status_code == 200


def test_my_submissions_only_shows_own_records(client, fake_containers, fake_users, master_admin):
    # user A submits one record
    client.post("/api/auth/signup", json={"username": "userA", "password": "password-a-123"})
    client.post("/api/auth/login", json={"username": "userA", "password": "password-a-123"})
    number_a = generate_synthetic_aadhaar("12345678901")
    ref_a = client.post("/api/aadhaar", json={"aadhaar_number": number_a}).json()["reference_id"]
    client.post("/api/auth/logout")

    # user B submits a different record
    client.post("/api/auth/signup", json={"username": "userB", "password": "password-b-123"})
    client.post("/api/auth/login", json={"username": "userB", "password": "password-b-123"})
    number_b = generate_synthetic_aadhaar("98765432101")
    client.post("/api/aadhaar", json={"aadhaar_number": number_b})

    # user B's "my submissions" should show only their own record
    resp = client.get("/api/my-submissions")
    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    assert items[0]["masked_preview"].endswith(number_b[-4:])
    assert ref_a not in [i["id"] for i in items]


def test_my_submissions_requires_login(client, fake_containers, fake_users):
    resp = client.get("/api/my-submissions")
    assert resp.status_code == 401
