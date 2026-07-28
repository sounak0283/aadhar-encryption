"""Unit tests for the in-memory admin session store (app.services.admin_session)."""
import time

from app.services import admin_session


class FakeUnlockedIdentity:
    def __init__(self):
        self.closed = False

    def unwrap_dek(self, wrapped_dek_b64: str) -> bytes:
        return b"x" * 32

    def close(self):
        self.closed = True


def _create(ident, admin_id="admin-1", username="admin", role="master"):
    return admin_session.create_session(admin_id, username, role, ident)


def test_create_and_get_session():
    ident = FakeUnlockedIdentity()
    token = _create(ident, admin_id="admin-1", username="alice", role="master")
    session = admin_session.get_session(token)
    assert session is not None
    assert session.unlocked_identity is ident
    assert session.admin_id == "admin-1"
    assert session.username == "alice"
    assert session.role == "master"


def test_unknown_token_returns_none():
    assert admin_session.get_session("nonexistent-token") is None


def test_expired_session_is_swept_and_closed():
    ident = FakeUnlockedIdentity()
    token = _create(ident)

    session = admin_session._sessions[token]
    session.expires_at = time.monotonic() - 1  # force expiry without waiting 5 real minutes

    assert admin_session.get_session(token) is None
    assert ident.closed is True


def test_logout_destroys_session_and_closes_identity():
    ident = FakeUnlockedIdentity()
    token = _create(ident)
    admin_session.destroy_session(token)
    assert admin_session.get_session(token) is None
    assert ident.closed is True


def test_activity_slides_the_ttl():
    ident = FakeUnlockedIdentity()
    token = _create(ident)
    first_expiry = admin_session._sessions[token].expires_at

    time.sleep(0.01)
    admin_session.get_session(token)  # touches / refreshes
    assert admin_session._sessions[token].expires_at > first_expiry
