"""Unit tests for the regular-user session store (app.services.user_session)."""
import time

from app.services import user_session


def test_create_and_get_session():
    token = user_session.create_session("user-1", "alice")
    session = user_session.get_session(token)
    assert session is not None
    assert session.user_id == "user-1"
    assert session.username == "alice"


def test_unknown_token_returns_none():
    assert user_session.get_session("nonexistent-token") is None


def test_expired_session_is_swept():
    token = user_session.create_session("user-1", "alice")
    user_session._sessions[token].expires_at = time.monotonic() - 1
    assert user_session.get_session(token) is None


def test_logout_destroys_session():
    token = user_session.create_session("user-1", "alice")
    user_session.destroy_session(token)
    assert user_session.get_session(token) is None


def test_activity_slides_the_ttl():
    token = user_session.create_session("user-1", "alice")
    first_expiry = user_session._sessions[token].expires_at
    time.sleep(0.01)
    user_session.get_session(token)
    assert user_session._sessions[token].expires_at > first_expiry
