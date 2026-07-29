"""
user_session.py
In-memory, TTL-based session store for regular (non-admin) users. Much
simpler than app/services/admin_session.py — a regular user holds no
encryption keys and has nothing sensitive to "close" on logout, so a
session here is just an id/username pair. Sliding 30-minute idle timeout —
longer than the admin session's 5 minutes, since this account can't decrypt
anything and getting logged out every 5 minutes while filling in a form
would just be annoying, not a meaningful security boundary.
"""
import secrets
import time
from dataclasses import dataclass, field

SESSION_TTL_SECONDS = 30 * 60


@dataclass
class Session:
    user_id: str
    username: str
    expires_at: float = field(default=0.0)

    def touch(self) -> None:
        self.expires_at = time.monotonic() + SESSION_TTL_SECONDS

    def is_expired(self) -> bool:
        return time.monotonic() >= self.expires_at


_sessions: dict[str, Session] = {}


def create_session(user_id: str, username: str) -> str:
    token = secrets.token_urlsafe(32)
    session = Session(user_id=user_id, username=username)
    session.touch()
    _sessions[token] = session
    return token


def get_session(token: str) -> Session | None:
    _sweep_expired()
    session = _sessions.get(token)
    if session is None:
        return None
    if session.is_expired():
        destroy_session(token)
        return None
    session.touch()
    return session


def destroy_session(token: str) -> None:
    _sessions.pop(token, None)


def _sweep_expired() -> None:
    expired = [token for token, s in _sessions.items() if s.is_expired()]
    for token in expired:
        destroy_session(token)


def reset() -> None:
    """Test-only: clear all sessions between test cases. Not used by the app itself."""
    _sessions.clear()
