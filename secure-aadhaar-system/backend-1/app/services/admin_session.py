"""
admin_session.py
In-memory, TTL-based session store holding an unlocked admin identity
capability for the duration of an active session — provider-agnostic (works
the same whether that capability is a raw local private key or a future
AWS KMS-backed handle). Sliding 5-minute idle timeout: any authenticated
request refreshes the expiry; a session that goes quiet for 5 minutes is
swept and its capability is closed.
"""
import secrets
import time
from dataclasses import dataclass, field

from app.providers.identity_provider import UnlockedIdentity

SESSION_TTL_SECONDS = 5 * 60


@dataclass
class Session:
    admin_id: str
    username: str
    role: str  # "master" | "sub"
    unlocked_identity: UnlockedIdentity
    expires_at: float = field(default=0.0)

    def touch(self) -> None:
        self.expires_at = time.monotonic() + SESSION_TTL_SECONDS

    def is_expired(self) -> bool:
        return time.monotonic() >= self.expires_at


_sessions: dict[str, Session] = {}


def create_session(admin_id: str, username: str, role: str, unlocked_identity: UnlockedIdentity) -> str:
    token = secrets.token_urlsafe(32)
    session = Session(admin_id=admin_id, username=username, role=role, unlocked_identity=unlocked_identity)
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
    session = _sessions.pop(token, None)
    if session is not None:
        session.unlocked_identity.close()


def _sweep_expired() -> None:
    expired = [token for token, s in _sessions.items() if s.is_expired()]
    for token in expired:
        destroy_session(token)


def reset() -> None:
    """Test-only: clear all sessions between test cases. Not used by the app itself."""
    _sessions.clear()
