"""FastAPI dependencies — admin and regular-user session authentication."""
from fastapi import Cookie, Depends, HTTPException

from app.services import admin_session, user_session

SESSION_COOKIE_NAME = "admin_session"
USER_SESSION_COOKIE_NAME = "user_session"


async def require_admin_session(
    admin_session_token: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> admin_session.Session:
    if admin_session_token is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    session = admin_session.get_session(admin_session_token)
    if session is None:
        raise HTTPException(status_code=401, detail="session expired or invalid")
    return session


async def require_master_session(
    session: admin_session.Session = Depends(require_admin_session),
) -> admin_session.Session:
    if session.role != "master":
        raise HTTPException(status_code=403, detail="master admin only")
    return session


async def require_user_session(
    user_session_token: str | None = Cookie(default=None, alias=USER_SESSION_COOKIE_NAME),
) -> user_session.Session:
    if user_session_token is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    session = user_session.get_session(user_session_token)
    if session is None:
        raise HTTPException(status_code=401, detail="session expired or invalid")
    return session
