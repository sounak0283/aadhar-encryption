"""Regular (non-admin) user signup / login / logout / me — the people submitting Aadhaar numbers."""
from fastapi import APIRouter, Cookie, Depends, HTTPException, Request, Response

from app.crypto import password_utils
from app.deps import USER_SESSION_COOKIE_NAME, require_user_session
from app.models.user import UserLoginRequest, UserMeResponse, UserSignupRequest
from app.rate_limit import limiter
from app.services import user_session, users_service

router = APIRouter(prefix="/api/auth")


@router.post("/signup")
@limiter.limit("10/minute")
async def signup(request: Request, payload: UserSignupRequest):
    try:
        await users_service.create(payload.username, password_utils.hash_password(payload.password))
    except users_service.UsernameTakenError:
        raise HTTPException(status_code=409, detail="username already in use")
    return {"status": "ok"}


@router.post("/login")
@limiter.limit("10/minute")
async def login(request: Request, payload: UserLoginRequest, response: Response):
    user = await users_service.get_by_username(payload.username)
    if user is None or user["status"] != "active":
        raise HTTPException(status_code=401, detail="invalid credentials")

    if not password_utils.verify_password(payload.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="invalid credentials")

    token = user_session.create_session(user_id=str(user["_id"]), username=user["username"])
    response.set_cookie(
        key=USER_SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=user_session.SESSION_TTL_SECONDS,
    )
    return {"status": "ok"}


@router.get("/me", response_model=UserMeResponse)
async def me(session: user_session.Session = Depends(require_user_session)):
    return UserMeResponse(id=session.user_id, username=session.username)


@router.post("/logout")
async def logout(
    response: Response,
    user_session_token: str | None = Cookie(default=None, alias=USER_SESSION_COOKIE_NAME),
):
    if user_session_token:
        user_session.destroy_session(user_session_token)
    response.delete_cookie(USER_SESSION_COOKIE_NAME)
    return {"status": "ok"}
