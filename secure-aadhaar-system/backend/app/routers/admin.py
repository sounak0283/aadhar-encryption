"""Admin login / register / manage sub-admins / list / decrypt / logout endpoints."""
import secrets
from datetime import date

from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, Response

from app import db
from app.config import get_admin_setup_token, get_app_totp_key
from app.crypto import totp_utils
from app.crypto.exceptions import BadSignatureError, BadTagError
from app.deps import SESSION_COOKIE_NAME, require_admin_session, require_master_session
from app.models.admin_identity import (
    AdminLoginRequest,
    AdminSummary,
    CreateSubAdminConfirmRequest,
    CreateSubAdminConfirmResponse,
    CreateSubAdminStartRequest,
    MeResponse,
    RegisterConfirmRequest,
    RegisterStartRequest,
    RegisterStartResponse,
    RegisterStatusResponse,
)
from app.models.audit_report import AuditLogEvent, AuditReportRow
from app.models.container import DecryptResponse, SubmissionListItem
from app.providers.identity_provider import load_identity_provider
from app.rate_limit import limiter
from app.services import (
    admin_identity_service,
    admin_management_service,
    admin_registration_service,
    admin_session,
    admins_service,
    audit_pdf_service,
    audit_report_service,
    audit_service,
    decrypt_service,
)

router = APIRouter(prefix="/api/admin")


# ============================================================================
# First-admin (master) self-registration — gated by ADMIN_SETUP_TOKEN
# ============================================================================


@router.get("/register/status", response_model=RegisterStatusResponse)
async def register_status():
    return RegisterStatusResponse(registered=await admins_service.any_admin_exists())


@router.post("/register/start", response_model=RegisterStartResponse)
@limiter.limit("5/minute")
async def register_start(request: Request, payload: RegisterStartRequest):
    try:
        expected_token = get_admin_setup_token()
    except EnvironmentError:
        raise HTTPException(status_code=503, detail="admin registration is not configured on this server")

    if not secrets.compare_digest(payload.setup_token, expected_token):
        raise HTTPException(status_code=403, detail="invalid setup token")

    try:
        registration_token, otpauth_uri, manual_secret, qr_code_png_base64 = await admin_registration_service.start(
            payload.username, payload.password
        )
    except admin_registration_service.AlreadyRegisteredError:
        raise HTTPException(status_code=409, detail="an admin already exists")
    except (admin_registration_service.WeakPasswordError, admin_registration_service.InvalidUsernameError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return RegisterStartResponse(
        registration_token=registration_token,
        otpauth_uri=otpauth_uri,
        manual_secret=manual_secret,
        qr_code_png_base64=qr_code_png_base64,
    )


@router.post("/register/confirm")
@limiter.limit("10/minute")
async def register_confirm(request: Request, payload: RegisterConfirmRequest):
    try:
        await admin_registration_service.confirm(payload.registration_token, payload.totp_code)
    except admin_registration_service.AlreadyRegisteredError:
        raise HTTPException(status_code=409, detail="an admin already exists")
    except admin_registration_service.RegistrationNotFoundError:
        raise HTTPException(status_code=404, detail="unknown or expired registration")
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid authenticator code")

    return {"status": "ok"}


# ============================================================================
# Login / session / logout
# ============================================================================


@router.post("/login")
async def login(payload: AdminLoginRequest, response: Response):
    admin = await admins_service.get_by_username(payload.username)
    if admin is None or admin["status"] != "active":
        # Same generic message as a wrong password — don't reveal whether the
        # username exists at all.
        await audit_service.record_admin_login(payload.username, "invalid_credentials")
        raise HTTPException(status_code=401, detail="invalid credentials")

    totp_secret = totp_utils.decrypt_totp_secret(admin["totp_secret_encrypted"], get_app_totp_key())
    if not totp_utils.verify_totp_code(totp_secret, payload.totp_code):
        await audit_service.record_admin_login(payload.username, "invalid_credentials")
        raise HTTPException(status_code=401, detail="invalid credentials")

    provider = load_identity_provider(admin)
    try:
        unlocked = provider.unlock(payload.password)
    except BadTagError:
        await audit_service.record_admin_login(payload.username, "invalid_credentials")
        raise HTTPException(status_code=401, detail="invalid credentials")

    token = admin_session.create_session(
        admin_id=str(admin["_id"]), username=admin["username"], role=admin["role"], unlocked_identity=unlocked
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=admin_session.SESSION_TTL_SECONDS,
    )
    await audit_service.record_admin_login(payload.username, "success")
    return {"status": "ok"}


@router.get("/me", response_model=MeResponse)
async def me(session: admin_session.Session = Depends(require_admin_session)):
    return MeResponse(id=session.admin_id, username=session.username, role=session.role)


@router.post("/logout")
async def logout(
    response: Response,
    admin_session_token: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
):
    if admin_session_token:
        session = admin_session.get_session(admin_session_token)
        admin_session.destroy_session(admin_session_token)
        if session is not None:
            await audit_service.record_admin_logout(session.username)
    response.delete_cookie(SESSION_COOKIE_NAME)
    return {"status": "ok"}


# ============================================================================
# Master-only: manage sub-admins
# ============================================================================


@router.get("/admins", response_model=list[AdminSummary])
async def list_admins(session: admin_session.Session = Depends(require_master_session)):
    admins = await admins_service.list_all()
    return [
        AdminSummary(
            id=str(a["_id"]),
            username=a["username"],
            role=a["role"],
            status=a["status"],
            created_at=db.as_utc(a["created_at"]),
            created_by=a.get("created_by"),
        )
        for a in admins
    ]


@router.post("/admins/start", response_model=RegisterStartResponse)
@limiter.limit("10/minute")
async def create_sub_admin_start(
    request: Request,
    payload: CreateSubAdminStartRequest,
    session: admin_session.Session = Depends(require_master_session),
):
    try:
        registration_token, otpauth_uri, manual_secret, qr_code_png_base64 = await admin_management_service.start(
            session.admin_id, payload.username, payload.password
        )
    except admin_management_service.UsernameTakenError:
        raise HTTPException(status_code=409, detail="username already in use")
    except (admin_management_service.WeakPasswordError, admin_management_service.InvalidUsernameError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return RegisterStartResponse(
        registration_token=registration_token,
        otpauth_uri=otpauth_uri,
        manual_secret=manual_secret,
        qr_code_png_base64=qr_code_png_base64,
    )


@router.post("/admins/confirm", response_model=CreateSubAdminConfirmResponse)
@limiter.limit("15/minute")
async def create_sub_admin_confirm(
    request: Request,
    payload: CreateSubAdminConfirmRequest,
    session: admin_session.Session = Depends(require_master_session),
):
    try:
        new_admin_id, granted = await admin_management_service.confirm(
            session.admin_id, session.unlocked_identity, payload.registration_token, payload.totp_code
        )
    except admin_management_service.RegistrationNotFoundError:
        raise HTTPException(status_code=404, detail="unknown or expired registration")
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid authenticator code")

    return CreateSubAdminConfirmResponse(admin_id=new_admin_id, containers_granted=granted)


# ============================================================================
# Submissions: list (any admin) / decrypt (any admin, only for records they
# have a wrapped_deks entry for)
# ============================================================================


@router.get("/submissions", response_model=list[SubmissionListItem])
async def list_submissions(session: admin_session.Session = Depends(require_admin_session)):
    items = []
    async for doc in db.containers_collection().find():
        items.append(
            SubmissionListItem(
                id=doc["reference_id"], created_at=db.as_utc(doc["created_at"]), masked_preview=doc["masked_preview"]
            )
        )
    items.sort(key=lambda item: item.created_at, reverse=True)
    return items


@router.get("/audit-report", response_model=list[AuditReportRow])
async def audit_report(
    from_date: date = Query(..., description="Start of the date range, inclusive, YYYY-MM-DD"),
    to_date: date = Query(..., description="End of the date range, inclusive, YYYY-MM-DD"),
    session: admin_session.Session = Depends(require_admin_session),
):
    try:
        rows = await audit_report_service.generate_report(from_date, to_date)
    except audit_report_service.InvalidDateRangeError:
        raise HTTPException(status_code=400, detail="from_date must not be after to_date")
    return rows


@router.get("/audit-report/pdf")
async def audit_report_pdf(
    from_date: date = Query(..., description="Start of the date range, inclusive, YYYY-MM-DD"),
    to_date: date = Query(..., description="End of the date range, inclusive, YYYY-MM-DD"),
    columns: str | None = Query(
        None,
        description="Comma-separated subset of date,reference_id,masked_aadhaar_no,request_datetime. Defaults to all four.",
    ),
    session: admin_session.Session = Depends(require_admin_session),
):
    selected_columns = [c.strip() for c in columns.split(",") if c.strip()] if columns else None
    try:
        pdf_bytes = await audit_pdf_service.generate_pdf(from_date, to_date, columns=selected_columns)
    except audit_report_service.InvalidDateRangeError:
        raise HTTPException(status_code=400, detail="from_date must not be after to_date")
    except audit_pdf_service.InvalidColumnError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    filename = f"audit-report_{from_date.isoformat()}_{to_date.isoformat()}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/audit-log", response_model=list[AuditLogEvent])
async def audit_log(
    from_date: date = Query(..., description="Start of the date range, inclusive, YYYY-MM-DD"),
    to_date: date = Query(..., description="End of the date range, inclusive, YYYY-MM-DD"),
    session: admin_session.Session = Depends(require_admin_session),
):
    """Every recorded admin/user login, logout, submission, and decrypt event
    within the range, newest first — the real per-hit timestamps behind the
    submission-only audit-report above."""
    if from_date > to_date:
        raise HTTPException(status_code=400, detail="from_date must not be after to_date")
    return await audit_service.list_events(from_date, to_date)


@router.post("/submissions/{submission_id}/decrypt", response_model=DecryptResponse)
async def decrypt_submission(
    submission_id: str,
    response: Response,
    session: admin_session.Session = Depends(require_admin_session),
):
    doc = await db.containers_collection().find_one({"reference_id": submission_id})
    if doc is None:
        raise HTTPException(status_code=404, detail="not found")

    sender_verify_key = admin_identity_service.load_sender_verify_key()

    container = {
        "alg": doc["alg"],
        "wrapped_deks": doc["wrapped_deks"],
        "sealed_number_b64": doc["sealed_number_b64"],
        "signature_b64": doc["signature_b64"],
    }

    try:
        number = decrypt_service.decrypt_container(container, session.admin_id, session.unlocked_identity, sender_verify_key)
    except BadSignatureError:
        await audit_service.record_decrypt(submission_id, "bad_signature", session.username)
        raise HTTPException(status_code=400, detail="bad_signature")
    except BadTagError:
        await audit_service.record_decrypt(submission_id, "crypto_error", session.username)
        raise HTTPException(status_code=400, detail="crypto_error")

    await audit_service.record_decrypt(submission_id, "success", session.username)
    response.headers["Cache-Control"] = "no-store"
    return DecryptResponse(aadhaar_number=number)
