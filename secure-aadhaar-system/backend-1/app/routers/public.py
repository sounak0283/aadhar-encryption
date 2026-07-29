"""POST /api/aadhaar (now requires a logged-in user) and GET /api/my-submissions."""
from fastapi import APIRouter, Depends, HTTPException, Request

from app import db
from app.deps import require_user_session
from app.models.container import SubmitAadhaarRequest, SubmitAadhaarResponse
from app.models.user import MySubmissionListItem
from app.rate_limit import limiter
from app.services import submission_service, user_session
from app.validation import freshness_error, is_valid_aadhaar_number

router = APIRouter()


@router.post("/api/aadhaar", response_model=SubmitAadhaarResponse)
@limiter.limit("5/minute")
async def submit_aadhaar(
    request: Request,
    payload: SubmitAadhaarRequest,
    session: user_session.Session = Depends(require_user_session),
):
    if not is_valid_aadhaar_number(payload.aadhaar_number):
        raise HTTPException(status_code=400, detail="invalid Aadhaar number")

    reason = freshness_error(payload.ts)
    if reason is not None:
        raise HTTPException(status_code=400, detail=reason)

    try:
        reference_id, masked_preview = await submission_service.encrypt_and_store(
            payload.aadhaar_number, submitted_by=session.user_id
        )
    except submission_service.NoActiveAdminsError:
        raise HTTPException(status_code=503, detail="no admin is registered yet — submissions are not accepted")

    return SubmitAadhaarResponse(reference_id=reference_id, masked_preview=masked_preview)


@router.get("/api/my-submissions", response_model=list[MySubmissionListItem])
async def my_submissions(session: user_session.Session = Depends(require_user_session)):
    items = []
    async for doc in db.containers_collection().find({"submitted_by": session.user_id}):
        items.append(
            MySubmissionListItem(
                id=str(doc["_id"]), created_at=db.as_utc(doc["created_at"]), masked_preview=doc["masked_preview"]
            )
        )
    items.sort(key=lambda item: item.created_at, reverse=True)
    return items
