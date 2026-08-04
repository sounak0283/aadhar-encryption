"""Pydantic schemas for the date-range audit report and audit-log (admin-only)."""
from datetime import datetime

from pydantic import BaseModel


class AuditReportRow(BaseModel):
    date: str  # YYYY-MM-DD, always present, even for dates with no submissions
    reference_id: str | None = None
    masked_aadhaar_no: str | None = None
    request_datetime: datetime | None = None


class AuditLogEvent(BaseModel):
    ts: datetime
    action: str  # "admin_login" | "admin_logout" | "user_login" | "user_logout" | "submit" | "decrypt"
    result: str
    username: str | None = None
    container_id: str | None = None
