"""Pydantic schemas for the date-range audit report (admin-only)."""
from datetime import datetime

from pydantic import BaseModel


class AuditReportRow(BaseModel):
    date: str  # YYYY-MM-DD, always present, even for dates with no submissions
    unique_reference_no: str | None = None
    reference_id: str | None = None
    masked_aadhaar_no: str | None = None
    request_datetime: datetime | None = None
