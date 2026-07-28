"""Pydantic schemas for the `containers` collection and related API payloads."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class Container(BaseModel):
    alg: str
    wrapped_deks: dict[str, str]
    sealed_number_b64: str
    signature_b64: str


class SubmitAadhaarRequest(BaseModel):
    aadhaar_number: str = Field(min_length=12, max_length=12, pattern=r"^\d{12}$")


class SubmitAadhaarResponse(BaseModel):
    reference_id: str
    masked_preview: str


class SubmissionListItem(BaseModel):
    id: str
    created_at: datetime
    masked_preview: str


class DecryptResponse(BaseModel):
    aadhaar_number: str
