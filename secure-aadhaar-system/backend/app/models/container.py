"""Pydantic schemas for the `containers` collection and related API payloads."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Container(BaseModel):
    alg: str
    wrapped_deks: dict[str, str]
    sealed_number_b64: str
    signature_b64: str


class SubmitAadhaarRequest(BaseModel):
    aadhaar_number: str = Field(min_length=12, max_length=12, pattern=r"^\d{12}$")
    # Explicit informed consent, analogous to UIDAI Auth API's mandatory
    # rc="Y" attribute ("Aadhaar number holder consent to do the Aadhaar
    # based authentication... Without explicit informed consent... AUA/Sub-AUA
    # application should not call this API"). Must be true — there is no
    # meaningful default, so it's required rather than defaulted.
    consent: bool = Field(...)
    # Client-supplied capture timestamp, analogous to UIDAI Pid's "ts"
    # attribute, used by the router for the replay/freshness window check
    # (see app/validation.py: is_within_freshness_window). Must be timezone-aware.
    ts: datetime = Field(...)

    @field_validator("consent")
    @classmethod
    def _consent_must_be_true(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("consent must be true — explicit informed consent is required to submit")
        return value

    @field_validator("ts")
    @classmethod
    def _ts_must_be_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("ts must be timezone-aware (e.g. end with 'Z' or a UTC offset)")
        return value


class SubmitAadhaarResponse(BaseModel):
    reference_id: str
    masked_preview: str


class SubmissionListItem(BaseModel):
    id: str
    created_at: datetime
    masked_preview: str


class DecryptResponse(BaseModel):
    aadhaar_number: str
