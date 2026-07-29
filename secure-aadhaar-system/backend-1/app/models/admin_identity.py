"""Pydantic schemas for admin auth, registration, and admin-management payloads."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class AdminLoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class MeResponse(BaseModel):
    id: str
    username: str
    role: Literal["master", "sub"]


class RegisterStatusResponse(BaseModel):
    registered: bool


class RegisterStartRequest(BaseModel):
    setup_token: str
    username: str = Field(min_length=3)
    password: str = Field(min_length=12)


class RegisterStartResponse(BaseModel):
    registration_token: str
    otpauth_uri: str
    manual_secret: str
    qr_code_png_base64: str


class RegisterConfirmRequest(BaseModel):
    registration_token: str
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class CreateSubAdminStartRequest(BaseModel):
    username: str = Field(min_length=3)
    password: str = Field(min_length=12)


class CreateSubAdminConfirmRequest(BaseModel):
    registration_token: str
    totp_code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class CreateSubAdminConfirmResponse(BaseModel):
    admin_id: str
    containers_granted: int


class AdminSummary(BaseModel):
    id: str
    username: str
    role: Literal["master", "sub"]
    status: Literal["active", "disabled"]
    created_at: datetime
    created_by: str | None
