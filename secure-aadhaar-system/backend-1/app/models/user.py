"""Pydantic schemas for regular (non-admin) user auth and their own submissions."""
from datetime import datetime

from pydantic import BaseModel, Field


class UserSignupRequest(BaseModel):
    username: str = Field(min_length=3)
    password: str = Field(min_length=8)


class UserLoginRequest(BaseModel):
    username: str
    password: str


class UserMeResponse(BaseModel):
    id: str
    username: str


class MySubmissionListItem(BaseModel):
    id: str
    created_at: datetime
    masked_preview: str
