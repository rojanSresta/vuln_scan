"""Authentication schemas."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.validators import AppEmail


class AuthRequest(BaseModel):
    full_name: str | None = None
    email: AppEmail
    password: str = Field(min_length=8, max_length=128)

    @field_validator("full_name")
    @classmethod
    def normalize_name(cls, value: str | None) -> str | None:
        if value is None:
            return value
        cleaned = re.sub(r"\s+", " ", value).strip()
        if not cleaned:
            raise ValueError("Full name is required")
        return cleaned


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: AppEmail
    full_name: str
    is_admin: bool = False


class AuthResponse(BaseModel):
    token: str
    user: UserResponse


class SignupResponse(BaseModel):
    message: str
