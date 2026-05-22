"""Admin panel schemas."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from app.schemas.auth import UserResponse
from app.schemas.validators import AppEmail


class AdminLoginRequest(BaseModel):
    email: AppEmail
    password: str


class AdminUserSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: AppEmail
    full_name: str
    is_admin: bool
    created_at: str
    scan_count: int


class AdminScanSummary(BaseModel):
    scan_id: str
    user_id: int
    user_email: str
    user_name: str
    target_url: str
    status: str
    progress: int
    message: str
    vulnerabilities: list[str]
    results: list[dict]
    report_available: bool
    created_at: str | None
    updated_at: str | None


class AdminStatsResponse(BaseModel):
    total_users: int
    total_scans: int
    active_sessions: int
    scans_by_status: dict[str, int]
    recent_scans: list[AdminScanSummary]


class AdminUserOption(BaseModel):
    id: int
    email: AppEmail
    full_name: str
    scan_count: int


class AdminUserOptionsResponse(BaseModel):
    items: list[AdminUserOption]


class AdminUsersResponse(BaseModel):
    items: list[AdminUserSummary]
    total: int
    page: int
    page_size: int
    total_pages: int


class AdminScansResponse(BaseModel):
    items: list[AdminScanSummary]
    total: int
    page: int
    page_size: int
    total_pages: int


class AdminAuthResponse(BaseModel):
    token: str
    user: UserResponse
