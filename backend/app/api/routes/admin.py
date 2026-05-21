"""Admin panel routes."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_admin
from app.core.security import generate_session_token, verify_password
from app.db import ScanRecord, Session as UserSession
from app.db import User, get_db
from app.schemas.admin import (
    AdminAuthResponse,
    AdminLoginRequest,
    AdminScanSummary,
    AdminScansResponse,
    AdminStatsResponse,
    AdminUserOption,
    AdminUserOptionsResponse,
    AdminUserSummary,
    AdminUsersResponse,
)

DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 50
from app.schemas.auth import UserResponse
from app.services.scan_jobs import serialize_scan

router = APIRouter(prefix="/admin", tags=["admin"])


def _serialize_admin_scan(record: ScanRecord) -> AdminScanSummary:
    payload = serialize_scan(record)
    user = record.user
    return AdminScanSummary(
        scan_id=payload["scan_id"],
        user_id=record.user_id,
        user_email=user.email,
        user_name=user.full_name,
        target_url=payload["target_url"],
        status=payload["status"],
        progress=payload["progress"],
        message=payload["message"],
        vulnerabilities=payload["vulnerabilities"],
        results=payload["results"],
        report_available=payload["report_available"],
        created_at=payload["created_at"],
        updated_at=payload["updated_at"],
    )


def _serialize_admin_user(user: User, scan_count: int) -> AdminUserSummary:
    return AdminUserSummary(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        is_admin=user.is_admin,
        created_at=user.created_at.isoformat() if user.created_at else "",
        scan_count=scan_count,
    )


def _paginate(total: int, page: int, page_size: int) -> tuple[int, int]:
    total_pages = max(1, (total + page_size - 1) // page_size)
    safe_page = min(max(page, 1), total_pages)
    return safe_page, total_pages


def _remove_report_file(report_path: str | None) -> None:
    if not report_path:
        return
    try:
        path = Path(report_path)
        if path.is_file():
            path.unlink()
    except OSError:
        pass


@router.post("/login", response_model=AdminAuthResponse)
def admin_login(payload: AdminLoginRequest, db: Session = Depends(get_db)) -> AdminAuthResponse:
    user = db.execute(select(User).where(User.email == payload.email.lower())).scalar_one_or_none()
    if not user or not user.is_admin or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid admin credentials")

    token = generate_session_token()
    db.add(UserSession(token=token, user_id=user.id))
    db.commit()
    return AdminAuthResponse(token=token, user=user)


@router.get("/me", response_model=UserResponse)
def admin_me(current_admin: User = Depends(get_current_admin)) -> UserResponse:
    return current_admin


@router.get("/stats", response_model=AdminStatsResponse)
def admin_stats(
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> AdminStatsResponse:
    del current_admin

    total_users = db.scalar(select(func.count()).select_from(User)) or 0
    total_scans = db.scalar(select(func.count()).select_from(ScanRecord)) or 0
    active_sessions = db.scalar(select(func.count()).select_from(UserSession)) or 0

    status_rows = db.execute(
        select(ScanRecord.status, func.count())
        .group_by(ScanRecord.status)
        .order_by(ScanRecord.status)
    ).all()
    scans_by_status = {status: count for status, count in status_rows}

    recent_records = db.execute(
        select(ScanRecord).order_by(desc(ScanRecord.created_at)).limit(8)
    ).scalars()
    recent_scans = [_serialize_admin_scan(record) for record in recent_records]

    return AdminStatsResponse(
        total_users=total_users,
        total_scans=total_scans,
        active_sessions=active_sessions,
        scans_by_status=scans_by_status,
        recent_scans=recent_scans,
    )


def _user_rows_query():
    return (
        select(User, func.count(ScanRecord.id))
        .outerjoin(ScanRecord, ScanRecord.user_id == User.id)
        .group_by(User.id)
    )


@router.get("/users/options", response_model=AdminUserOptionsResponse)
def list_user_options(
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> AdminUserOptionsResponse:
    del current_admin

    rows = db.execute(_user_rows_query().order_by(User.full_name, User.email)).all()
    items = [
        AdminUserOption(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            scan_count=scan_count,
        )
        for user, scan_count in rows
    ]
    return AdminUserOptionsResponse(items=items)


@router.get("/users", response_model=AdminUsersResponse)
def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> AdminUsersResponse:
    del current_admin

    total = db.scalar(select(func.count()).select_from(User)) or 0
    page, total_pages = _paginate(total, page, page_size)
    offset = (page - 1) * page_size

    rows = db.execute(
        _user_rows_query().order_by(desc(User.created_at)).limit(page_size).offset(offset)
    ).all()

    items = [_serialize_admin_user(user, scan_count) for user, scan_count in rows]
    return AdminUsersResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    if user_id == current_admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own admin account")

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.is_admin:
        raise HTTPException(status_code=400, detail="Admin accounts cannot be deleted from the panel")

    scans = db.execute(select(ScanRecord).where(ScanRecord.user_id == user_id)).scalars()
    for scan in scans:
        _remove_report_file(scan.report_path)

    db.delete(user)
    db.commit()
    return {"message": "User account removed"}


@router.get("/scans", response_model=AdminScansResponse)
def list_scans(
    user_id: int = Query(..., description="Filter scans by user id"),
    page: int = Query(1, ge=1),
    page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> AdminScansResponse:
    del current_admin

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    total = (
        db.scalar(select(func.count()).select_from(ScanRecord).where(ScanRecord.user_id == user_id)) or 0
    )
    page, total_pages = _paginate(total, page, page_size)
    offset = (page - 1) * page_size

    records = db.execute(
        select(ScanRecord)
        .where(ScanRecord.user_id == user_id)
        .order_by(desc(ScanRecord.created_at))
        .limit(page_size)
        .offset(offset)
    ).scalars()
    return AdminScansResponse(
        items=[_serialize_admin_scan(record) for record in records],
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/scans/{scan_id}", response_model=AdminScanSummary)
def get_scan(
    scan_id: str,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> AdminScanSummary:
    del current_admin

    record = db.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id)).scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _serialize_admin_scan(record)


@router.delete("/scans/{scan_id}")
def delete_scan(
    scan_id: str,
    current_admin: User = Depends(get_current_admin),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    del current_admin

    record = db.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id)).scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    _remove_report_file(record.report_path)

    from app.services.scan_jobs import scan_jobs

    scan_jobs.pop(scan_id, None)

    db.delete(record)
    db.commit()
    return {"message": "Scan record removed"}
