"""Admin panel business logic."""

from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from app.database.models import ScanRecord, User, UserSession
from app.schemas.admin import (
    AdminLoginRequest,
    AdminScanSummary,
    AdminScansResponse,
    AdminStatsResponse,
    AdminUserOption,
    AdminUserOptionsResponse,
    AdminUserSummary,
    AdminUsersResponse,
)
from app.schemas.auth import AuthResponse, UserResponse
from app.services.auth_service import AuthService
from app.services.scan_service import ScanService

DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 50


class AdminService:
    def __init__(self, auth_service: AuthService | None = None, scan_service: ScanService | None = None):
        self.auth_service = auth_service or AuthService()
        self.scan_service = scan_service or ScanService()

    def login(self, db: Session, payload: AdminLoginRequest) -> AuthResponse:
        return self.auth_service.admin_login(db, payload.email, payload.password)

    def get_stats(self, db: Session) -> AdminStatsResponse:
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

        return AdminStatsResponse(
            total_users=total_users,
            total_scans=total_scans,
            active_sessions=active_sessions,
            scans_by_status=scans_by_status,
            recent_scans=[self._to_admin_scan(record) for record in recent_records],
        )

    def list_user_options(self, db: Session) -> AdminUserOptionsResponse:
        rows = db.execute(self._user_rows_query().order_by(User.full_name, User.email)).all()
        items = [
            AdminUserOption(id=user.id, email=user.email, full_name=user.full_name, scan_count=scan_count)
            for user, scan_count in rows
        ]
        return AdminUserOptionsResponse(items=items)

    def list_users(self, db: Session, page: int, page_size: int) -> AdminUsersResponse:
        total = db.scalar(select(func.count()).select_from(User)) or 0
        page, total_pages = self._paginate(total, page, page_size)
        offset = (page - 1) * page_size

        rows = db.execute(
            self._user_rows_query().order_by(desc(User.created_at)).limit(page_size).offset(offset)
        ).all()

        return AdminUsersResponse(
            items=[self._to_admin_user(user, scan_count) for user, scan_count in rows],
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )

    def delete_user(self, db: Session, current_admin: User, user_id: int) -> dict[str, str]:
        if user_id == current_admin.id:
            raise HTTPException(status_code=400, detail="You cannot delete your own admin account")

        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        if user.is_admin:
            raise HTTPException(status_code=400, detail="Admin accounts cannot be deleted from the panel")

        scans = db.execute(select(ScanRecord).where(ScanRecord.user_id == user_id)).scalars()
        for scan in scans:
            self._remove_report_file(scan.report_path)

        db.delete(user)
        db.commit()
        return {"message": "User account removed"}

    def list_scans(self, db: Session, user_id: int, page: int, page_size: int) -> AdminScansResponse:
        user = db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        total = (
            db.scalar(select(func.count()).select_from(ScanRecord).where(ScanRecord.user_id == user_id)) or 0
        )
        page, total_pages = self._paginate(total, page, page_size)
        offset = (page - 1) * page_size

        records = db.execute(
            select(ScanRecord)
            .where(ScanRecord.user_id == user_id)
            .order_by(desc(ScanRecord.created_at))
            .limit(page_size)
            .offset(offset)
        ).scalars()

        return AdminScansResponse(
            items=[self._to_admin_scan(record) for record in records],
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
        )

    def get_scan(self, db: Session, scan_id: str) -> AdminScanSummary:
        record = db.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id)).scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=404, detail="Scan not found")
        return self._to_admin_scan(record)

    def delete_scan(self, db: Session, scan_id: str) -> dict[str, str]:
        record = db.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id)).scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=404, detail="Scan not found")

        self._remove_report_file(record.report_path)
        self.scan_service.clear_active(scan_id)

        db.delete(record)
        db.commit()
        return {"message": "Scan record removed"}

    def _to_admin_scan(self, record: ScanRecord) -> AdminScanSummary:
        payload = self.scan_service.serialize(record)
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

    def _to_admin_user(self, user: User, scan_count: int) -> AdminUserSummary:
        return AdminUserSummary(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            is_admin=user.is_admin,
            created_at=user.created_at.isoformat() if user.created_at else "",
            scan_count=scan_count,
        )

    def _user_rows_query(self):
        return (
            select(User, func.count(ScanRecord.id))
            .outerjoin(ScanRecord, ScanRecord.user_id == User.id)
            .group_by(User.id)
        )

    def _paginate(self, total: int, page: int, page_size: int) -> tuple[int, int]:
        total_pages = max(1, (total + page_size - 1) // page_size)
        safe_page = min(max(page, 1), total_pages)
        return safe_page, total_pages

    @staticmethod
    def _remove_report_file(report_path: str | None) -> None:
        if not report_path:
            return
        try:
            path = Path(report_path)
            if path.is_file():
                path.unlink()
        except OSError:
            pass
