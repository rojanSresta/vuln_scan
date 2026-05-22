"""Scan data access layer"""

from typing import Optional, List
from sqlalchemy import select
from app.db.session import session_scope
from app.db.models import ScanRecord


class ScanRepository:
    """Repository for scan operations"""

    @staticmethod
    def find_by_id(scan_id: str, user_id: int) -> Optional[ScanRecord]:
        """Find a scan by ID and user"""
        with session_scope() as db:
            return db.execute(
                select(ScanRecord).where(
                    ScanRecord.scan_id == scan_id,
                    ScanRecord.user_id == user_id,
                )
            ).scalar_one_or_none()

    @staticmethod
    def find_or_raise(scan_id: str, user_id: int) -> ScanRecord:
        """Find a scan or raise exception"""
        from fastapi import HTTPException

        record = ScanRepository.find_by_id(scan_id, user_id)
        if not record:
            raise HTTPException(status_code=404, detail="Scan not found")
        return record

    @staticmethod
    def update(scan_id: str, **fields) -> None:
        """Update scan record"""
        from app.db.session import utc_now

        with session_scope() as db:
            record = db.execute(
                select(ScanRecord).where(ScanRecord.scan_id == scan_id)
            ).scalar_one_or_none()

            if not record:
                return

            for key, value in fields.items():
                setattr(record, key, value)
            record.updated_at = utc_now()

    @staticmethod
    def list_by_user(user_id: int, limit: int = 50) -> List[ScanRecord]:
        """List scans for a user"""
        with session_scope() as db:
            return db.execute(
                select(ScanRecord)
                .where(ScanRecord.user_id == user_id)
                .order_by(ScanRecord.created_at.desc())
                .limit(limit)
            ).scalars().all()
