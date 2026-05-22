"""User scan history business logic."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.database.models import ScanRecord, User
from app.services.scan_service import ScanService


class HistoryService:
    def __init__(self, scan_service: ScanService | None = None):
        self.scan_service = scan_service or ScanService()

    def list_for_user(self, db: Session, user: User) -> dict[str, object]:
        records = db.execute(
            select(ScanRecord)
            .where(ScanRecord.user_id == user.id)
            .order_by(desc(ScanRecord.created_at))
        ).scalars()
        return {"items": [self.scan_service.serialize(record) for record in records]}

    def get_item(self, db: Session, user: User, scan_id: str) -> dict[str, object]:
        record = db.execute(
            select(ScanRecord).where(
                ScanRecord.scan_id == scan_id,
                ScanRecord.user_id == user.id,
            )
        ).scalar_one_or_none()
        if not record:
            raise HTTPException(status_code=404, detail="Scan not found")
        return self.scan_service.serialize(record)
