"""History routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db import ScanRecord, User, get_db
from app.services.scan_jobs import serialize_scan

router = APIRouter(tags=["history"])


@router.get("/history")
def get_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> dict[str, object]:
    records = db.execute(
        select(ScanRecord)
        .where(ScanRecord.user_id == current_user.id)
        .order_by(desc(ScanRecord.created_at))
    ).scalars()
    return {"items": [serialize_scan(record) for record in records]}


@router.get("/history/{scan_id}")
def get_history_item(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    record = db.execute(
        select(ScanRecord).where(
            ScanRecord.scan_id == scan_id,
            ScanRecord.user_id == current_user.id,
        )
    ).scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")
    return serialize_scan(record)
