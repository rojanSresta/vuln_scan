"""In-memory scan tracking and persistence helpers."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select

from app.db import ScanRecord, session_scope, utc_now
from app.services.scanning.service import ManualVulnerabilityScanner

logger = logging.getLogger(__name__)

scan_jobs: dict[str, dict[str, Any]] = {}


def serialize_scan(record: ScanRecord) -> dict[str, Any]:
    return {
        "scan_id": record.scan_id,
        "target_url": record.target_url,
        "status": record.status,
        "progress": record.progress,
        "message": record.message,
        "vulnerabilities": record.vulnerabilities or [],
        "results": record.results or [],
        "report_available": record.status == "done",
        "created_at": record.created_at.isoformat() if record.created_at else None,
        "updated_at": record.updated_at.isoformat() if record.updated_at else None,
    }


def load_scan(scan_id: str, user_id: int) -> ScanRecord | None:
    with session_scope() as db:
        return db.execute(
            select(ScanRecord).where(
                ScanRecord.scan_id == scan_id,
                ScanRecord.user_id == user_id,
            )
        ).scalar_one_or_none()


def require_scan(scan_id: str, user_id: int) -> ScanRecord:
    record = load_scan(scan_id, user_id)
    if not record:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="Scan not found")
    return record


def update_scan_record(scan_id: str, **fields: Any) -> None:
    with session_scope() as db:
        record = db.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id)).scalar_one_or_none()
        if not record:
            return
        for key, value in fields.items():
            setattr(record, key, value)
        record.updated_at = utc_now()


def run_scan(scan_id: str, user_id: int, target_url: str, vulnerabilities: list[str]) -> None:
    del user_id
    job = scan_jobs[scan_id]

    try:
        scanner = ManualVulnerabilityScanner()
        job["status"] = "spidering"
        job["message"] = "Preparing scan..."
        job["progress"] = 2
        update_scan_record(scan_id, status="spidering", progress=2, message="Preparing scan...")
        logger.info("[%s] Manual scan start -> %s", scan_id, target_url)

        def on_progress(progress: int, message: str) -> None:
            status = "spidering" if progress < 35 else "scanning"
            job["progress"] = progress
            job["message"] = message
            job["status"] = status
            update_scan_record(scan_id, status=status, progress=progress, message=message)

        results = scanner.scan(
            target_url=target_url,
            vulnerabilities=vulnerabilities,
            progress_callback=on_progress,
        )

        job["results"] = results
        job["status"] = "done"
        job["progress"] = 100
        job["message"] = f"Scan complete - {len(results)} finding(s)"
        update_scan_record(
            scan_id,
            status="done",
            progress=100,
            message=job["message"],
            results=results,
        )
        logger.info("[%s] Done: %s findings", scan_id, len(results))

    except Exception as exc:
        logger.exception("[%s] Scan error: %s", scan_id, exc)
        job["status"] = "error"
        job["message"] = f"Scan failed: {exc}"
        job["progress"] = 0
        update_scan_record(
            scan_id,
            status="error",
            progress=0,
            message=job["message"],
            results=[],
        )
    finally:
        scan_jobs.pop(scan_id, None)
