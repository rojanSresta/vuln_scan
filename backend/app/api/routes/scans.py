"""Scan routes."""

from __future__ import annotations

import os
import uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select

from app.api.deps import get_current_user
from app.db import ScanRecord, User, session_scope, utc_now
from app.schemas.scan import ScanRequest, ScanStatus
from app.services.reporting.pdf import generate_pdf_report
from app.services.scan_jobs import load_scan, require_scan, run_scan, scan_jobs, update_scan_record

router = APIRouter(prefix="/scan", tags=["scan"])


@router.post("/start")
def start_scan(
    req: ScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    scan_id = str(uuid.uuid4())
    vulnerabilities = ["scan_all"] if "scan_all" in req.vulnerabilities else req.vulnerabilities

    scan_jobs[scan_id] = {
        "scan_id": scan_id,
        "status": "queued",
        "progress": 0,
        "message": "Scan queued...",
        "target_url": req.target_url,
        "vulnerabilities": vulnerabilities,
        "results": [],
        "report_path": None,
    }

    with session_scope() as db:
        db.add(
            ScanRecord(
                scan_id=scan_id,
                user_id=current_user.id,
                target_url=req.target_url,
                vulnerabilities=vulnerabilities,
                status="queued",
                progress=0,
                message="Scan queued...",
                results=[],
                report_path=None,
                created_at=utc_now(),
                updated_at=utc_now(),
            )
        )

    background_tasks.add_task(run_scan, scan_id, current_user.id, req.target_url, vulnerabilities)
    return {"scan_id": scan_id, "message": "Scan started"}


@router.get("/status/{scan_id}", response_model=ScanStatus)
def get_status(scan_id: str, current_user: User = Depends(get_current_user)) -> ScanStatus:
    job = scan_jobs.get(scan_id)
    if job:
        record = load_scan(scan_id, current_user.id)
        if not record:
            raise HTTPException(status_code=404, detail="Scan not found")
        return ScanStatus(
            scan_id=scan_id,
            status=job["status"],
            progress=job["progress"],
            message=job["message"],
        )

    record = require_scan(scan_id, current_user.id)
    return ScanStatus(
        scan_id=record.scan_id,
        status=record.status,
        progress=record.progress,
        message=record.message,
    )


@router.get("/results/{scan_id}")
def get_results(scan_id: str, current_user: User = Depends(get_current_user)) -> dict[str, Any]:
    record = require_scan(scan_id, current_user.id)
    if record.status not in {"done", "error"}:
        raise HTTPException(status_code=400, detail="Scan not finished yet")
    return {
        "scan_id": record.scan_id,
        "target_url": record.target_url,
        "status": record.status,
        "results": record.results or [],
        "created_at": record.created_at.isoformat() if record.created_at else None,
    }


@router.get("/report/{scan_id}")
def download_report(scan_id: str, current_user: User = Depends(get_current_user)) -> FileResponse:
    record = require_scan(scan_id, current_user.id)
    if record.status != "done":
        raise HTTPException(status_code=400, detail="Scan not finished yet")

    report_path = record.report_path
    if not report_path or not os.path.exists(report_path):
        report_path = generate_pdf_report(
            scan_id=scan_id,
            target_url=record.target_url,
            results=record.results or [],
        )
        with session_scope() as db:
            persisted = db.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id)).scalar_one()
            persisted.report_path = report_path
            persisted.updated_at = utc_now()

    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename=f"vuln_report_{scan_id[:8]}.pdf",
    )
