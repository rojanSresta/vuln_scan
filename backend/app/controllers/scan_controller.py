"""Scan API controller."""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends
from fastapi.responses import FileResponse
from sqlalchemy import select

from app.auth.session_guard import get_current_user
from app.database import ScanRecord, User, get_db, session_scope, utc_now
from app.schemas.scan import ScanRequest, ScanStatus
from app.services import report_service, scan_service

router = APIRouter(prefix="/scan", tags=["scan"])


class ScanController:
    def __init__(self, scans=scan_service, reports=report_service):
        self.scans = scans
        self.reports = reports

    def start(
        self,
        req: ScanRequest,
        background_tasks: BackgroundTasks,
        current_user: User = Depends(get_current_user),
    ) -> dict[str, str]:
        result = self.scans.start(current_user.id, req.target_url, req.vulnerabilities)
        vulns = ["scan_all"] if "scan_all" in req.vulnerabilities else req.vulnerabilities
        background_tasks.add_task(
            self.scans.run_background,
            result["scan_id"],
            req.target_url,
            vulns,
        )
        return result

    def status(self, scan_id: str, current_user: User = Depends(get_current_user)) -> ScanStatus:
        return self.scans.get_status(scan_id, current_user.id)

    def cancel(self, scan_id: str, current_user: User = Depends(get_current_user)) -> ScanStatus:
        return self.scans.cancel(scan_id, current_user.id)

    def results(self, scan_id: str, current_user: User = Depends(get_current_user)) -> dict[str, Any]:
        return self.scans.get_results(scan_id, current_user.id)

    def download_report(self, scan_id: str, current_user: User = Depends(get_current_user)) -> FileResponse:
        record = self.scans.require_scan(scan_id, current_user.id)
        if record.status != "done":
            from fastapi import HTTPException

            raise HTTPException(status_code=400, detail="Scan not finished yet")

        report_path = record.report_path
        if not report_path or not os.path.exists(report_path):
            report_path = self.reports.create(
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


_controller = ScanController()
router.add_api_route("/start", _controller.start, methods=["POST"])
router.add_api_route("/status/{scan_id}", _controller.status, methods=["GET"], response_model=ScanStatus)
router.add_api_route("/cancel/{scan_id}", _controller.cancel, methods=["POST"], response_model=ScanStatus)
router.add_api_route("/results/{scan_id}", _controller.results, methods=["GET"])
router.add_api_route("/report/{scan_id}", _controller.download_report, methods=["GET"])
