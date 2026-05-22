"""Scan job management and execution."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy import select

from app.database import ScanRecord, session_scope, utc_now
from app.scanner import ScanCancelledError, ScanEngine
from app.schemas.scan import ScanStatus

logger = logging.getLogger(__name__)


class ScanService:
    def __init__(self):
        self._active_scans: dict[str, dict[str, bool]] = {}

    def serialize(self, record: ScanRecord) -> dict[str, Any]:
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

    def start(self, user_id: int, target_url: str, vulnerabilities: list[str]) -> dict[str, str]:
        scan_id = str(uuid.uuid4())
        vulns = ["scan_all"] if "scan_all" in vulnerabilities else vulnerabilities
        self._active_scans[scan_id] = {"cancel_requested": False}

        with session_scope() as db:
            db.add(
                ScanRecord(
                    scan_id=scan_id,
                    user_id=user_id,
                    target_url=target_url,
                    vulnerabilities=vulns,
                    status="queued",
                    progress=0,
                    message="Scan queued...",
                    results=[],
                    report_path=None,
                    created_at=utc_now(),
                    updated_at=utc_now(),
                )
            )
        return {"scan_id": scan_id, "message": "Scan started"}

    def get_status(self, scan_id: str, user_id: int) -> ScanStatus:
        record = self.require_scan(scan_id, user_id)
        return ScanStatus(
            scan_id=record.scan_id,
            status=record.status,
            progress=record.progress,
            message=record.message,
        )

    def cancel(self, scan_id: str, user_id: int) -> ScanStatus:
        self.require_scan(scan_id, user_id)
        state = self._active_scans.get(scan_id)
        if state and not state.get("cancel_requested"):
            state["cancel_requested"] = True
            self._update_record(scan_id, status="cancelled", message="Cancelling scan...")
        record = self._load_scan(scan_id, user_id)
        if not record:
            raise HTTPException(status_code=404, detail="Scan not found")
        return self.get_status(scan_id, user_id)

    def get_results(self, scan_id: str, user_id: int) -> dict[str, Any]:
        record = self.require_scan(scan_id, user_id)
        if record.status not in {"done", "error"}:
            raise HTTPException(status_code=400, detail="Scan not finished yet")
        return {
            "scan_id": record.scan_id,
            "target_url": record.target_url,
            "status": record.status,
            "results": record.results or [],
            "created_at": record.created_at.isoformat() if record.created_at else None,
        }

    def run_background(self, scan_id: str, target_url: str, vulnerabilities: list[str]) -> None:
        self._active_scans.setdefault(scan_id, {"cancel_requested": False})

        try:
            def ensure_not_cancelled() -> None:
                if self._active_scans.get(scan_id, {}).get("cancel_requested"):
                    raise ScanCancelledError("Scan cancelled by user.")

            engine = ScanEngine(cancel_callback=ensure_not_cancelled)
            ensure_not_cancelled()
            self._update_record(scan_id, status="scanning", progress=2, message="Scanning...")
            logger.info("[%s] Manual scan start -> %s", scan_id, target_url)

            def on_progress(progress: int, _message: str) -> None:
                ensure_not_cancelled()
                self._update_record(scan_id, status="scanning", progress=progress, message="Scanning...")

            results = engine.run(
                target_url=target_url,
                vulnerabilities=vulnerabilities,
                progress_callback=on_progress,
            )

            ensure_not_cancelled()
            self._update_record(
                scan_id,
                status="done",
                progress=100,
                message=f"Scan complete - {len(results)} finding(s)",
                results=results,
            )
            logger.info("[%s] Done: %s findings", scan_id, len(results))

        except ScanCancelledError:
            logger.info("[%s] Scan cancelled", scan_id)
            self._update_record(scan_id, status="cancelled", message="Scan cancelled.", results=[])
        except Exception as exc:
            logger.exception("[%s] Scan error: %s", scan_id, exc)
            self._update_record(
                scan_id,
                status="error",
                progress=0,
                message=f"Scan failed: {exc}",
                results=[],
            )
        finally:
            self._active_scans.pop(scan_id, None)

    def clear_active(self, scan_id: str) -> None:
        self._active_scans.pop(scan_id, None)

    def _load_scan(self, scan_id: str, user_id: int) -> ScanRecord | None:
        with session_scope() as db:
            return db.execute(
                select(ScanRecord).where(
                    ScanRecord.scan_id == scan_id,
                    ScanRecord.user_id == user_id,
                )
            ).scalar_one_or_none()

    def require_scan(self, scan_id: str, user_id: int) -> ScanRecord:
        record = self._load_scan(scan_id, user_id)
        if not record:
            raise HTTPException(status_code=404, detail="Scan not found")
        return record

    def _update_record(self, scan_id: str, **fields: Any) -> None:
        with session_scope() as db:
            record = db.execute(select(ScanRecord).where(ScanRecord.scan_id == scan_id)).scalar_one_or_none()
            if not record:
                return
            for key, value in fields.items():
                setattr(record, key, value)
            record.updated_at = utc_now()
