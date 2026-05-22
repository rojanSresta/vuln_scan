"""PDF report generation service."""

from __future__ import annotations

from typing import Any

from app.services.reporting.pdf import generate_pdf_report


class ReportService:
    def create(self, scan_id: str, target_url: str, results: list[dict[str, Any]]) -> str:
        return generate_pdf_report(scan_id=scan_id, target_url=target_url, results=results)
