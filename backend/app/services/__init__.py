"""Application services (business logic layer)."""

from app.services.admin_service import AdminService
from app.services.auth_service import AuthService
from app.services.history_service import HistoryService
from app.services.report_service import ReportService
from app.services.scan_service import ScanService

# Shared instances used by controllers
scan_service = ScanService()
auth_service = AuthService()
admin_service = AdminService(auth_service=auth_service, scan_service=scan_service)
history_service = HistoryService(scan_service=scan_service)
report_service = ReportService()

__all__ = [
    "AdminService",
    "AuthService",
    "HistoryService",
    "ReportService",
    "ScanService",
    "admin_service",
    "auth_service",
    "history_service",
    "report_service",
    "scan_service",
]
