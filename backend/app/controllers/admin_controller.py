"""Admin panel API controller."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.auth.session_guard import get_current_admin
from app.database import User, get_db
from app.schemas.admin import (
    AdminLoginRequest,
    AdminScanSummary,
    AdminScansResponse,
    AdminStatsResponse,
    AdminUserOptionsResponse,
    AdminUsersResponse,
)
from app.schemas.auth import AuthResponse, UserResponse
from app.services.admin_service import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.services import admin_service

router = APIRouter(prefix="/admin", tags=["admin"])


class AdminController:
    def __init__(self, service=admin_service):
        self.service = service

    def login(self, payload: AdminLoginRequest, db: Session = Depends(get_db)) -> AuthResponse:
        return self.service.login(db, payload)

    def me(self, current_admin: User = Depends(get_current_admin)) -> UserResponse:
        return current_admin

    def stats(
        self, current_admin: User = Depends(get_current_admin), db: Session = Depends(get_db)
    ) -> AdminStatsResponse:
        del current_admin
        return self.service.get_stats(db)

    def user_options(
        self, current_admin: User = Depends(get_current_admin), db: Session = Depends(get_db)
    ) -> AdminUserOptionsResponse:
        del current_admin
        return self.service.list_user_options(db)

    def users(
        self,
        page: int = Query(1, ge=1),
        page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
        current_admin: User = Depends(get_current_admin),
        db: Session = Depends(get_db),
    ) -> AdminUsersResponse:
        del current_admin
        return self.service.list_users(db, page, page_size)

    def delete_user(
        self,
        user_id: int,
        current_admin: User = Depends(get_current_admin),
        db: Session = Depends(get_db),
    ) -> dict[str, str]:
        return self.service.delete_user(db, current_admin, user_id)

    def scans(
        self,
        user_id: int = Query(..., description="Filter scans by user id"),
        page: int = Query(1, ge=1),
        page_size: int = Query(DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
        current_admin: User = Depends(get_current_admin),
        db: Session = Depends(get_db),
    ) -> AdminScansResponse:
        del current_admin
        return self.service.list_scans(db, user_id, page, page_size)

    def get_scan(
        self,
        scan_id: str,
        current_admin: User = Depends(get_current_admin),
        db: Session = Depends(get_db),
    ) -> AdminScanSummary:
        del current_admin
        return self.service.get_scan(db, scan_id)

    def delete_scan(
        self,
        scan_id: str,
        current_admin: User = Depends(get_current_admin),
        db: Session = Depends(get_db),
    ) -> dict[str, str]:
        del current_admin
        return self.service.delete_scan(db, scan_id)


_controller = AdminController()
router.add_api_route("/login", _controller.login, methods=["POST"], response_model=AuthResponse)
router.add_api_route("/me", _controller.me, methods=["GET"], response_model=UserResponse)
router.add_api_route("/stats", _controller.stats, methods=["GET"], response_model=AdminStatsResponse)
router.add_api_route("/users/options", _controller.user_options, methods=["GET"], response_model=AdminUserOptionsResponse)
router.add_api_route("/users", _controller.users, methods=["GET"], response_model=AdminUsersResponse)
router.add_api_route("/users/{user_id}", _controller.delete_user, methods=["DELETE"])
router.add_api_route("/scans", _controller.scans, methods=["GET"], response_model=AdminScansResponse)
router.add_api_route("/scans/{scan_id}", _controller.get_scan, methods=["GET"], response_model=AdminScanSummary)
router.add_api_route("/scans/{scan_id}", _controller.delete_scan, methods=["DELETE"])
