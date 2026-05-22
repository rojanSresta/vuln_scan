"""Scan history API controller."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.auth.session_guard import get_current_user
from app.database import User, get_db
from app.services import history_service

router = APIRouter(tags=["history"])


class HistoryController:
    def __init__(self, service=history_service):
        self.service = service

    def list_history(
        self, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)
    ) -> dict[str, object]:
        return self.service.list_for_user(db, current_user)

    def get_item(
        self,
        scan_id: str,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> dict[str, object]:
        return self.service.get_item(db, current_user, scan_id)


_controller = HistoryController()
router.add_api_route("/history", _controller.list_history, methods=["GET"])
router.add_api_route("/history/{scan_id}", _controller.get_item, methods=["GET"])
