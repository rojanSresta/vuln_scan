"""Authentication API controller."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header
from sqlalchemy.orm import Session

from app.auth.session_guard import SessionGuard, get_current_user
from app.database import User, get_db
from app.schemas.auth import AuthRequest, AuthResponse, SignupResponse, UserResponse
from app.services import auth_service

router = APIRouter(prefix="/auth", tags=["auth"])


class AuthController:
    def __init__(self, service=auth_service):
        self.service = service

    def signup(self, payload: AuthRequest, db: Session = Depends(get_db)) -> SignupResponse:
        return self.service.signup(db, payload)

    def login(self, payload: AuthRequest, db: Session = Depends(get_db)) -> AuthResponse:
        return self.service.login(db, payload)

    def me(self, current_user: User = Depends(get_current_user)) -> UserResponse:
        return current_user

    def logout(
        self,
        authorization: str | None = Header(default=None),
        db: Session = Depends(get_db),
    ) -> dict[str, str]:
        token = SessionGuard.parse_token(authorization)
        return self.service.logout(db, token)


_controller = AuthController()
router.add_api_route("/signup", _controller.signup, methods=["POST"], response_model=SignupResponse)
router.add_api_route("/login", _controller.login, methods=["POST"], response_model=AuthResponse)
router.add_api_route("/me", _controller.me, methods=["GET"], response_model=UserResponse)
router.add_api_route("/logout", _controller.logout, methods=["POST"])
