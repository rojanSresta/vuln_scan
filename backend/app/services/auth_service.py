"""User authentication business logic."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database.models import User, UserSession
from app.schemas.auth import AuthRequest, AuthResponse, SignupResponse, UserResponse
from app.security import PasswordHasher, TokenFactory


class AuthService:
    def signup(self, db: Session, payload: AuthRequest) -> SignupResponse:
        if not payload.full_name:
            raise HTTPException(status_code=422, detail="Full name is required")

        existing = db.execute(select(User).where(User.email == payload.email.lower())).scalar_one_or_none()
        if existing:
            raise HTTPException(status_code=409, detail="An account with this email already exists")

        db.add(
            User(
                email=payload.email.lower(),
                full_name=payload.full_name,
                password_hash=PasswordHasher.hash(payload.password),
                is_admin=False,
            )
        )
        db.commit()
        return SignupResponse(message="Signed up successfully. Please log in.")

    def login(self, db: Session, payload: AuthRequest) -> AuthResponse:
        user, token = self._authenticate(db, payload.email, payload.password, admin_only=False)
        return AuthResponse(token=token, user=user)

    def admin_login(self, db: Session, email: str, password: str) -> AuthResponse:
        user, token = self._authenticate(db, email, password, admin_only=True)
        return AuthResponse(token=token, user=user)

    def logout(self, db: Session, token: str) -> dict[str, str]:
        session = db.execute(select(UserSession).where(UserSession.token == token)).scalar_one_or_none()
        if session:
            db.delete(session)
            db.commit()
        return {"message": "Logged out"}

    def _authenticate(
        self, db: Session, email: str, password: str, *, admin_only: bool
    ) -> tuple[UserResponse, str]:
        user = db.execute(select(User).where(User.email == email.lower())).scalar_one_or_none()
        if not user or not PasswordHasher.verify(password, user.password_hash):
            detail = "Invalid admin credentials" if admin_only else "Invalid email or password"
            raise HTTPException(status_code=401, detail=detail)
        if admin_only and not user.is_admin:
            raise HTTPException(status_code=401, detail="Invalid admin credentials")

        token = TokenFactory.create()
        db.add(UserSession(token=token, user_id=user.id))
        db.commit()
        return user, token
