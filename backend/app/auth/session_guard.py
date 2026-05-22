"""Protects API routes — validates bearer tokens."""

from __future__ import annotations

from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import User, UserSession, get_db


class SessionGuard:
    @staticmethod
    def parse_token(authorization: str | None) -> str:
        if not authorization:
            raise HTTPException(status_code=401, detail="Missing Authorization header")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token:
            raise HTTPException(status_code=401, detail="Invalid Authorization header")
        return token

    @staticmethod
    def get_user(
        authorization: str | None = Header(default=None),
        db: Session = Depends(get_db),
    ) -> User:
        token = SessionGuard.parse_token(authorization)
        session = db.execute(select(UserSession).where(UserSession.token == token)).scalar_one_or_none()
        if not session:
            raise HTTPException(status_code=401, detail="Invalid or expired session")
        return session.user

    @staticmethod
    def get_admin(current_user: User = Depends(get_user)) -> User:
        if not current_user.is_admin:
            raise HTTPException(status_code=403, detail="Admin access required")
        return current_user


# FastAPI dependency aliases
get_current_user = SessionGuard.get_user
get_current_admin = SessionGuard.get_admin
parse_bearer_token = SessionGuard.parse_token
