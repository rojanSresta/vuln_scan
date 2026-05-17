"""Authentication routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, parse_bearer_token
from app.core.security import generate_session_token, hash_password, verify_password
from app.db import Session as UserSession
from app.db import User, get_db
from app.schemas.auth import AuthRequest, AuthResponse, UserResponse

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/signup", response_model=AuthResponse)
def signup(payload: AuthRequest, db: Session = Depends(get_db)) -> AuthResponse:
    if not payload.full_name:
        raise HTTPException(status_code=422, detail="Full name is required")

    existing = db.execute(select(User).where(User.email == payload.email.lower())).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists")

    user = User(
        email=payload.email.lower(),
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        is_admin=False,
    )
    db.add(user)
    db.flush()

    token = generate_session_token()
    db.add(UserSession(token=token, user_id=user.id))
    db.commit()
    db.refresh(user)
    return AuthResponse(token=token, user=user)


@router.post("/login", response_model=AuthResponse)
def login(payload: AuthRequest, db: Session = Depends(get_db)) -> AuthResponse:
    user = db.execute(select(User).where(User.email == payload.email.lower())).scalar_one_or_none()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = generate_session_token()
    db.add(UserSession(token=token, user_id=user.id))
    db.commit()
    return AuthResponse(token=token, user=user)


@router.get("/me", response_model=UserResponse)
def me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return current_user


@router.post("/logout")
def logout(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> dict[str, str]:
    token = parse_bearer_token(authorization)
    session = db.execute(select(UserSession).where(UserSession.token == token)).scalar_one_or_none()
    if session:
        db.delete(session)
        db.commit()
    return {"message": "Logged out"}
