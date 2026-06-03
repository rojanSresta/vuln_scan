"""Database connection and session management."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import DATABASE_URL
from app.database.base import Base

engine = create_engine(
    DATABASE_URL,
    future=True,
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    future=True,
    expire_on_commit=False,
)


def init_db() -> None:
    from app.database.setup import DatabaseSetup

    DatabaseSetup().run()


@contextmanager
def session_scope() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
