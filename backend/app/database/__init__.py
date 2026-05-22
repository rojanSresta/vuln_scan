"""Database package."""

from app.database.base import Base
from app.database.connection import SessionLocal, engine, get_db, init_db, session_scope, utc_now
from app.database.models import ScanRecord, User, UserSession

# Backward-friendly alias
Session = UserSession

__all__ = [
    "Base",
    "ScanRecord",
    "Session",
    "SessionLocal",
    "User",
    "UserSession",
    "engine",
    "get_db",
    "init_db",
    "session_scope",
    "utc_now",
]
