"""Compatibility alias — prefer app.database in new code."""

from app.database import (
    Base,
    ScanRecord,
    Session,
    SessionLocal,
    User,
    UserSession,
    engine,
    get_db,
    init_db,
    session_scope,
    utc_now,
)

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
