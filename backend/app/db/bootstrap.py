"""Schema helpers and default admin seeding."""

from __future__ import annotations

import logging

from sqlalchemy import select, text

from app.core.config import ADMIN_EMAIL, ADMIN_FULL_NAME, ADMIN_PASSWORD
from app.core.security import hash_password
from app.db.base import Base
from app.db.models import User
from app.db.session import SessionLocal, engine

logger = logging.getLogger(__name__)


def _ensure_user_admin_column() -> None:
    with engine.begin() as connection:
        connection.execute(
            text(
                "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN "
                "NOT NULL DEFAULT FALSE"
            )
        )


def seed_default_admin() -> None:
    with SessionLocal() as db:
        admin = db.execute(select(User).where(User.email == ADMIN_EMAIL)).scalar_one_or_none()
        if admin:
            if not admin.is_admin:
                admin.is_admin = True
                db.commit()
            return

        db.add(
            User(
                email=ADMIN_EMAIL,
                full_name=ADMIN_FULL_NAME,
                password_hash=hash_password(ADMIN_PASSWORD),
                is_admin=True,
            )
        )
        db.commit()
        logger.info("Default admin account created for %s", ADMIN_EMAIL)


def bootstrap_database() -> None:
    Base.metadata.create_all(bind=engine)
    _ensure_user_admin_column()
    seed_default_admin()
