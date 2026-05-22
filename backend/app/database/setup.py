"""Creates tables and seeds the default admin user."""

from __future__ import annotations

import logging

from sqlalchemy import select, text

from app.config import ADMIN_EMAIL, ADMIN_FULL_NAME, ADMIN_PASSWORD
from app.database.base import Base
from app.database.connection import SessionLocal, engine
from app.database.models import User
from app.security import PasswordHasher

logger = logging.getLogger(__name__)


class DatabaseSetup:
    def run(self) -> None:
        Base.metadata.create_all(bind=engine)
        self._ensure_admin_column()
        self._seed_admin()

    def _ensure_admin_column(self) -> None:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN "
                    "NOT NULL DEFAULT FALSE"
                )
            )

    def _seed_admin(self) -> None:
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
                    password_hash=PasswordHasher.hash(ADMIN_PASSWORD),
                    is_admin=True,
                )
            )
            db.commit()
            logger.info("Default admin account created for %s", ADMIN_EMAIL)
