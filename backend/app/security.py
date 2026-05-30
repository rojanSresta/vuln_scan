"""Password hashing (bcrypt) and session token helpers."""

from __future__ import annotations

import secrets

import bcrypt

_BCRYPT_PREFIXES = ("$2a$", "$2b$", "$2y$")


class PasswordHasher:
    """Handles password hashing and verification."""

    @staticmethod
    def hash(password: str) -> str:
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        return hashed.decode("utf-8")

    @staticmethod
    def verify(password: str, stored_hash: str) -> bool:
        if not stored_hash.startswith(_BCRYPT_PREFIXES):
            return False
        try:
            return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
        except ValueError:
            return False


class TokenFactory:
    """Creates secure session tokens."""

    @staticmethod
    def create() -> str:
        return secrets.token_urlsafe(32)


hash_password = PasswordHasher.hash
verify_password = PasswordHasher.verify
generate_session_token = TokenFactory.create
