"""Password hashing (bcrypt) and session token helpers."""

from __future__ import annotations

import hashlib
import hmac
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
        if stored_hash.startswith(_BCRYPT_PREFIXES):
            try:
                return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
            except ValueError:
                return False
        return PasswordHasher._verify_legacy(password, stored_hash)

    @staticmethod
    def needs_rehash(stored_hash: str) -> bool:
        return not stored_hash.startswith(_BCRYPT_PREFIXES)

    @staticmethod
    def _verify_legacy(password: str, stored_hash: str) -> bool:
        try:
            salt, digest_hex = stored_hash.split("$", 1)
        except ValueError:
            return False
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
        return hmac.compare_digest(candidate.hex(), digest_hex)


class TokenFactory:
    """Creates secure session tokens."""

    @staticmethod
    def create() -> str:
        return secrets.token_urlsafe(32)


# Simple aliases used across services
hash_password = PasswordHasher.hash
verify_password = PasswordHasher.verify
password_needs_rehash = PasswordHasher.needs_rehash
generate_session_token = TokenFactory.create
