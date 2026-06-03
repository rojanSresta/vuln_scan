"""Application settings."""

from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
PROJECT_ROOT = BASE_DIR.parent


def load_env_file(path: Path) -> None:
    """Load simple KEY=value pairs without overriding real environment vars."""
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


load_env_file(BASE_DIR / ".env")
load_env_file(PROJECT_ROOT / ".env")

APP_TITLE = "VulnScan API"
APP_DESCRIPTION = "Manual web vulnerability scanner backend"
APP_VERSION = "2.0.0"

def _normalize_database_url(url: str | None) -> str | None:
    """Neon and other hosts often provide postgres:// URLs; SQLAlchemy needs psycopg."""
    if not url:
        return None
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    if url.startswith("postgresql://") and "+psycopg" not in url:
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


DATABASE_URL = _normalize_database_url(os.getenv("DATABASE_URL"))

_cors_raw = os.getenv("CORS_ORIGINS", "").strip()
if _cors_raw == "*":
    CORS_ORIGINS = ["*"]
elif _cors_raw:
    CORS_ORIGINS = [origin.strip() for origin in _cors_raw.split(",") if origin.strip()]
else:
    CORS_ORIGINS =  [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ADMIN_FULL_NAME = os.getenv("ADMIN_FULL_NAME")

ALLOWED_VULNERABILITIES = {
    "sql_injection",
    "xss",
    "dir_traversal",
    "missing_headers",
    "default_credentials",
    "scan_all",
}
