"""Application configuration."""

from __future__ import annotations

import os

APP_TITLE = "VulnScan API"
APP_DESCRIPTION = "Manual web vulnerability scanner backend"
APP_VERSION = "2.0.0"

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://wavs:wavs@localhost:5432/wavs",
)

_cors_raw = os.getenv("CORS_ORIGINS", "")
CORS_ORIGINS = (
    [origin.strip() for origin in _cors_raw.split(",") if origin.strip()]
    if _cors_raw
    else [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
)

TOKEN_KEY = os.getenv("TOKEN_KEY", "wavs_token")

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@wavs.local").lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin12345")
ADMIN_FULL_NAME = os.getenv("ADMIN_FULL_NAME", "System Admin")

ALLOWED_VULNERABILITIES = {
    "sql_injection",
    "xss",
    "dir_traversal",
    "missing_headers",
    "default_credentials",
    "scan_all",
}
