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

CORS_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

TOKEN_KEY = os.getenv("TOKEN_KEY", "wavs_token")

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@wavs.local").lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin12345")
ADMIN_FULL_NAME = os.getenv("ADMIN_FULL_NAME", "System Admin")

ALLOWED_VULNERABILITIES = {
    "sql_injection",
    "xss",
    "csrf",
    "broken_auth",
    "dir_traversal",
    "scan_all",
}
