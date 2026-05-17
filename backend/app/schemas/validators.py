"""Shared field validators."""

from __future__ import annotations

import re
from typing import Annotated

from pydantic import BeforeValidator

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(value: str) -> str:
    email = str(value).strip().lower()
    if not email or len(email) > 255:
        raise ValueError("Invalid email address")
    if not _EMAIL_RE.match(email):
        raise ValueError("Invalid email address")
    return email


AppEmail = Annotated[str, BeforeValidator(normalize_email)]
