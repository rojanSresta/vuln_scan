"""Scan schemas."""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, field_validator

from app.core.config import ALLOWED_VULNERABILITIES


class ScanRequest(BaseModel):
    target_url: str
    vulnerabilities: List[str]

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return value

    @field_validator("vulnerabilities")
    @classmethod
    def validate_vulns(cls, value: List[str]) -> List[str]:
        if not value:
            raise ValueError("Select at least one vulnerability type")
        for item in value:
            if item not in ALLOWED_VULNERABILITIES:
                raise ValueError(f"Unknown vulnerability type: {item}")
        return value


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: int
    message: str
