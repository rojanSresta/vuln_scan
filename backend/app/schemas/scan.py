"""Scan request and response schemas"""

from pydantic import BaseModel
from typing import List, Optional


class ScanRequest(BaseModel):
    """Scan creation request"""

    target_url: str
    vulnerabilities: List[str] = ["sql_injection", "xss", "csrf", "broken_auth", "dir_traversal"]


class ScanResponse(BaseModel):
    """Scan response"""

    scan_id: str
    target_url: str
    status: str
    progress: int = 0
    message: str = ""
    results: List[dict] = []

    class Config:
        from_attributes = True
