"""Base vulnerability check class"""

from typing import List
from app.services.scanning.base import CrawlContext, VulnerabilityFinding


class BaseVulnerabilityCheck:
    """Base class for all vulnerability checks"""

    category: str = ""

    def __init__(self, client):
        self.client = client

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        """Scan for vulnerabilities"""
        raise NotImplementedError

    def _build_reference(self, title: str) -> str:
        """Build reference URL for vulnerability"""
        return f"Manual heuristic detection for {title}"
