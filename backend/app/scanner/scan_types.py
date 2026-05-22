"""Scanner data types and constants."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List
from urllib.parse import parse_qs, urlparse

ProgressCallback = Callable[[int, str], None]


class ScanCancelledError(Exception):
    """Raised when a scan is cancelled by the user."""


DEFAULT_VULNERABILITIES = [
    "sql_injection",
    "xss",
    "dir_traversal",
    "missing_headers",
    "default_credentials",
]

SECURITY_HEADERS = (
    ("Strict-Transport-Security", "Medium", "HSTS"),
    ("X-Content-Type-Options", "Low", "MIME sniffing protection"),
    ("X-Frame-Options", "Medium", "clickjacking protection"),
    ("Content-Security-Policy", "Medium", "content security policy"),
    ("Referrer-Policy", "Low", "referrer leakage control"),
    ("Permissions-Policy", "Informational", "browser feature restrictions"),
)

RISK_CODES = {"High": 3, "Medium": 2, "Low": 1, "Informational": 0}
SQL_ERROR_PATTERNS = [
    r"sql syntax",
    r"mysql",
    r"postgresql",
    r"sqlite",
    r"odbc",
    r"ora-\d+",
    r"unclosed quotation mark",
    r"syntax error near",
]
TRAVERSAL_SUCCESS_PATTERNS = [
    r"root:.*:0:0",
    r"\[extensions\]",
    r"\[fonts\]",
]


@dataclass
class FormField:
    name: str
    field_type: str = "text"
    value: str = ""


@dataclass
class FormRecord:
    page_url: str
    action_url: str
    method: str
    fields: List[FormField] = field(default_factory=list)


@dataclass
class PageRecord:
    url: str
    status_code: int
    headers: Dict[str, str]
    text: str
    content_type: str
    forms: List[FormRecord] = field(default_factory=list)
    links: List[str] = field(default_factory=list)

    @property
    def query_params(self) -> Dict[str, List[str]]:
        return parse_qs(urlparse(self.url).query, keep_blank_values=True)


@dataclass
class VulnerabilityFinding:
    name: str
    risk: str
    url: str
    description: str
    solution: str
    explanation: str
    reference: str = ""
    cwe_id: str = ""
    wasc_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "risk": self.risk,
            "risk_code": RISK_CODES[self.risk],
            "url": self.url,
            "description": self.description,
            "solution": self.solution,
            "reference": self.reference,
            "cwe_id": self.cwe_id,
            "wasc_id": self.wasc_id,
            "explanation": self.explanation,
        }


@dataclass
class CrawlContext:
    target_url: str
    pages: List[PageRecord]
