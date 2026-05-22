"""Shared scanning primitives."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

import requests

logger = logging.getLogger(__name__)

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


class HTMLDocumentParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: List[str] = []
        self.forms: List[FormRecord] = []
        self._current_form: Optional[Dict[str, Any]] = None

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attr_map = {key.lower(): value or "" for key, value in attrs}
        if tag == "a":
            href = attr_map.get("href", "").strip()
            if href:
                self.links.append(urljoin(self.base_url, href))
        elif tag == "form":
            action = urljoin(self.base_url, attr_map.get("action", "") or self.base_url)
            method = (attr_map.get("method", "get") or "get").lower()
            self._current_form = {
                "page_url": self.base_url,
                "action_url": action,
                "method": method,
                "fields": [],
            }
        elif tag == "input" and self._current_form is not None:
            name = attr_map.get("name", "").strip()
            if name:
                self._current_form["fields"].append(
                    FormField(
                        name=name,
                        field_type=(attr_map.get("type", "text") or "text").lower(),
                        value=attr_map.get("value", ""),
                    )
                )
        elif tag == "textarea" and self._current_form is not None:
            name = attr_map.get("name", "").strip()
            if name:
                self._current_form["fields"].append(FormField(name=name, field_type="textarea"))
        elif tag == "select" and self._current_form is not None:
            name = attr_map.get("name", "").strip()
            if name:
                self._current_form["fields"].append(FormField(name=name, field_type="select"))

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(FormRecord(**self._current_form))
            self._current_form = None


class HttpClient:
    def __init__(self, cancel_callback: Callable[[], None] | None = None):
        self.session = requests.Session()
        self.cancel_callback = cancel_callback
        self.session.headers.update(
            {
                "User-Agent": "WAVS-Manual-Scanner/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )

    def get(self, url: str, params: Optional[Dict[str, str]] = None) -> requests.Response:
        self._check_cancelled()
        return self.session.get(url, params=params, timeout=12, allow_redirects=True)

    def post(self, url: str, data: Dict[str, str]) -> requests.Response:
        self._check_cancelled()
        return self.session.post(url, data=data, timeout=12, allow_redirects=True)

    def _check_cancelled(self) -> None:
        if self.cancel_callback:
            self.cancel_callback()


class WebCrawler:
    def __init__(self, client: HttpClient, max_pages: int = 12):
        self.client = client
        self.max_pages = max_pages

    def crawl(self, target_url: str, progress_callback: Optional[ProgressCallback] = None) -> CrawlContext:
        parsed_target = urlparse(target_url)
        visited = set()
        queue = [target_url]
        pages: List[PageRecord] = []

        while queue and len(pages) < self.max_pages:
            current = queue.pop(0)
            normalized = self._normalize_url(current)
            if normalized in visited:
                continue

            visited.add(normalized)
            if progress_callback:
                progress_callback(
                    min(35, 5 + len(pages) * 3),
                    f"Crawling pages with BFS… {len(pages) + 1} page(s) visited",
                )

            try:
                response = self.client.get(current)
            except requests.RequestException as exc:
                logger.debug("Skipping %s during crawl: %s", current, exc)
                continue

            content_type = response.headers.get("Content-Type", "")
            text = response.text if "text/html" in content_type or not content_type else response.text[:0]
            parser = HTMLDocumentParser(response.url)
            if text:
                try:
                    parser.feed(text)
                except Exception:
                    logger.debug("HTML parse failed for %s", response.url)

            page = PageRecord(
                url=response.url,
                status_code=response.status_code,
                headers=dict(response.headers),
                text=text,
                content_type=content_type,
                forms=parser.forms,
                links=parser.links,
            )
            pages.append(page)

            for link in parser.links:
                if self._should_visit(link, parsed_target) and self._normalize_url(link) not in visited:
                    queue.append(link)

        return CrawlContext(target_url=target_url, pages=pages)

    def _should_visit(self, url: str, target: Any) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        if parsed.netloc != target.netloc:
            return False
        if parsed.fragment:
            return False
        return True

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.params, parsed.query, ""))


class VulnerabilityCheck:
    category = ""

    def __init__(self, client: HttpClient):
        self.client = client

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        raise NotImplementedError

    def _build_reference(self, title: str) -> str:
        return f"Manual heuristic detection for {title}"
