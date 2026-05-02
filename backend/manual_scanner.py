"""
manual_scanner.py
Lightweight OOP vulnerability scanner with a simple BFS crawler.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse
import logging
import re

import requests

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[int, str], None]

DEFAULT_VULNERABILITIES = [
    "sql_injection",
    "xss",
    "csrf",
    "broken_auth",
    "dir_traversal",
]

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

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
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
            if not name:
                return
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

    def handle_endtag(self, tag: str):
        if tag == "form" and self._current_form is not None:
            self.forms.append(FormRecord(**self._current_form))
            self._current_form = None


class HttpClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "WAVS-Manual-Scanner/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )

    def get(self, url: str, params: Optional[Dict[str, str]] = None) -> requests.Response:
        return self.session.get(url, params=params, timeout=12, allow_redirects=True)

    def post(self, url: str, data: Dict[str, str]) -> requests.Response:
        return self.session.post(url, data=data, timeout=12, allow_redirects=True)


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


class SQLInjectionCheck(VulnerabilityCheck):
    category = "sql_injection"
    payloads = ["'", "\"", "' OR '1'='1", "1 OR 1=1--"]

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        tested = set()

        for page in context.pages:
            for param in page.query_params:
                key = (page.url.split("?")[0], param)
                if key in tested:
                    continue
                tested.add(key)

                for payload in self.payloads:
                    response = self._probe_query(page.url, param, payload)
                    if not response:
                        continue
                    body = response.text.lower()
                    if response.status_code >= 500 or any(re.search(pattern, body) for pattern in SQL_ERROR_PATTERNS):
                        findings.append(
                            VulnerabilityFinding(
                                name="SQL Injection",
                                risk="High",
                                url=response.url,
                                description="A parameter reacted to SQL-style payloads with database error behaviour.",
                                solution="Use parameterised queries and validate or constrain user input before it reaches the database layer.",
                                explanation="The application appears to build database queries unsafely, so crafted input may alter SQL execution.",
                                reference=self._build_reference("SQL injection"),
                                cwe_id="89",
                                wasc_id="19",
                            )
                        )
                        break

        if findings:
            return findings[:1]

        for page in context.pages:
            for form in page.forms:
                candidate_fields = [field for field in form.fields if field.field_type in {"text", "search", "textarea", "select", "email", "number"}]
                if not candidate_fields:
                    continue
                for payload in self.payloads:
                    submission = {field.name: field.value or "1" for field in form.fields}
                    submission[candidate_fields[0].name] = payload
                    try:
                        response = self._submit_form(form, submission)
                    except requests.RequestException:
                        continue
                    body = response.text.lower()
                    if response.status_code >= 500 or any(re.search(pattern, body) for pattern in SQL_ERROR_PATTERNS):
                        findings.append(
                            VulnerabilityFinding(
                                name="SQL Injection",
                                risk="High",
                                url=response.url,
                                description="A form submission reacted to SQL-style payloads with database error behaviour.",
                                solution="Use parameterised queries and validate or constrain user input before it reaches the database layer.",
                                explanation="The application appears to build database queries unsafely, so crafted input may alter SQL execution.",
                                reference=self._build_reference("SQL injection"),
                                cwe_id="89",
                                wasc_id="19",
                            )
                        )
                        return findings[:1]

        return findings[:1]

    def _probe_query(self, url: str, param: str, payload: str) -> Optional[requests.Response]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        flat_params = {key: values[0] if values else "" for key, values in params.items()}
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
        try:
            return self.client.get(clean_url, params=flat_params)
        except requests.RequestException:
            return None

    def _submit_form(self, form: FormRecord, data: Dict[str, str]) -> requests.Response:
        if form.method == "post":
            return self.client.post(form.action_url, data)
        return self.client.get(form.action_url, params=data)


class XSSCheck(VulnerabilityCheck):
    category = "xss"
    payload = "<script>alert(1337)</script>"

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        if self._scan_query_reflections(context.pages):
            findings.append(self._finding(context.target_url))
        elif self._scan_form_reflections(context.pages):
            findings.append(self._finding(context.target_url))
        return findings[:1]

    def _scan_query_reflections(self, pages: Sequence[PageRecord]) -> bool:
        for page in pages:
            for param in page.query_params:
                response = self._probe_query(page.url, param)
                if response and self.payload in response.text:
                    return True
        return False

    def _scan_form_reflections(self, pages: Sequence[PageRecord]) -> bool:
        for page in pages:
            for form in page.forms:
                candidate_fields = [field for field in form.fields if field.field_type not in {"hidden", "password", "submit"}]
                if not candidate_fields:
                    continue
                submission = {field.name: field.value or "test" for field in form.fields}
                submission[candidate_fields[0].name] = self.payload
                try:
                    response = self._submit_form(form, submission)
                except requests.RequestException:
                    continue
                if self.payload in response.text:
                    return True
        return False

    def _probe_query(self, url: str, param: str) -> Optional[requests.Response]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [self.payload]
        flat_params = {key: values[0] if values else "" for key, values in params.items()}
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
        try:
            return self.client.get(clean_url, params=flat_params)
        except requests.RequestException:
            return None

    def _submit_form(self, form: FormRecord, data: Dict[str, str]) -> requests.Response:
        if form.method == "post":
            return self.client.post(form.action_url, data)
        return self.client.get(form.action_url, params=data)

    def _finding(self, url: str) -> VulnerabilityFinding:
        return VulnerabilityFinding(
            name="Cross Site Scripting (Reflected)",
            risk="High",
            url=url,
            description="A payload was reflected back into the response without output encoding.",
            solution="Encode untrusted output before rendering it in HTML and enforce a strict Content Security Policy.",
            explanation="The page appears to echo attacker-controlled input directly into the browser, which can allow script execution.",
            reference=self._build_reference("reflected XSS"),
            cwe_id="79",
            wasc_id="8",
        )


class CSRFCheck(VulnerabilityCheck):
    category = "csrf"
    token_keywords = ("csrf", "xsrf", "token", "authenticity")
    state_keywords = ("login", "signin", "signup", "register", "password", "update", "delete", "reset", "profile")

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        for page in context.pages:
            for form in page.forms:
                if form.method != "post":
                    continue
                if not self._looks_state_changing(form):
                    continue
                if any(self._has_token_name(field.name) for field in form.fields):
                    continue
                return [
                    VulnerabilityFinding(
                        name="Absence of Anti-CSRF Tokens",
                        risk="Medium",
                        url=form.action_url,
                        description="A state-changing form does not appear to include a CSRF token.",
                        solution="Add a unique server-validated CSRF token to every state-changing form submission.",
                        explanation="Without a per-request token, another site may be able to trigger sensitive actions for a logged-in user.",
                        reference=self._build_reference("CSRF"),
                        cwe_id="352",
                        wasc_id="9",
                    )
                ]
        return []

    def _has_token_name(self, name: str) -> bool:
        lowered = name.lower()
        return any(keyword in lowered for keyword in self.token_keywords)

    def _looks_state_changing(self, form: FormRecord) -> bool:
        action_bits = f"{form.page_url} {form.action_url}".lower()
        return any(keyword in action_bits for keyword in self.state_keywords) or any(
            field.field_type == "password" for field in form.fields
        )


class BrokenAuthCheck(VulnerabilityCheck):
    category = "broken_auth"
    session_param_keywords = ("session", "sid", "token", "auth")
    login_keywords = ("login", "signin", "auth", "session", "account")

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []

        insecure_login_form = self._find_insecure_login_form(context.pages)
        if insecure_login_form:
            findings.append(
                VulnerabilityFinding(
                    name="Weak Authentication Method",
                    risk="High",
                    url=insecure_login_form.page_url,
                    description="A login form appears to submit credentials over GET or plain HTTP.",
                    solution="Serve authentication flows only over HTTPS and submit credentials with POST requests.",
                    explanation="Credential handling looks weak enough that passwords or session data may leak through logs, URLs, or the network.",
                    reference=self._build_reference("broken authentication"),
                    cwe_id="287",
                    wasc_id="2",
                )
            )

        session_in_url = self._find_session_id_in_url(context.pages)
        if session_in_url:
            findings.append(
                VulnerabilityFinding(
                    name="Session ID in URL Rewrite",
                    risk="Medium",
                    url=session_in_url.url,
                    description="Session-like values appear in the URL query string.",
                    solution="Store session identifiers in secure cookies instead of URLs.",
                    explanation="Session tokens in URLs are easier to leak through browser history, logs, and referrer headers.",
                    reference=self._build_reference("session token exposure"),
                    cwe_id="598",
                    wasc_id="13",
                )
            )

        weak_cookie_page = self._find_weak_cookie_page(context.pages)
        if weak_cookie_page:
            findings.append(weak_cookie_page)

        return findings[:3]

    def _find_insecure_login_form(self, pages: Sequence[PageRecord]) -> Optional[FormRecord]:
        for page in pages:
            for form in page.forms:
                if not self._is_auth_form(form):
                    continue
                if form.method == "get" or urlparse(form.action_url).scheme != "https":
                    return form
        return None

    def _find_session_id_in_url(self, pages: Sequence[PageRecord]) -> Optional[PageRecord]:
        for page in pages:
            for param in page.query_params:
                lowered = param.lower()
                if any(keyword in lowered for keyword in self.session_param_keywords):
                    return page
        return None

    def _find_weak_cookie_page(self, pages: Sequence[PageRecord]) -> Optional[VulnerabilityFinding]:
        for page in pages:
            if not any(keyword in page.url.lower() for keyword in self.login_keywords):
                continue
            cookie_header = page.headers.get("Set-Cookie", "")
            if not cookie_header:
                continue
            lowered = cookie_header.lower()
            if "httponly" not in lowered:
                return VulnerabilityFinding(
                    name="Cookie No HttpOnly Flag",
                    risk="Medium",
                    url=page.url,
                    description="A session cookie was set without the HttpOnly attribute.",
                    solution="Mark authentication and session cookies as HttpOnly.",
                    explanation="Cookies readable by JavaScript are easier to steal when any script injection happens elsewhere in the app.",
                    reference=self._build_reference("session cookie hardening"),
                    cwe_id="1004",
                    wasc_id="13",
                )
            if urlparse(page.url).scheme == "https" and "secure" not in lowered:
                return VulnerabilityFinding(
                    name="Cookie Without Secure Flag",
                    risk="Medium",
                    url=page.url,
                    description="A cookie on an HTTPS page was set without the Secure attribute.",
                    solution="Mark authentication and session cookies as Secure.",
                    explanation="Cookies without the Secure flag can be exposed if the browser ever sends them over an unencrypted request.",
                    reference=self._build_reference("secure cookie attribute"),
                    cwe_id="614",
                    wasc_id="13",
                )
        return None

    def _is_auth_form(self, form: FormRecord) -> bool:
        if any(field.field_type == "password" for field in form.fields):
            return True
        combined = f"{form.page_url} {form.action_url}".lower()
        return any(keyword in combined for keyword in self.login_keywords)


class DirectoryTraversalCheck(VulnerabilityCheck):
    category = "dir_traversal"
    candidate_keywords = ("file", "path", "page", "template", "folder", "doc", "document", "download", "image")
    payloads = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..\\..\\..\\windows\\win.ini",
    ]

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        tested = set()
        for page in context.pages:
            for param in page.query_params:
                if not any(keyword in param.lower() for keyword in self.candidate_keywords):
                    continue
                key = (page.url.split("?")[0], param)
                if key in tested:
                    continue
                tested.add(key)
                for payload in self.payloads:
                    response = self._probe_query(page.url, param, payload)
                    if not response:
                        continue
                    body = response.text.lower()
                    if any(re.search(pattern, body) for pattern in TRAVERSAL_SUCCESS_PATTERNS):
                        return [
                            VulnerabilityFinding(
                                name="Path Traversal",
                                risk="High",
                                url=response.url,
                                description="A file-oriented parameter accepted traversal payloads and returned sensitive file content.",
                                solution="Restrict file access to a safe allowlist and reject traversal patterns such as ../ and encoded equivalents.",
                                explanation="The application appears to let user input escape the intended directory, which can expose server files.",
                                reference=self._build_reference("directory traversal"),
                                cwe_id="22",
                                wasc_id="33",
                            )
                        ]
        return []

    def _probe_query(self, url: str, param: str, payload: str) -> Optional[requests.Response]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        flat_params = {key: values[0] if values else "" for key, values in params.items()}
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
        try:
            return self.client.get(clean_url, params=flat_params)
        except requests.RequestException:
            return None


class ManualVulnerabilityScanner:
    def __init__(self):
        self.client = HttpClient()
        self.crawler = WebCrawler(self.client)
        self.checks: Dict[str, VulnerabilityCheck] = {
            "sql_injection": SQLInjectionCheck(self.client),
            "xss": XSSCheck(self.client),
            "csrf": CSRFCheck(self.client),
            "broken_auth": BrokenAuthCheck(self.client),
            "dir_traversal": DirectoryTraversalCheck(self.client),
        }

    def scan(
        self,
        target_url: str,
        vulnerabilities: Sequence[str],
        progress_callback: Optional[ProgressCallback] = None,
    ) -> List[Dict[str, Any]]:
        effective_vulns = self._resolve_vulnerabilities(vulnerabilities)
        if progress_callback:
            progress_callback(2, "Preparing manual scan engine…")

        context = self.crawler.crawl(target_url, progress_callback=progress_callback)
        if not context.pages:
            raise RuntimeError("The target could not be reached or no crawlable pages were found.")
        findings: List[VulnerabilityFinding] = []
        total_checks = len(effective_vulns) or 1

        for index, category in enumerate(effective_vulns, start=1):
            check = self.checks[category]
            if progress_callback:
                pct = 35 + int(((index - 1) / total_checks) * 55)
                progress_callback(pct, f"Running {self._label(category)} checks…")
            findings.extend(check.scan(context))

        ordered = sorted(findings, key=lambda item: (-RISK_CODES[item.risk], item.name))
        deduped = self._dedupe_findings(ordered)
        if progress_callback:
            progress_callback(97, "Collecting scan results…")
        return [finding.to_dict() for finding in deduped]

    def _resolve_vulnerabilities(self, vulnerabilities: Sequence[str]) -> List[str]:
        if "scan_all" in vulnerabilities:
            return list(DEFAULT_VULNERABILITIES)
        return [item for item in vulnerabilities if item in self.checks]

    def _dedupe_findings(self, findings: Iterable[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        seen = set()
        results = []
        for finding in findings:
            key = (finding.name, finding.url)
            if key in seen:
                continue
            seen.add(key)
            results.append(finding)
        return results

    def _label(self, category: str) -> str:
        labels = {
            "sql_injection": "SQL injection",
            "xss": "XSS",
            "csrf": "CSRF",
            "broken_auth": "broken authentication",
            "dir_traversal": "directory traversal",
        }
        return labels.get(category, category)
