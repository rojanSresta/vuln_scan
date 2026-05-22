"""Concrete vulnerability checks."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qs, urlparse, urlunparse

import requests

from app.services.scanning.base import (
    SECURITY_HEADERS,
    CrawlContext,
    FormField,
    FormRecord,
    PageRecord,
    SQL_ERROR_PATTERNS,
    TRAVERSAL_SUCCESS_PATTERNS,
    VulnerabilityCheck,
    VulnerabilityFinding,
)
from app.services.scanning.payloads import load_passwords, load_payloads, load_usernames

LOGIN_KEYWORDS = ("login", "signin", "sign-in", "auth", "session", "account")
USERNAME_FIELD_KEYWORDS = ("user", "email", "login", "name", "account")
FAILURE_HINTS = (
    "invalid",
    "incorrect",
    "failed",
    "wrong password",
    "denied",
    "try again",
    "bad credentials",
    "login failed",
    "authentication failed",
)
SUCCESS_HINTS = ("logout", "sign out", "dashboard", "welcome", "my account", "profile")


class SQLInjectionCheck(VulnerabilityCheck):
    category = "sql_injection"

    def __init__(self, client):
        super().__init__(client)
        self.payloads = load_payloads(self.category)

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
                        findings.append(self._finding(response.url, "parameter"))
                        break

        if findings:
            return findings[:1]

        for page in context.pages:
            for form in page.forms:
                candidate_fields = [
                    field
                    for field in form.fields
                    if field.field_type in {"text", "search", "textarea", "select", "email", "number"}
                ]
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
                        return [self._finding(response.url, "form")]

        return findings[:1]

    def _finding(self, url: str, source: str) -> VulnerabilityFinding:
        description = (
            "A parameter reacted to SQL-style payloads with database error behaviour."
            if source == "parameter"
            else "A form submission reacted to SQL-style payloads with database error behaviour."
        )
        return VulnerabilityFinding(
            name="SQL Injection",
            risk="High",
            url=url,
            description=description,
            solution="Use parameterised queries and validate or constrain user input before it reaches the database layer.",
            explanation="The application appears to build database queries unsafely, so crafted input may alter SQL execution.",
            reference=self._build_reference("SQL injection"),
            cwe_id="89",
            wasc_id="19",
        )

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

    def __init__(self, client):
        super().__init__(client)
        self.payloads = load_payloads(self.category)

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
                for payload in self.payloads:
                    response = self._probe_query(page.url, param, payload)
                    if response and payload in response.text:
                        return True
        return False

    def _scan_form_reflections(self, pages: Sequence[PageRecord]) -> bool:
        for page in pages:
            for form in page.forms:
                candidate_fields = [
                    field for field in form.fields if field.field_type not in {"hidden", "password", "submit"}
                ]
                if not candidate_fields:
                    continue
                for payload in self.payloads:
                    submission = {field.name: field.value or "test" for field in form.fields}
                    submission[candidate_fields[0].name] = payload
                    try:
                        response = self._submit_form(form, submission)
                    except requests.RequestException:
                        continue
                    if payload in response.text:
                        return True
        return False

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


class DirectoryTraversalCheck(VulnerabilityCheck):
    category = "dir_traversal"
    candidate_keywords = ("file", "path", "page", "template", "folder", "doc", "document", "download", "image")

    def __init__(self, client):
        super().__init__(client)
        self.payloads = load_payloads(self.category)

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


class MissingHeadersCheck(VulnerabilityCheck):
    category = "missing_headers"

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        reported: set[str] = set()

        for page in context.pages:
            header_keys = {key.lower() for key in page.headers}
            is_https = urlparse(page.url).scheme == "https"

            for header_name, risk, purpose in SECURITY_HEADERS:
                if header_name in reported:
                    continue
                if header_name == "Strict-Transport-Security" and not is_https:
                    continue
                if header_name.lower() in header_keys:
                    continue

                reported.add(header_name)
                findings.append(
                    VulnerabilityFinding(
                        name=f"Missing Security Header: {header_name}",
                        risk=risk,
                        url=page.url,
                        description=f"The response does not include the {header_name} header ({purpose}).",
                        solution=f"Configure the server or application to send a suitable {header_name} header on every response.",
                        explanation="Security headers help browsers enforce safer defaults and reduce common web attack surface.",
                        reference=self._build_reference("security headers"),
                        cwe_id="693",
                        wasc_id="15",
                    )
                )

        return findings


class DefaultCredentialsCheck(VulnerabilityCheck):
    category = "default_credentials"

    def __init__(self, client):
        super().__init__(client)
        self.usernames = load_usernames()
        self.passwords = load_passwords()

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        for page in context.pages:
            for form in page.forms:
                fields = self._resolve_login_fields(form)
                if not fields:
                    continue
                username_field, password_field = fields

                for username in self.usernames:
                    for password in self.passwords:
                        submission = {field.name: field.value or "" for field in form.fields}
                        submission[username_field.name] = username
                        submission[password_field.name] = password
                        try:
                            response = self._submit_form(form, submission)
                        except requests.RequestException:
                            continue
                        if self._login_succeeded(response, form):
                            return [
                                VulnerabilityFinding(
                                    name="Default Credentials Accepted",
                                    risk="High",
                                    url=form.action_url,
                                    description=(
                                        f"The login form accepted a common credential pair "
                                        f"({username_field.name}={username!r})."
                                    ),
                                    solution="Disable default accounts, enforce strong unique passwords, and implement account lockout.",
                                    explanation="Weak or factory-default credentials allow unauthorised access without exploiting other flaws.",
                                    reference=self._build_reference("default credentials"),
                                    cwe_id="521",
                                    wasc_id="2",
                                )
                            ]
        return []

    def _resolve_login_fields(self, form: FormRecord) -> Optional[Tuple[FormField, FormField]]:
        if not self._is_auth_form(form):
            return None

        password_fields = [field for field in form.fields if field.field_type == "password"]
        if not password_fields:
            return None

        password_field = password_fields[0]
        username_field = None
        for field in form.fields:
            if field is password_field:
                continue
            if field.field_type in {"hidden", "submit", "button", "password"}:
                continue
            lowered = field.name.lower()
            if any(keyword in lowered for keyword in USERNAME_FIELD_KEYWORDS):
                username_field = field
                break

        if username_field is None:
            text_fields = [
                field
                for field in form.fields
                if field.field_type in {"text", "email", "search", "tel"}
            ]
            if text_fields:
                username_field = text_fields[0]

        if username_field is None:
            return None
        return username_field, password_field

    def _is_auth_form(self, form: FormRecord) -> bool:
        if any(field.field_type == "password" for field in form.fields):
            return True
        combined = f"{form.page_url} {form.action_url}".lower()
        return any(keyword in combined for keyword in LOGIN_KEYWORDS)

    def _login_succeeded(self, response: requests.Response, form: FormRecord) -> bool:
        body = response.text.lower()
        if any(hint in body for hint in FAILURE_HINTS):
            return False

        location = response.headers.get("Location", "").lower()
        if response.status_code in {301, 302, 303, 307, 308}:
            if location and not any(keyword in location for keyword in LOGIN_KEYWORDS):
                return True

        if any(hint in body for hint in SUCCESS_HINTS):
            return True

        if response.status_code == 200 and "set-cookie" in {key.lower() for key in response.headers}:
            if not any(keyword in form.action_url.lower() for keyword in LOGIN_KEYWORDS):
                return True

        return False

    def _submit_form(self, form: FormRecord, data: Dict[str, str]) -> requests.Response:
        if form.method == "post":
            return self.client.post(form.action_url, data)
        return self.client.get(form.action_url, params=data)
