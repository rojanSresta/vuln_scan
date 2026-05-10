"""Concrete vulnerability checks."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence
from urllib.parse import parse_qs, urlparse, urlunparse

import requests

from app.services.scanning.base import (
    CrawlContext,
    FormRecord,
    PageRecord,
    SQL_ERROR_PATTERNS,
    TRAVERSAL_SUCCESS_PATTERNS,
    VulnerabilityCheck,
    VulnerabilityFinding,
)


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
