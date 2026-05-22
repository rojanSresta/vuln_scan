"""Broken Authentication vulnerability check"""

from typing import List, Optional, Sequence
from urllib.parse import urlparse

from app.constants import STATE_CHANGING_KEYWORDS, SESSION_PARAM_KEYWORDS
from app.services.scanning.base import CrawlContext, FormRecord, PageRecord, VulnerabilityFinding, VulnerabilityCheck


class BrokenAuthCheck(VulnerabilityCheck):
    category = "broken_auth"

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
                if any(keyword in lowered for keyword in SESSION_PARAM_KEYWORDS):
                    return page
        return None

    def _find_weak_cookie_page(self, pages: Sequence[PageRecord]) -> Optional[VulnerabilityFinding]:
        for page in pages:
            if not any(keyword in page.url.lower() for keyword in STATE_CHANGING_KEYWORDS):
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
        return any(keyword in combined for keyword in STATE_CHANGING_KEYWORDS)
