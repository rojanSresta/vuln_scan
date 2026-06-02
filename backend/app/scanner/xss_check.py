"""Reflected XSS vulnerability check."""

from __future__ import annotations

import re
import requests

from app.scanner.check_base import VulnerabilityCheck
from app.scanner.check_helpers import first_reflectable_field, form_submission
from app.scanner.payload_loader import PayloadLoader
from app.scanner.scan_types import CrawlContext, PageRecord, VulnerabilityFinding


class XssCheck(VulnerabilityCheck):
    category = "xss"

    def __init__(self, client):
        super().__init__(client)
        self.payloads = PayloadLoader.load(self.category)

    def scan(self, context: CrawlContext) -> list[VulnerabilityFinding]:
        if self._scan_query_reflections(context.pages) or self._scan_form_reflections(context.pages):
            return [self._make_finding(context.target_url)]
        return []

    def _scan_query_reflections(self, pages: list[PageRecord]) -> bool:
        for page in pages:
            for param in page.query_params:
                for payload in self.payloads:
                    response = self.probe_query(page.url, param, payload)
                    if response and self._payload_reflected_in_non_script(payload, response.text):
                        return True
        return False

    def _scan_form_reflections(self, pages: list[PageRecord]) -> bool:
        for page in pages:
            for form in page.forms:
                field = first_reflectable_field(form)
                if not field:
                    continue
                for payload in self.payloads:
                    try:
                        response = self.submit_form(form, form_submission(form, field.name, payload, "test"))
                    except requests.RequestException:
                        continue
                    if self._payload_reflected_in_non_script(payload, response.text):
                        return True
        return False

    @staticmethod
    def _payload_reflected_in_non_script(payload: str, html: str) -> bool:
        payload_l = payload.lower()
        html_l = html.lower()
        if payload_l not in html_l:
            return False

        # Ignore matches only present inside <script> blocks to reduce false positives.
        non_script = re.sub(r"<script\b[^>]*>.*?</script>", "", html_l, flags=re.I | re.S)
        return payload_l in non_script

    def _make_finding(self, url: str) -> VulnerabilityFinding:
        return VulnerabilityFinding(
            name="Cross Site Scripting (Reflected)",
            risk="High",
            url=url,
            description="A payload was reflected back into the response without output encoding.",
            solution="Encode untrusted output before rendering it in HTML and enforce a strict Content Security Policy.",
            explanation="The page appears to echo attacker-controlled input directly into the browser, which can allow script execution.",
            reference=self.build_reference("reflected XSS"),
            cwe_id="79",
            wasc_id="8",
        )
