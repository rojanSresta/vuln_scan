"""SQL injection vulnerability check."""

from __future__ import annotations

import requests

from app.scanner.check_base import VulnerabilityCheck
from app.scanner.check_helpers import first_input_field, form_submission, sql_error_detected
from app.scanner.payload_loader import PayloadLoader
from app.scanner.scan_types import CrawlContext, VulnerabilityFinding


class SqlInjectionCheck(VulnerabilityCheck):
    category = "sql_injection"

    def __init__(self, client):
        super().__init__(client)
        self.payloads = PayloadLoader.load(self.category)

    def scan(self, context: CrawlContext) -> list[VulnerabilityFinding]:
        for page in context.pages:
            for param in page.query_params:
                for payload in self.payloads:
                    response = self.probe_query(page.url, param, payload)
                    if response and sql_error_detected(response):
                        return [self._make_finding(response.url, "parameter")]

        for page in context.pages:
            for form in page.forms:
                field = first_input_field(form)
                if not field:
                    continue
                for payload in self.payloads:
                    try:
                        response = self.submit_form(form, form_submission(form, field.name, payload, "1"))
                    except requests.RequestException:
                        continue
                    if sql_error_detected(response):
                        return [self._make_finding(response.url, "form")]
        return []

    def _make_finding(self, url: str, source: str) -> VulnerabilityFinding:
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
            reference=self.build_reference("SQL injection"),
            cwe_id="89",
            wasc_id="19",
        )
