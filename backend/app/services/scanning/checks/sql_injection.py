"""SQL Injection vulnerability check"""

import re
from typing import List
import requests

from app.constants import SQL_ERROR_PATTERNS
from app.services.scanning.base import CrawlContext, VulnerabilityFinding, VulnerabilityCheck
from app.services.scanning.common import probe_query_param, submit_form


class SQLInjectionCheck(VulnerabilityCheck):
    category = "sql_injection"
    payloads = ["'", '"', "' OR '1'='1", "1 OR 1=1--"]

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        findings: List[VulnerabilityFinding] = []
        tested = set()

        # Check query parameters
        for page in context.pages:
            for param in page.query_params:
                key = (page.url.split("?")[0], param)
                if key in tested:
                    continue
                tested.add(key)

                for payload in self.payloads:
                    response = probe_query_param(self.client, page.url, param, payload)
                    if not response:
                        continue
                    body = response.text.lower()
                    if response.status_code >= 500 or any(
                        re.search(pattern, body) for pattern in SQL_ERROR_PATTERNS
                    ):
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

        # Check form submissions
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
                        response = submit_form(self.client, form, submission)
                    except requests.RequestException:
                        continue
                    body = response.text.lower()
                    if response.status_code >= 500 or any(
                        re.search(pattern, body) for pattern in SQL_ERROR_PATTERNS
                    ):
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
