"""Cross-Site Scripting (XSS) vulnerability check"""

from typing import List, Sequence
import requests

from app.services.scanning.base import CrawlContext, PageRecord, VulnerabilityFinding, VulnerabilityCheck
from app.services.scanning.common import probe_query_param, submit_form


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
                response = probe_query_param(self.client, page.url, param, self.payload)
                if response and self.payload in response.text:
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
                submission = {field.name: field.value or "test" for field in form.fields}
                submission[candidate_fields[0].name] = self.payload
                try:
                    response = submit_form(self.client, form, submission)
                except requests.RequestException:
                    continue
                if self.payload in response.text:
                    return True
        return False

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
