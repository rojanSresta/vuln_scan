"""Missing security headers check."""

from __future__ import annotations

from urllib.parse import urlparse

from app.scanner.check_base import VulnerabilityCheck
from app.scanner.scan_types import CrawlContext, SECURITY_HEADERS, VulnerabilityFinding


class HeadersCheck(VulnerabilityCheck):
    category = "missing_headers"

    def scan(self, context: CrawlContext) -> list[VulnerabilityFinding]:
        findings: list[VulnerabilityFinding] = []
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
                        reference=self.build_reference("security headers"),
                        cwe_id="693",
                        wasc_id="15",
                    )
                )
        return findings
