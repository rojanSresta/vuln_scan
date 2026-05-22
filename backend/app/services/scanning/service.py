"""Manual vulnerability scanner."""

from __future__ import annotations

from typing import Any, Iterable, List, Sequence

from app.services.scanning.base import (
    DEFAULT_VULNERABILITIES,
    HttpClient,
    ProgressCallback,
    RISK_CODES,
    VulnerabilityFinding,
    WebCrawler,
)
from app.services.scanning.checks import (
    DefaultCredentialsCheck,
    DirectoryTraversalCheck,
    MissingHeadersCheck,
    SQLInjectionCheck,
    XSSCheck,
)


class ManualVulnerabilityScanner:
    def __init__(self, cancel_callback=None):
        self.client = HttpClient(cancel_callback=cancel_callback)
        self.crawler = WebCrawler(self.client)
        self.checks = {
            "sql_injection": SQLInjectionCheck(self.client),
            "xss": XSSCheck(self.client),
            "dir_traversal": DirectoryTraversalCheck(self.client),
            "missing_headers": MissingHeadersCheck(self.client),
            "default_credentials": DefaultCredentialsCheck(self.client),
        }

    def scan(
        self,
        target_url: str,
        vulnerabilities: Sequence[str],
        progress_callback: ProgressCallback | None = None,
    ) -> List[dict[str, Any]]:
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
            "dir_traversal": "directory traversal",
            "missing_headers": "missing security headers",
            "default_credentials": "default credentials",
        }
        return labels.get(category, category)
