"""Main scanner engine — runs all vulnerability check classes."""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from app.scanner.credentials_check import DefaultCredentialsCheck
from app.scanner.headers_check import HeadersCheck
from app.scanner.http_client import HttpClient
from app.scanner.path_check import PathTraversalCheck
from app.scanner.scan_types import DEFAULT_VULNERABILITIES, RISK_CODES, ProgressCallback, VulnerabilityFinding
from app.scanner.sql_check import SqlInjectionCheck
from app.scanner.web_crawler import WebCrawler
from app.scanner.xss_check import XssCheck

CHECK_LABELS = {
    "sql_injection": "Testing for SQL injection...",
    "xss": "Testing for cross-site scripting...",
    "dir_traversal": "Testing for directory traversal...",
    "missing_headers": "Checking security headers...",
    "default_credentials": "Testing default credentials...",
}


class ScanEngine:
    def __init__(self, cancel_callback=None):
        self.client = HttpClient(cancel_callback=cancel_callback)
        self.crawler = WebCrawler(self.client)
        self.checks = {
            "sql_injection": SqlInjectionCheck(self.client),
            "xss": XssCheck(self.client),
            "dir_traversal": PathTraversalCheck(self.client),
            "missing_headers": HeadersCheck(self.client),
            "default_credentials": DefaultCredentialsCheck(self.client),
        }

    def run(
        self,
        target_url: str,
        vulnerabilities: Sequence[str],
        progress_callback: ProgressCallback | None = None,
    ) -> list[dict[str, Any]]:
        effective = self._resolve_vulnerabilities(vulnerabilities)
        if progress_callback:
            progress_callback(2, "Preparing scanner...")

        context = self.crawler.crawl(target_url, progress_callback=progress_callback)
        if not context.pages:
            raise RuntimeError("The target could not be reached or no crawlable pages were found.")

        findings: list[VulnerabilityFinding] = []
        total = len(effective) or 1

        for index, category in enumerate(effective, start=1):
            check = self.checks[category]
            if progress_callback:
                pct = 35 + int(((index - 1) / total) * 55)
                progress_callback(pct, CHECK_LABELS.get(category, "Performing vulnerability checks..."))
            findings.extend(check.scan(context))

        ordered = sorted(findings, key=lambda item: (-RISK_CODES[item.risk], item.name))
        deduped = self._dedupe(ordered)
        if progress_callback:
            progress_callback(97, "Generating report...")
        return [finding.to_dict() for finding in deduped]

    def _resolve_vulnerabilities(self, vulnerabilities: Sequence[str]) -> list[str]:
        if "scan_all" in vulnerabilities:
            return list(DEFAULT_VULNERABILITIES)
        return [item for item in vulnerabilities if item in self.checks]

    def _dedupe(self, findings: Iterable[VulnerabilityFinding]) -> list[VulnerabilityFinding]:
        seen = set()
        results = []
        for finding in findings:
            key = (finding.name, finding.url)
            if key in seen:
                continue
            seen.add(key)
            results.append(finding)
        return results
