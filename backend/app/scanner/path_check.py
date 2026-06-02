"""Path traversal vulnerability check."""

from __future__ import annotations

import re
from uuid import uuid4

from app.scanner.check_base import VulnerabilityCheck
from app.scanner.payload_loader import PayloadLoader
from app.scanner.scan_types import CrawlContext, TRAVERSAL_SUCCESS_PATTERNS, VulnerabilityFinding


class PathTraversalCheck(VulnerabilityCheck):
    category = "dir_traversal"
    candidate_keywords = ("file", "path", "page", "template", "folder", "doc", "document", "download", "image", "id", "pid", "dir", "dir_path", "catalog", "category", "section", "item", "file_id", "resource", "asset")

    def __init__(self, client):
        super().__init__(client)
        self.payloads = PayloadLoader.load(self.category)

    def scan(self, context: CrawlContext) -> list[VulnerabilityFinding]:
        tested = set()
        for page in context.pages:
            for param in page.query_params:
                if not any(keyword in param.lower() for keyword in self.candidate_keywords):
                    continue
                key = (page.url.split("?")[0], param)
                if key in tested:
                    continue
                tested.add(key)
                baseline = self.probe_query(page.url, param, f"baseline-{uuid4().hex[:10]}")
                baseline_body = baseline.text.lower() if baseline else ""
                baseline_matches = any(re.search(pattern, baseline_body) for pattern in TRAVERSAL_SUCCESS_PATTERNS)
                for payload in self.payloads:
                    response = self.probe_query(page.url, param, payload)
                    if not response:
                        continue
                    body = response.text.lower()
                    payload_matches = any(re.search(pattern, body) for pattern in TRAVERSAL_SUCCESS_PATTERNS)
                    if payload_matches and not baseline_matches:
                        return [
                            VulnerabilityFinding(
                                name="Directory Traversal",
                                risk="High",
                                url=response.url,
                                description="A file-oriented parameter accepted traversal payloads and returned sensitive file content.",
                                solution="Restrict file access to a safe allowlist and reject traversal patterns such as ../ and encoded equivalents.",
                                explanation="The application appears to let user input escape the intended directory, which can expose server files.",
                                reference=self.build_reference("directory traversal"),
                                cwe_id="22",
                                wasc_id="33",
                            )
                        ]
        return []
