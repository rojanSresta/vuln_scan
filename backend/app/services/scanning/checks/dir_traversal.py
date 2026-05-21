"""Directory Traversal vulnerability check"""

import re
from typing import List

from app.constants import TRAVERSAL_SUCCESS_PATTERNS, FILE_PARAM_KEYWORDS
from app.services.scanning.base import CrawlContext, VulnerabilityFinding, VulnerabilityCheck
from app.services.scanning.common import probe_query_param


class DirectoryTraversalCheck(VulnerabilityCheck):
    category = "dir_traversal"
    payloads = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..\\..\\..\\windows\\win.ini",
    ]

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        tested = set()
        for page in context.pages:
            for param in page.query_params:
                if not any(keyword in param.lower() for keyword in FILE_PARAM_KEYWORDS):
                    continue
                key = (page.url.split("?")[0], param)
                if key in tested:
                    continue
                tested.add(key)
                for payload in self.payloads:
                    response = probe_query_param(self.client, page.url, param, payload)
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
