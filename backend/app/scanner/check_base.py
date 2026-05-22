"""Base class for all vulnerability checks."""

from __future__ import annotations

from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse, urlunparse

import requests
from requests import Response

from app.scanner.http_client import HttpClient
from app.scanner.scan_types import CrawlContext, FormRecord, VulnerabilityFinding


class VulnerabilityCheck:
    category = ""

    def __init__(self, client: HttpClient):
        self.client = client

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        raise NotImplementedError

    def probe_query(self, url: str, param: str, payload: str) -> Optional[Response]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        flat_params = {key: values[0] if values else "" for key, values in params.items()}
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
        try:
            return self.client.get(clean_url, params=flat_params)
        except requests.RequestException:
            return None

    def submit_form(self, form: FormRecord, data: Dict[str, str]) -> Response:
        if form.method == "post":
            return self.client.post(form.action_url, data)
        return self.client.get(form.action_url, params=data)

    def build_reference(self, title: str) -> str:
        return f"Manual heuristic detection for {title}"
