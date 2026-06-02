"""Base class for all vulnerability checks."""

from __future__ import annotations

from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlparse, urlunparse

import requests
from requests import Response

from app.scanner.http_client import HttpClient
from app.scanner.scan_types import CrawlContext, FormRecord, VulnerabilityFinding
from app.scanner.scope import is_same_site, registrable_domain


class VulnerabilityCheck:
    category = ""

    def __init__(self, client: HttpClient):
        self.client = client
        self._target_root_domain: str = ""

    def set_scope_target(self, target_url: str) -> None:
        self._target_root_domain = registrable_domain(target_url)

    def _is_in_scope(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        if not self._target_root_domain:
            return True
        return is_same_site(url, self._target_root_domain)

    def scan(self, context: CrawlContext) -> List[VulnerabilityFinding]:
        raise NotImplementedError

    def probe_query(self, url: str, param: str, payload: str) -> Optional[Response]:
        if not self._is_in_scope(url):
            return None

        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        flat_params = {key: values[0] if values else "" for key, values in params.items()}
        clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, "", parsed.fragment))
        try:
            return self.client.get(clean_url, params=flat_params, allow_redirects=False)
        except requests.RequestException:
            return None

    def submit_form(self, form: FormRecord, data: Dict[str, str]) -> Response:
        if not self._is_in_scope(form.action_url):
            raise requests.RequestException(f"Skipping out-of-scope form action: {form.action_url}")

        if form.method == "post":
            return self.client.post(form.action_url, data, allow_redirects=False)
        return self.client.get(form.action_url, params=data, allow_redirects=False)

    def build_reference(self, title: str) -> str:
        return f"Manual heuristic detection for {title}"
