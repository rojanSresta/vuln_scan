"""HTTP client used by the scanner."""

from __future__ import annotations

from typing import Callable, Dict, Optional

import requests


class HttpClient:
    def __init__(self, cancel_callback: Callable[[], None] | None = None):
        self.session = requests.Session()
        self.cancel_callback = cancel_callback
        self.session.headers.update(
            {
                "User-Agent": "WAVS-Manual-Scanner/1.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )

    def get(
        self,
        url: str,
        params: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> requests.Response:
        self._check_cancelled()
        return self.session.get(url, params=params, timeout=12, allow_redirects=allow_redirects)

    def post(
        self,
        url: str,
        data: Dict[str, str],
        allow_redirects: bool = True,
    ) -> requests.Response:
        self._check_cancelled()
        return self.session.post(url, data=data, timeout=12, allow_redirects=allow_redirects)

    def _check_cancelled(self) -> None:
        if self.cancel_callback:
            self.cancel_callback()
