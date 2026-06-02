"""URL scope helpers for scanner crawl and probe decisions."""

from __future__ import annotations

from urllib.parse import urlparse

import tldextract

_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


def registrable_domain(url: str) -> str:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return ""

    extracted = _EXTRACTOR(hostname)
    if extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return hostname


def is_same_site(url: str, root_domain: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    return bool(root_domain) and registrable_domain(url) == root_domain
