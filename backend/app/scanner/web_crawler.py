"""Crawls pages on the same host as the target URL."""

from __future__ import annotations

import logging
from typing import Optional
from urllib.parse import urljoin, urlparse, urlunparse

import requests

from app.scanner.html_parser import HtmlParser
from app.scanner.http_client import HttpClient
from app.scanner.scan_types import CrawlContext, PageRecord, ProgressCallback
from app.scanner.scope import is_same_site, registrable_domain

logger = logging.getLogger(__name__)


class WebCrawler:
    def __init__(self, client: HttpClient, max_pages: int = 12):
        self.client = client
        self.max_pages = max_pages

    def crawl(self, target_url: str, progress_callback: Optional[ProgressCallback] = None) -> CrawlContext:
        target_root_domain = registrable_domain(target_url)
        visited = set()
        queue = [target_url]
        pages: list[PageRecord] = []

        while queue and len(pages) < self.max_pages:
            current = queue.pop(0)
            normalized = self._normalize_url(current)
            if normalized in visited:
                continue

            visited.add(normalized)
            if progress_callback:
                progress_callback(min(35, 5 + len(pages) * 3), f"Crawling {normalized}...")

            try:
                # Disable automatic redirect following; manually follow only redirects
                # that stay on the same registrable domain as the operator's target.
                response = self.client.get(current, allow_redirects=False)
            except requests.RequestException as exc:
                logger.debug("Skipping %s during crawl: %s", current, exc)
                continue

            redirects_followed = 0
            redirect_statuses = {301, 302, 303, 307, 308}
            while (response.is_redirect or response.status_code in redirect_statuses) and redirects_followed < 3:
                location = response.headers.get("Location")
                if not location:
                    break

                next_url = urljoin(response.url, location)
                next_parsed = urlparse(next_url)
                if next_parsed.scheme not in {"http", "https"}:
                    break

                if not is_same_site(next_url, target_root_domain):
                    break

                next_normalized = self._normalize_url(next_url)
                if next_normalized in visited:
                    break

                current = next_url
                response = self.client.get(current, allow_redirects=False)
                redirects_followed += 1

            # If we ended up on a different site, don't treat it as an in-scope crawled page.
            if not is_same_site(current, target_root_domain):
                continue
            if response.is_redirect or response.status_code in redirect_statuses:
                # Still a redirect (cross-host or no Location), skip recording this page.
                continue

            content_type = response.headers.get("Content-Type", "")
            text = response.text if "text/html" in content_type or not content_type else response.text[:0]
            parser = HtmlParser(response.url)
            if text:
                try:
                    parser.feed(text)
                except Exception:
                    logger.debug("HTML parse failed for %s", response.url)

            page = PageRecord(
                url=response.url,
                status_code=response.status_code,
                headers=dict(response.headers),
                text=text,
                content_type=content_type,
                forms=parser.forms,
                links=parser.links,
            )
            pages.append(page)

            for link in parser.links:
                if self._should_visit(link, target_root_domain) and self._normalize_url(link) not in visited:
                    queue.append(link)

        return CrawlContext(target_url=target_url, pages=pages)

    def _should_visit(self, url: str, target_root_domain: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return False
        if not is_same_site(url, target_root_domain):
            return False
        if parsed.fragment:
            return False
        return True

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        netloc = (parsed.netloc or "").lower()
        path = parsed.path or "/"
        return urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
